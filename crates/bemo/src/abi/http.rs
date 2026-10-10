/*
 * Copyright (c) 2024-2026 Elide Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

//! HTTP mode for v2 sockets: the driver owns receives, parses requests natively,
//! reports them as `REQUEST` events carrying an exchange handle, streams request bodies
//! as zero-copy `BODY` segments, and encodes and sends responses in request order.

use std::cell::Cell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::{BuildHasherDefault, Hasher};
use std::io;
use std::rc::Rc;

use super::*;
use crate::buffer::ReceiveCredit;
use crate::driver::VectoredSend;
#[path = "http_exchange.rs"]
mod exchange;
#[path = "http_h2.rs"]
mod h2_socket;
#[path = "http_tls.rs"]
mod tls_socket;
use crate::http::{
  BODY_WINDOW_BYTES, CHUNK_HEADROOM, CHUNK_TAIL, DateCache, Exchange, Framing, HttpConnection, Method, Outcome,
  ResponseHeader, encode_head, encode_response, frame_chunk,
};
use exchange::ExchangeStore;
use h2_socket::H2Socket;
use tls_socket::TlsSocket;
#[path = "http_events.rs"]
mod events;

// Address alignment and common pointer prefixes defeat identity hashing's bucket/fingerprint bits.
type AddressMap<V> = HashMap<u64, V, BuildHasherDefault<AddressHasher>>;

/// These maps accept internally allocated addresses, never untrusted HTTP strings.
#[derive(Default)]
pub(super) struct AddressHasher(u64);

impl Hasher for AddressHasher {
  #[inline]
  fn finish(&self) -> u64 {
    self.0
  }

  fn write(&mut self, _: &[u8]) {
    unreachable!("address maps only hash u64 keys");
  }

  #[inline]
  fn write_u64(&mut self, mut value: u64) {
    // MurmurHash3's 64-bit finalizer mixes both aligned low bits and common pointer prefixes.
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    self.0 = value ^ (value >> 33);
  }
}

/// Event kind for a parsed request; `value` carries the exchange handle, which is also the
/// address of its [`ExchangeLayout`].
pub const EVENT_REQUEST: u32 = 5;
/// Event kind for a socket the driver closed itself after its final response.
pub const EVENT_CLOSED: u32 = 6;
/// Event kind for a body segment: `operation` is the segment handle (the address of its
/// [`SegmentLayout`]), `value` the exchange, `result` the segment length.
pub const EVENT_BODY: u32 = 7;
/// Event kind ending a body: `value` is the exchange; `result` is zero on a clean end, or a
/// negative portable error when the body was truncated, malformed, or discarded unread.
pub const EVENT_BODY_END: u32 = 8;
/// Event kind for a sent response part of a streaming exchange: `value` is the exchange,
/// `result` the part's bytes on the wire, or a negative portable error when it was dropped.
/// Emitted once per queued part, the head included, in queue order.
pub const EVENT_PART_SENT: u32 = 9;
/// One HTTP/2 exchange was reset; sibling streams remain live.
pub const EVENT_RESET: u32 = 10;
/// [`ExchangeLayout`] flag: body segments and a body end follow this request.
pub const HAS_BODY: u8 = 1;

/// [`ExchangeLayout`] has declared-length and first-Host metadata after its 32-byte prefix.
pub const HAS_HEADER_METADATA: u8 = 2;
/// Flag for [`elide_transport_http_respond`]: send the head only; the body follows as parts.
pub const RESPOND_STREAM: u32 = 2;
/// Flag for [`elide_transport_http_chunk_send`]: this part ends the response.
pub const CHUNK_FINAL: u32 = 2;
/// Retain a frozen body handle instead of consuming prepared mutable storage. HTTP/1 chunked
/// framing still requires prepared storage; HTTP/2 and HTTP/1 length/close framing accept this.
pub const CHUNK_RETAIN: u32 = 4;
/// Most response bytes one streaming exchange may hold queued or in flight.
pub const RESPONSE_WINDOW_BYTES: usize = 256 * 1024;
/// Parts per vectored send, well under `IOV_MAX`.
const SEND_PARTS: usize = 64;
/// Live request handles admitted per connection.
const MAX_EXCHANGES: usize = 64;
/// Maximum newly queued bytes deferred by an active callback scope before attempting a flush.
const CORK_BYTES: usize = 64 * 1024;
/// Retry work per poll; requeued sockets wait behind the rest of the current round.
const RETRY_BATCH: usize = 256;

/// Portable code for a body or response the peer or the caller cut short.
fn aborted() -> i64 {
  error_code(io::ErrorKind::ConnectionAborted.into())
}

/// Portable code for a malformed or mis-sized message.
fn malformed() -> i64 {
  error_code(io::ErrorKind::InvalidData.into())
}

/// A driver's HTTP-mode bookkeeping.
#[derive(Default)]
pub(super) struct HttpTables {
  pub(super) sockets: IntMap<u64, HttpSocket>,
  /// Address-stable slots; guest and wire lifetimes must both end before reuse.
  pub(super) exchanges: ExchangeStore,
  /// Delivered body segments, keyed the same way; each is released individually.
  pub(super) segments: AddressMap<BodySegment>,
  /// Events that did not fit the caller's batch; drained first on the next poll.
  pub(super) overflow: events::EventQueue,
  pub(super) date: DateCache,
  // Intrusive identities: one entry per live socket, no allocations or stale close tombstones.
  retry_head: u64,
  retry_tail: u64,
  retry_len: usize,
  retry_remaining: usize,
}

impl HttpTables {
  fn queue_retry(&mut self, socket: u64) {
    let Some(http) = self.sockets.get_mut(&socket) else {
      return;
    };
    if http.retry_queued {
      self.retry_remaining = self.retry_len;
      return;
    }
    http.retry_queued = true;
    http.retry_prev = self.retry_tail;
    http.retry_next = 0;
    if self.retry_tail == 0 {
      self.retry_head = socket;
    } else {
      self.sockets.get_mut(&self.retry_tail).unwrap().retry_next = socket;
    }
    self.retry_tail = socket;
    self.retry_len += 1;
    self.retry_remaining = self.retry_len;
  }

  fn remove_retry(&mut self, socket: u64) {
    let Some(http) = self.sockets.get_mut(&socket) else {
      return;
    };
    if !http.retry_queued {
      return;
    }
    http.retry_queued = false;
    let prev = std::mem::take(&mut http.retry_prev);
    let next = std::mem::take(&mut http.retry_next);
    if prev == 0 {
      self.retry_head = next;
    } else {
      self.sockets.get_mut(&prev).unwrap().retry_next = next;
    }
    if next == 0 {
      self.retry_tail = prev;
    } else {
      self.sockets.get_mut(&next).unwrap().retry_prev = prev;
    }
    self.retry_len -= 1;
  }
}

pub(super) struct HttpSocket {
  retry_prev: u64,
  retry_next: u64,
  retry_queued: bool,
  tls: Option<TlsSocket>,
  h2: Option<H2Socket>,
  parser: HttpConnection,
  budget: Budget,
  capacity: usize,
  outstanding: usize,
  // Preserve freed handle addresses until their queued response parts retire.
  retired: AddressMap<()>,
  pending_input: VecDeque<PendingInput>,
  /// Exchange handles in arrival order; responses leave in this order.
  order: VecDeque<u64>,
  /// Response parts queued per exchange, waiting for their turn on the lane.
  ready: AddressMap<Parts>,
  /// Parts of the vectored send in flight, in wire order.
  inflight: VecDeque<Inflight>,
  /// The send vector, recycled across sends.
  vector: Vec<FrozenBuffer>,
  /// A send is in flight on the write lane.
  sending: bool,
  cork_depth: u32,
  cork_bytes: usize,
  /// Close once every queued response has been sent.
  closing: bool,
  /// Reject new request heads while finishing accepted exchanges and bodies.
  draining: bool,
  /// A receive is in flight.
  receiving: bool,
  /// Logical registration identity, retained through kernel rearms and pause cancellation.
  persistent: Option<u64>,
  /// EOF may follow queued multishot data while request admission is paused.
  pending_eof: bool,
  /// Receive capacity pinned by unacked segments of this socket; shared with their charges.
  pinned: Rc<Cell<usize>>,
  /// Exchange whose body is being framed, or zero.
  body: u64,
}

impl HttpSocket {
  fn new(budget: Budget, capacity: usize, tls: Option<TlsSocket>) -> Self {
    HttpSocket {
      retry_prev: 0,
      retry_next: 0,
      retry_queued: false,
      tls,
      h2: None,
      parser: HttpConnection::new(budget.clone()),
      budget,
      capacity,
      outstanding: 0,
      retired: AddressMap::default(),
      pending_input: VecDeque::new(),
      order: VecDeque::new(),
      ready: AddressMap::default(),
      inflight: VecDeque::new(),
      vector: Vec::new(),
      sending: false,
      cork_depth: 0,
      cork_bytes: 0,
      closing: false,
      draining: false,
      receiving: false,
      persistent: None,
      pending_eof: false,
      pinned: Rc::default(),
      body: 0,
    }
  }

  fn queue(&mut self, exchange: u64, parts: Parts) {
    self.cork_write(parts.queued_bytes);
    self.ready.insert(exchange, parts);
  }

  fn cork_write(&mut self, bytes: usize) {
    if self.cork_depth != 0 {
      self.cork_bytes = self.cork_bytes.saturating_add(bytes);
    }
  }
}

/// No driver/socket borrows cross guest calls; either may be released by reentry.
pub(super) struct Cork {
  driver: u64,
  socket: u64,
  _responses: crate::buffer::ResponseBatch,
}

impl Cork {
  pub(super) fn covers(&self, socket: u64) -> bool {
    self.socket == socket
  }

  pub(super) fn enter(driver: u64, socket: u64) -> Option<Self> {
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let http = drivers.0.get_mut(&driver)?.http.sockets.get_mut(&socket)?;
      if http.h2.is_some() {
        return None;
      }
      http.cork_depth = http.cork_depth.checked_add(1)?;
      Some(Self {
        driver,
        socket,
        _responses: crate::buffer::ResponseBatch::enter(),
      })
    })
  }
}

impl Drop for Cork {
  fn drop(&mut self) {
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let Some(state) = drivers.0.get_mut(&self.driver) else {
        return;
      };
      let Some(http) = state.http.sockets.get_mut(&self.socket) else {
        return;
      };
      debug_assert!(http.cork_depth != 0);
      http.cork_depth -= 1;
      if http.cork_depth == 0 {
        http.cork_bytes = 0;
        let mut events = VecDeque::new();
        pump(state, self.socket, &mut events);
        state.http.overflow.extend(events);
      }
    });
  }
}

/// One exchange's response, as the parts queued so far.
struct Parts {
  first: Option<FrozenBuffer>,
  queue: VecDeque<FrozenBuffer>,
  /// The final part has been queued; the exchange leaves `order` once `queue` drains.
  complete: bool,
  /// Bytes queued or in flight, bounded by [`RESPONSE_WINDOW_BYTES`] for a streaming exchange.
  queued_bytes: usize,
  /// Parts arrive through `chunk_send` and each reports [`EVENT_PART_SENT`].
  streaming: bool,
  framing: Framing,
  /// Payload bytes accepted so far, checked against `Framing::Length`.
  body_bytes: u64,
  /// The response carries no body (HEAD, 1xx, 204, 205, 304): parts are accepted and dropped.
  bodiless: bool,
}

impl Parts {
  fn single(encoded: FrozenBuffer) -> Self {
    let len = encoded.as_ref().len();
    Self {
      first: Some(encoded),
      queue: VecDeque::new(),
      complete: true,
      queued_bytes: len,
      streaming: false,
      framing: Framing::Length(len as u64),
      body_bytes: 0,
      bodiless: false,
    }
  }

  fn pop_front(&mut self) -> Option<FrozenBuffer> {
    self.first.take().or_else(|| self.queue.pop_front())
  }

  fn push_back(&mut self, part: FrozenBuffer) {
    if self.first.is_none() && self.queue.is_empty() {
      self.first = Some(part);
    } else {
      self.queue.push_back(part);
    }
  }

  fn len(&self) -> usize {
    usize::from(self.first.is_some()) + self.queue.len()
  }

  fn is_empty(&self) -> bool {
    self.first.is_none() && self.queue.is_empty()
  }
}

/// A part handed to the kernel; `remaining` shrinks across short sends.
struct Inflight {
  exchange: u64,
  len: usize,
  remaining: usize,
  report: bool,
}

/// Fixed-layout view of a body segment, first in its storage so the segment handle doubles
/// as its address: the JVM reads data address and length from these 16 bytes and never calls
/// back for them. Valid until [`elide_transport_http_segment_release`].
#[repr(C)]
pub struct SegmentLayout {
  data: u64,
  len: u64,
}

#[repr(C)]
struct SegmentStorage {
  layout: SegmentLayout,
  /// Zero-copy slice whose allocation outlives its driver when the consumer retains it.
  bytes: FrozenBuffer,
}

static RETIRED_SEGMENTS: LazyLock<Mutex<AddressMap<Box<SegmentStorage>>>> = LazyLock::new(Mutex::default);

pub(super) struct BodySegment {
  storage: Box<SegmentStorage>,
  socket: u64,
  /// The window charge, shared by every segment cut from one receive; the last drop unpins its
  /// capacity. Taken by [`elide_transport_http_segment_ack`] once the bytes are the consumer's
  /// problem rather than the transport's read-ahead, which is independent of when they are freed.
  charge: Option<Rc<ReceiveCharge>>,
  h2: Option<(u32, usize)>,
}

/// One receive allocation's pinned capacity, held for as long as any segment cut from it is
/// unacked. A segment pins its whole receive, so the window is charged per receive, not per
/// payload byte.
struct ReceiveCharge {
  capacity: usize,
  pinned: Rc<Cell<usize>>,
  provided: Option<ReceiveCredit>,
}

struct PendingInput {
  bytes: FrozenBuffer,
  charge: Option<Rc<ReceiveCharge>>,
}

impl ReceiveCharge {
  fn new(capacity: usize, pinned: &Rc<Cell<usize>>) -> Rc<Self> {
    pinned.set(pinned.get() + capacity);
    Rc::new(Self {
      capacity,
      pinned: pinned.clone(),
      provided: None,
    })
  }
}

impl Drop for ReceiveCharge {
  fn drop(&mut self) {
    if let Some(credit) = &self.provided {
      credit.ack();
    }
    self.pinned.set(self.pinned.get().saturating_sub(self.capacity));
  }
}

/// Fixed-layout view of a live exchange, first in `HttpExchange` so the exchange handle
/// doubles as its address: the JVM reads head and span-table addresses, lengths, method, version,
/// keep-alive and flags from the 32-byte prefix. [`HAS_HEADER_METADATA`] advertises the
/// signed content length at offset 32 and first Host index at offset 40. Valid until the
/// exchange is freed by [`elide_transport_http_free`].
#[repr(C)]
pub struct ExchangeLayout {
  head_ptr: *const u8,
  head_len: u64,
  spans_ptr: *const u32,
  span_count: u32,
  method: u8,
  version: u8,
  keep_alive: u8,
  /// Bit 0 is [`HAS_BODY`]. This byte was reserved and always zero before flags existed, so
  /// readers that ignore it keep working.
  flags: u8,
  /// Signed JVM length, or -1 when absent or outside its range.
  content_length: i64,
  /// First Host field index, or -1 when absent.
  host_index: i32,
}

#[repr(C)]
pub(super) struct HttpExchange {
  layout: ExchangeLayout,
  socket: u64,
  exchange: Exchange,
  stream: u32,
  /// Span table in the [`elide_transport_http_spans`] layout; the JVM reads it in place.
  spans: Vec<u32>,
  /// Set by respond/send/release; the memory itself lives until the JVM frees it.
  responded: bool,
  budget: Budget,
  /// Response storage allocated by [`elide_transport_http_prepare`] on the responding thread and
  /// taken by [`elide_transport_http_send`] on the driver thread. Single writer at a time by
  /// protocol: the responder fills it, then hands the exchange to the driver through its task
  /// queue, which orders the two accesses.
  pending: std::cell::UnsafeCell<Option<Buffer>>,
}

impl HttpExchange {
  fn new(socket: u64, exchange: Exchange, budget: Budget, stream: u32, mut spans: Vec<u32>) -> Self {
    fill_span_table(&exchange, &mut spans);
    let head = exchange.head.as_ref();
    let layout = ExchangeLayout {
      head_ptr: head.as_ptr(),
      head_len: head.len() as u64,
      spans_ptr: spans.as_ptr(),
      span_count: spans.len() as u32,
      method: exchange.method as u8,
      version: exchange.version,
      keep_alive: exchange.keep_alive as u8,
      flags: HAS_HEADER_METADATA | if exchange.has_body { HAS_BODY } else { 0 },
      content_length: exchange
        .content_length
        .and_then(|n| i64::try_from(n).ok())
        .unwrap_or(-1),
      host_index: exchange.host_index.map_or(-1, |n| n as i32),
    };
    Self {
      layout,
      socket,
      exchange,
      stream,
      spans,
      responded: false,
      budget,
      pending: std::cell::UnsafeCell::new(None),
    }
  }
}

fn span_table(x: &Exchange) -> Vec<u32> {
  let mut spans = Vec::with_capacity(4 + x.headers.len() * 4);
  fill_span_table(x, &mut spans);
  spans
}

fn fill_span_table(x: &Exchange, spans: &mut Vec<u32>) {
  spans.clear();
  spans.extend_from_slice(&[x.method_span.start, x.method_span.end, x.path.start, x.path.end]);
  for span in &x.headers {
    spans.extend_from_slice(&[span.name.start, span.name.end, span.value.start, span.value.end]);
  }
}

/// Flag for [`elide_transport_http_send`]: close the connection after this response.
pub const SEND_CLOSE: u32 = 1;

/// A compact copy of a request head, made by [`elide_transport_http_retain`] the first time the
/// JVM lends the head's bytes to a guest string, and owned by the JVM until
/// [`elide_transport_http_head_release`].
///
/// One allocation the JVM reads through a single memory view: a 16-byte header (span count
/// `u32`, head length `u32`, method, version, keep-alive, padding), then the span table (`u32`
/// start/end pairs: method, path, then name and value per header, as
/// [`elide_transport_http_spans`] writes them), then the head bytes. The copy exists so borrowed
/// strings never pin the socket's receive buffer, which the parser's head is a slice of.
pub struct RetainedHead;

impl RetainedHead {
  pub const HEADER: usize = 16;

  /// Allocate the blob; returns its address and length.
  fn retain(x: &Exchange) -> (u64, usize) {
    let head = x.head.as_ref();
    let spans = span_table(x);
    let total = Self::HEADER + spans.len() * 4 + head.len();
    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(&(spans.len() as u32).to_ne_bytes());
    blob.extend_from_slice(&(head.len() as u32).to_ne_bytes());
    blob.extend_from_slice(&[x.method as u8, x.version, x.keep_alive as u8, 0, 0, 0, 0, 0]);
    for value in &spans {
      blob.extend_from_slice(&value.to_ne_bytes());
    }
    blob.extend_from_slice(head);
    debug_assert_eq!(blob.len(), total);
    let raw = Box::into_raw(blob.into_boxed_slice());
    (raw.cast::<u8>() as u64, total)
  }

  /// Total length of a blob, recovered from its header.
  ///
  /// # Safety
  /// `address` must be a live blob from [`Self::retain`].
  unsafe fn len(address: u64) -> usize {
    let base = address as *const u8;
    // SAFETY: The caller guarantees a live retained blob with its initialized eight-byte header.
    let spans = unsafe { base.cast::<u32>().read_unaligned() } as usize;
    // SAFETY: The second u32 lies within that same initialized eight-byte header.
    let head = unsafe { base.add(4).cast::<u32>().read_unaligned() } as usize;
    Self::HEADER + spans * 4 + head
  }
}

fn event(kind: u32, operation: u64, socket: u64, value: u64, result: i64) -> NativeEvent {
  NativeEvent {
    operation,
    socket,
    value,
    result,
    kind,
    reserved: 0,
  }
}

/// Switch an attached socket of `workload` into HTTP mode and start receiving.
///
/// Receive storage of `capacity` bytes is charged to `owner`. Returns zero on success.
pub fn elide_transport_socket_http(workload: u64, driver: u64, socket: u64, owner: u64, capacity: u64) -> i32 {
  activate_http(workload, driver, socket, owner, capacity, None)
}

fn activate_http(workload: u64, driver: u64, socket: u64, owner: u64, capacity: u64, tls: Option<TlsSocket>) -> i32 {
  let Ok(capacity) = usize::try_from(capacity) else {
    return INVALID;
  };
  if capacity == 0 {
    return INVALID;
  }
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    if !state.sockets.contains_key(&socket)
      || !owned(state, socket, workload)
      || state.http.sockets.contains_key(&socket)
      || state.operations.values().any(|operation| operation.socket == socket)
    {
      return INVALID;
    }
    let Some(budget) = budget(owner) else {
      return INVALID;
    };
    state
      .http
      .sockets
      .insert(socket, HttpSocket::new(budget, capacity, tls));
    if arm_receive(state, socket) {
      // TLS requires deadline checks and can yield application/handshake work without a CQE.
      if state.http.sockets.get(&socket).is_some_and(|http| http.tls.is_some()) {
        state.http.queue_retry(socket);
      }
      0
    } else {
      state.http.sockets.remove(&socket);
      INVALID
    }
  })
}

/// Activate native HTTP over TLS using an existing server context. Driver thread only.
/// ALPN accepts HTTP/1.1 and HTTP/2; unsupported application protocols fail activation.
pub fn elide_transport_socket_http_tls(
  workload: u64,
  driver: u64,
  socket: u64,
  owner: u64,
  capacity: u64,
  context: u64,
) -> i32 {
  let (Some(config), Some(budget)) = (super::tls::server_config(workload, context), budget(owner)) else {
    return INVALID;
  };
  let Ok(tls) = TlsSocket::new(config, budget) else {
    return INVALID;
  };
  activate_http(workload, driver, socket, owner, capacity, Some(tls))
}

/// Stop admitting request heads and close HTTP sockets once their accepted responses reach the wire.
/// Repeated calls return the remaining connection count; driver thread only. Returns `INVALID`
/// for an unknown driver. The caller closes the listener separately and enforces its deadline.
pub fn elide_transport_http_drain(driver: u64) -> i32 {
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    let sockets: Vec<u64> = state.http.sockets.keys().copied().collect();
    let mut events = VecDeque::new();
    for socket in sockets {
      if let Some(http) = state.http.sockets.get_mut(&socket) {
        http.draining = true;
      }
      pump(state, socket, &mut events);
    }
    state.http.overflow.extend(events);
    state.http.sockets.len().min(i32::MAX as usize) as i32
  })
}

/// Retire HTTP sockets and transfer delivered body storage beyond the driver's lifetime.
/// Driver thread only. The caller must serialize this with its queue's retirement, then release
/// retained segments through [`elide_transport_http_segment_release_retired`] on any thread.
pub fn elide_transport_http_retire(driver: u64) -> i32 {
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    retire(state);
    0
  })
}

pub(super) fn retire(state: &mut DriverState) {
  let sockets: Vec<u64> = state.http.sockets.keys().copied().collect();
  let mut events = VecDeque::new();
  for socket in sockets {
    close_socket(state, socket, &mut events);
  }
  // Undelivered segments have no consumer to release them. Every other segment's stable box
  // and allocation remain owned until that consumer releases, without retaining driver-local Rc's.
  for event in state.http.overflow.iter() {
    if event.kind == EVENT_BODY {
      state.http.segments.remove(&event.operation);
    } else if event.kind == 2 {
      socket::elide_transport_socket_discard(event.value);
    }
  }
  let mut retired = lock(&RETIRED_SEGMENTS);
  for (id, segment) in state.http.segments.drain() {
    retired.insert(id, segment.storage);
  }
  state.http.overflow.extend(events);
}

/// Release a segment after its driver retired; safe on any thread, exactly once per segment.
/// Returns `INVALID` if it is not present in the retired registry.
pub fn elide_transport_http_segment_release_retired(segment: u64) -> i32 {
  if lock(&RETIRED_SEGMENTS).remove(&segment).is_some() {
    0
  } else {
    INVALID
  }
}

/// Submit the next receive for an HTTP socket. Returns false when admission failed.
///
/// Nothing is submitted while unacked segments pin [`BODY_WINDOW_BYTES`] of receive capacity;
/// [`elide_transport_http_segment_ack`] and [`elide_transport_http_segment_release`] re-arm once
/// they drop below it.
fn arm_receive(state: &mut DriverState, socket: u64) -> bool {
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return false;
  };
  if http.receiving {
    return true;
  }
  if http.pending_eof
    || http
      .tls
      .as_ref()
      .is_some_and(|tls| tls.input_eof || tls.lane.input_closed())
  {
    if let Some(id) = http.persistent {
      return state.driver.pause_persistent_receive(id).is_ok();
    }
    return true;
  }
  if let Some(h2) = &http.h2 {
    if h2.input_capacity() < http.capacity {
      if let Some(id) = http.persistent {
        return state.driver.pause_persistent_receive(id).is_ok();
      }
      return true;
    }
  } else {
    let finished = http.parser.is_closed() && !http.parser.body_pending();
    if finished
      || http.closing
      || !http.pending_input.is_empty()
      || (http.outstanding >= MAX_EXCHANGES && !http.parser.body_pending())
      || (http.draining && http.body == 0)
      || http.pinned.get() >= BODY_WINDOW_BYTES
    {
      if let Some(id) = http.persistent {
        return state.driver.pause_persistent_receive(id).is_ok();
      }
      return true;
    }
  }
  let Some(connection) = state.sockets.get(&socket) else {
    return false;
  };
  if let Some(id) = http.persistent {
    return state.driver.resume_persistent_receive(id).is_ok();
  }
  if http.capacity == 16 * 1024 && state.driver.backend() == Backend::IoUring {
    return match state.driver.enable_persistent_receive(
      connection,
      http.budget.clone(),
      http.capacity,
      BODY_WINDOW_BYTES,
    ) {
      Ok(id) => {
        http.persistent = Some(id);
        state.operations.insert(id, Operation::http(socket));
        true
      }
      Err(_) => false,
    };
  }
  let Ok(storage) = Buffer::receive(http.capacity, http.budget.clone()) else {
    return false;
  };
  match state.driver.receive(connection, storage) {
    Ok(operation) => {
      state.operations.insert(operation, Operation::http(socket));
      http.receiving = true;
      true
    }
    Err(_) => false,
  }
}

/// Handle a receive completion on an HTTP socket, queueing resulting events.
pub(super) fn on_received(
  state: &mut DriverState,
  socket: u64,
  status: io::Result<usize>,
  storage: Buffer,
  events: &mut VecDeque<NativeEvent>,
) {
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return;
  };
  http.receiving = false;
  match status {
    Ok(0) if http.tls.is_none() => {
      end_input(state, socket, events);
      return;
    }
    Ok(0) => {
      tls_socket::end_input(state, socket, events);
      return;
    }
    Err(_) => {
      close_socket(state, socket, events);
      return;
    }
    Ok(_) => {}
  }
  if http.draining && http.body == 0 && http.h2.is_none() {
    pump(state, socket, events);
    return;
  }
  if let Some(tls) = &mut http.tls {
    let credit = storage.receive_credit();
    if tls.lane.feed(storage).is_err() {
      close_socket(state, socket, events);
      return;
    }
    // The bounded ciphertext lane owns storage now; fragmented records need new delivery credit.
    if let Some(credit) = credit {
      credit.ack();
    }
    tls_socket::drive(state, socket, events);
    pump(state, socket, events);
  } else {
    process_input(state, socket, storage.freeze(), events);
  }
}

pub(super) fn on_persistent_received(
  state: &mut DriverState,
  socket: u64,
  status: io::Result<usize>,
  storage: Option<Buffer>,
  events: &mut VecDeque<NativeEvent>,
) {
  if state.http.sockets.get(&socket).is_some_and(|http| http.tls.is_some()) {
    if matches!(status, Ok(0)) {
      tls_socket::end_input(state, socket, events);
    } else if let Some(storage) = storage {
      on_received(state, socket, status, storage, events);
    } else {
      close_socket(state, socket, events);
    }
    return;
  }
  let length = match status {
    Ok(length) if length > 0 => length,
    Ok(0) => {
      end_input(state, socket, events);
      return;
    }
    _ => {
      close_socket(state, socket, events);
      return;
    }
  };
  let Some(storage) = storage.filter(|buffer| buffer.as_init().len() == length) else {
    close_socket(state, socket, events);
    return;
  };
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return;
  };
  if http.closing || (http.draining && http.body == 0) {
    return;
  }
  let storage = storage.freeze();
  let charge = storage.receive_credit().map(|credit| {
    http.pinned.set(http.pinned.get() + http.capacity);
    Rc::new(ReceiveCharge {
      capacity: http.capacity,
      pinned: http.pinned.clone(),
      provided: Some(credit),
    })
  });
  let input = PendingInput { bytes: storage, charge };
  if !http.pending_input.is_empty() || (http.outstanding >= MAX_EXCHANGES && !http.parser.body_pending()) {
    http.pending_input.push_back(input);
    arm_receive(state, socket);
  } else {
    process_pending(state, socket, input, events);
  }
}

/// A streaming response is mid-body. EOF then means the client went away rather than a request
/// half-close awaiting its response, so the exchange must observe the disconnect before its next
/// write (a body that never ends would otherwise hold the socket open indefinitely).
fn streams_open(http: &HttpSocket) -> bool {
  http.ready.values().any(|parts| parts.streaming && !parts.complete)
}

fn end_input(state: &mut DriverState, socket: u64, events: &mut VecDeque<NativeEvent>) {
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return;
  };
  http.pending_eof = true;
  if http.pending_input.is_empty() {
    if http.parser.body_pending() || streams_open(http) {
      close_socket(state, socket, events);
      return;
    }
    http.closing = true;
    end_body(http, socket, aborted(), events);
  }
  pump(state, socket, events);
}

fn process_input(state: &mut DriverState, socket: u64, storage: FrozenBuffer, events: &mut VecDeque<NativeEvent>) {
  let charge = storage.receive_credit().and_then(|credit| {
    let http = state.http.sockets.get(&socket)?;
    http.pinned.set(http.pinned.get() + http.capacity);
    Some(Rc::new(ReceiveCharge {
      capacity: http.capacity,
      pinned: http.pinned.clone(),
      provided: Some(credit),
    }))
  });
  process_pending(state, socket, PendingInput { bytes: storage, charge }, events);
}

fn process_pending(state: &mut DriverState, socket: u64, input: PendingInput, events: &mut VecDeque<NativeEvent>) {
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return;
  };
  let mut charge = input.charge;
  let mut outcomes = VecDeque::new();
  let pending = http.parser.ingest_bounded(
    input.bytes,
    MAX_EXCHANGES.saturating_sub(http.outstanding),
    &mut outcomes,
  );
  // One charge per receive that yields segments, created with its first segment.
  for outcome in outcomes {
    match outcome {
      Outcome::Request(exchange) => {
        if http.draining {
          break;
        }
        if exchange.expect_continue {
          let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
          let encoded = Buffer::new(interim.len(), http.budget.clone()).and_then(|mut buffer| {
            buffer.write(0, interim)?;
            Ok(buffer.freeze())
          });
          let id = identity();
          let Ok(encoded) = encoded else {
            close_socket(state, socket, events);
            return;
          };
          if id == 0 {
            close_socket(state, socket, events);
            return;
          }
          // RFC 9112 §9.2: even 1xx belongs to the oldest request without a final response.
          // Preserve pipeline order without completing this exchange.
          http.order.push_back(id);
          http.queue(id, Parts::single(encoded));
        }
        // The slot address is the handle and the address of its layout: readable from any
        // thread without a lookup until the JVM frees the exchange, and never mutated by the
        // driver after creation.
        http.outstanding += 1;
        let has_body = exchange.has_body;
        let id = state.http.exchanges.insert(socket, exchange, http.budget.clone(), 0);
        http.order.push_back(id);
        events.push_back(event(EVENT_REQUEST, 0, socket, id, 0));
        if has_body {
          http.body = id;
        }
      }
      Outcome::Segment(bytes) => {
        let charge = charge
          .get_or_insert_with(|| ReceiveCharge::new(http.capacity, &http.pinned))
          .clone();
        let slice = bytes.as_ref();
        let layout = SegmentLayout {
          data: slice.as_ptr() as u64,
          len: slice.len() as u64,
        };
        let storage = Box::new(SegmentStorage { layout, bytes });
        let id = &*storage as *const SegmentStorage as u64;
        let len = storage.layout.len as i64;
        let segment = BodySegment {
          storage,
          socket,
          charge: Some(charge),
          h2: None,
        };
        state.http.segments.insert(id, segment);
        events.push_back(event(EVENT_BODY, id, socket, http.body, len));
      }
      Outcome::BodyEnd => end_body(http, socket, 0, events),
      Outcome::Error(error) => {
        end_body(http, socket, malformed(), events);
        // The parser is closed; answer the error after any earlier responses.
        let id = identity();
        let encoded = encode_response(
          &http.budget,
          &mut state.http.date,
          1,
          error.status(),
          &[],
          b"",
          false,
          false,
        );
        if let (Ok(encoded), true) = (encoded, id != 0) {
          http.order.push_back(id);
          http.queue(id, Parts::single(encoded));
        }
        http.closing = true;
      }
    }
  }
  if let Some(bytes) = pending {
    http.pending_input.push_front(PendingInput { bytes, charge });
  } else {
    drop(charge);
    if !http.closing
      && (http.outstanding < MAX_EXCHANGES || http.parser.body_pending())
      && let Some(next) = http.pending_input.pop_front()
    {
      process_pending(state, socket, next, events);
      return;
    }
  }
  if http.pending_eof && http.pending_input.is_empty() {
    if http.parser.body_pending() || streams_open(http) {
      close_socket(state, socket, events);
      return;
    }
    http.closing = true;
    end_body(http, socket, aborted(), events);
  }
  pump(state, socket, events);
  if state.http.sockets.get(&socket).is_some_and(|http| !http.closing) {
    arm_receive(state, socket);
  }
}

/// Handle a vectored send completion on an HTTP socket: report the parts it carried, resume a
/// short send, then refill the lane.
pub(super) fn on_sent(
  state: &mut DriverState,
  socket: u64,
  status: io::Result<usize>,
  buffers: Vec<FrozenBuffer>,
  events: &mut VecDeque<NativeEvent>,
) {
  if state.http.sockets.get(&socket).is_some_and(|http| http.tls.is_some()) {
    tls_socket::on_sent(state, socket, status, buffers, events);
  } else {
    on_plain_sent(state, socket, status, buffers, events);
  }
}

fn on_plain_sent(
  state: &mut DriverState,
  socket: u64,
  status: io::Result<usize>,
  mut buffers: Vec<FrozenBuffer>,
  events: &mut VecDeque<NativeEvent>,
) {
  if state.http.sockets.get(&socket).is_some_and(|http| http.h2.is_some()) {
    match status {
      Ok(sent) => h2_socket::sent(state, socket, sent, events),
      Err(_) => close_socket(state, socket, events),
    }
    return;
  }
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return;
  };
  http.sending = false;
  let resume = match status {
    Ok(sent) => {
      let mut left = sent;
      // Every fully covered part reports, empty ones included; a partial one stays at the front.
      while let Some(part) = http.inflight.front_mut() {
        if left < part.remaining {
          part.remaining -= left;
          break;
        }
        left -= part.remaining;
        let part = http.inflight.pop_front().unwrap();
        let ready = if let Some(parts) = http.ready.get_mut(&part.exchange) {
          parts.queued_bytes -= part.len;
          true
        } else {
          false
        };
        // An exchange's in-flight parts are contiguous in request order.
        if !ready
          && !http
            .inflight
            .front()
            .is_some_and(|pending| pending.exchange == part.exchange)
          && http.retired.remove(&part.exchange).is_some()
        {
          state.http.exchanges.recycle(part.exchange);
          http.outstanding -= 1;
        }
        if part.report {
          events.push_back(event(EVENT_PART_SENT, 0, socket, part.exchange, part.len as i64));
        }
      }
      buffers.advance(sent)
    }
    Err(error) => Err(error),
  };
  match resume {
    Ok(true) => http.vector = buffers,
    Ok(false) => {
      // A short send: the remainder goes out before anything else.
      let Some(connection) = state.sockets.get(&socket) else {
        return;
      };
      match state.driver.send_vectored(connection, buffers) {
        Ok(operation) => {
          state.operations.insert(operation, Operation::http(socket));
          http.sending = true;
        }
        Err((error, buffers)) if error.kind() == io::ErrorKind::WouldBlock => {
          // Keep the batch and its in-flight accounting until a driver slot opens.
          http.vector = buffers;
          state.http.queue_retry(socket);
        }
        Err((error, _)) => fail_writes(http, socket, error_code(error), events),
      }
    }
    Err(error) => fail_writes(http, socket, error_code(error), events),
  }
  let pending = state.http.sockets.get_mut(&socket).and_then(|http| {
    (http.outstanding < MAX_EXCHANGES)
      .then(|| http.pending_input.pop_front())
      .flatten()
  });
  if let Some(pending) = pending {
    process_pending(state, socket, pending, events);
  } else {
    pump(state, socket, events);
  }
}

/// Send ready parts in request order while the write lane is free. The front exchange's queued
/// parts go first; once it is complete and drained, following complete exchanges join the same
/// vectored send. An incomplete streaming exchange at the front holds the lane.
fn pump(state: &mut DriverState, socket: u64, events: &mut VecDeque<NativeEvent>) {
  if let Some(http) = state.http.sockets.get_mut(&socket)
    && http.h2.is_none()
    && http.cork_depth != 0
  {
    if http.cork_bytes < CORK_BYTES {
      return;
    }
    http.cork_bytes = 0;
  }
  if state.http.sockets.get(&socket).is_some_and(|http| http.h2.is_some()) {
    h2_socket::drive(state, socket, events);
    tls_socket::drive(state, socket, events);
    resume_receiving(state, socket);
    return;
  }
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return;
  };
  if http.tls.as_ref().is_some_and(|tls| tls.driving) {
    return;
  }
  if !http.sending {
    let mut batch = std::mem::take(&mut http.vector);
    while let Some(&front) = http.order.front() {
      let Some(parts) = http.ready.get_mut(&front) else {
        break;
      };
      while http.inflight.len() < SEND_PARTS {
        let Some(part) = parts.pop_front() else {
          break;
        };
        let len = part.as_ref().len();
        http.inflight.push_back(Inflight {
          exchange: front,
          len,
          remaining: len,
          report: parts.streaming,
        });
        if let Some(previous) = batch.last_mut() {
          if let Err(part) = previous.merge(part) {
            batch.push(part);
          }
        } else {
          batch.push(part);
        }
      }
      if !(parts.complete && parts.is_empty()) {
        break;
      }
      http.ready.remove(&front);
      http.order.pop_front();
    }
    if batch.is_empty() {
      http.vector = batch;
    } else if let Some(tls) = &mut http.tls {
      tls.lane.enqueue(batch);
      http.sending = true;
    } else if let Some(connection) = state.sockets.get(&socket) {
      match state.driver.send_vectored(connection, batch) {
        Ok(operation) => {
          state.operations.insert(operation, Operation::http(socket));
          http.sending = true;
        }
        Err((error, batch)) if error.kind() == io::ErrorKind::WouldBlock => {
          // Keep the batch and its in-flight accounting until a driver slot opens.
          http.vector = batch;
          state.http.queue_retry(socket);
        }
        Err((error, _)) => fail_writes(http, socket, error_code(error), events),
      }
    }
  }
  tls_socket::drive(state, socket, events);
  let Some(http) = state.http.sockets.get_mut(&socket) else {
    return;
  };
  if (http.closing || (http.draining && http.body == 0))
    && !http.sending
    && http.order.is_empty()
    && http.vector.is_empty()
  {
    if let Some(tls) = &mut http.tls {
      tls.lane.close();
      tls_socket::drive(state, socket, events);
    } else {
      close_socket(state, socket, events);
    }
  }
  // Re-arm the receive lane for any live, non-closing socket whose lane is empty: a transient
  // `arm_receive` failure (owner-budget exhaustion or proactor admission `WouldBlock`) leaves
  // no operation in flight and previously no code path retried it. `pump` is the chokepoint
  // every `respond`/`send`/`free`/`abandon`/`on_sent`/`on_received` path already drains through,
  // so re-arming here — after the close-check, which itself may have removed the socket —
  // catches the moment the budget that blocked the last arm is paid back, even on the
  // early-out branches above (a busy send lane or a not-yet-ready front response).
  resume_receiving(state, socket);
}

pub(super) fn needs_poll(state: &DriverState) -> bool {
  if state.http.retry_remaining != 0 {
    return true;
  }
  let mut socket = state.http.retry_head;
  while socket != 0 {
    let http = &state.http.sockets[&socket];
    if http.h2.as_ref().is_some_and(H2Socket::needs_poll) || http.tls.as_ref().is_some_and(TlsSocket::needs_poll) {
      return true;
    }
    socket = http.retry_next;
  }
  false
}

/// Retry only registered work after polling frees driver slots. TLS remains registered for
/// handshake deadlines and internally scheduled H2 progress; idle plaintext sockets never enter.
pub(super) fn retry_deferred(state: &mut DriverState, events: &mut Vec<NativeEvent>) {
  if state.http.retry_remaining == 0 {
    state.http.retry_remaining = state.http.retry_len;
  }
  state.http.retry_remaining = state.http.retry_remaining.min(state.http.retry_len);
  let count = state.http.retry_remaining.min(RETRY_BATCH);
  let mut pending = VecDeque::new();
  for _ in 0..count {
    let socket = state.http.retry_head;
    if socket == 0 {
      state.http.retry_remaining = 0;
      break;
    }
    let remaining = state.http.retry_remaining - 1;
    state.http.remove_retry(socket);
    pump(state, socket, &mut pending);
    events.extend(pending.drain(..));
    if state
      .http
      .sockets
      .get(&socket)
      .is_some_and(|http| http.tls.is_some() || (!http.sending && !http.vector.is_empty()))
    {
      state.http.queue_retry(socket);
    }
    // No guest callbacks run here. Internal requeues must not extend this round; fresh work
    // queued between polls does extend it, even when its socket was already registered for TLS.
    state.http.retry_remaining = remaining.min(state.http.retry_len);
  }
}

/// Drop every queued and in-flight part after a write failure, reporting the streaming ones,
/// and close once the lane is idle.
fn fail_writes(http: &mut HttpSocket, socket: u64, code: i64, events: &mut VecDeque<NativeEvent>) {
  for part in http.inflight.drain(..) {
    if part.report {
      events.push_back(event(EVENT_PART_SENT, 0, socket, part.exchange, code));
    }
  }
  for (exchange, parts) in http.ready.drain() {
    if parts.streaming {
      for _ in 0..parts.len() {
        events.push_back(event(EVENT_PART_SENT, 0, socket, exchange, code));
      }
    }
  }
  http.order.clear();
  http.vector.clear();
  http.closing = true;
}

/// Report the pending body as ended with `result`, if the JVM was told to expect one.
fn end_body(http: &mut HttpSocket, socket: u64, result: i64, events: &mut VecDeque<NativeEvent>) {
  if http.body != 0 {
    events.push_back(event(EVENT_BODY_END, 0, socket, http.body, result));
    http.body = 0;
  }
}

/// Stop delivering `exchange`'s body once the JVM has answered or dropped it: the parser keeps
/// framing silently, the connection closes after its queued responses, and the body is ended
/// with an error whether or not a segment was delivered. Segments already delivered stay valid.
/// Whether a caller-supplied `connection` header carries the `close` token.
fn declares_close(headers: &[ResponseHeader<'_>]) -> bool {
  headers.iter().any(|header| {
    header.name.eq_ignore_ascii_case(b"connection")
      && header
        .value
        .split(|&byte| byte == b',')
        .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"))
  })
}

fn discard_body(http: &mut HttpSocket, socket: u64, exchange: u64, events: &mut VecDeque<NativeEvent>) {
  if http.body != exchange || !http.parser.body_pending() {
    return;
  }
  http.parser.discard_body();
  http.closing = true;
  end_body(http, socket, aborted(), events);
}

pub(super) fn close_socket(state: &mut DriverState, socket: u64, events: &mut VecDeque<NativeEvent>) {
  super::serving::disconnected(state, socket);
  let mut retiring = false;
  // Exchanges and segments outlive their socket: the JVM may still read them, and frees each
  // explicitly. A body still being framed is truncated.
  state.http.remove_retry(socket);
  if let Some(mut http) = state.http.sockets.remove(&socket) {
    retiring = http.persistent.is_some();
    h2_socket::closed(&mut http, socket, events);
    end_body(&mut http, socket, aborted(), events);
    fail_writes(&mut http, socket, aborted(), events);
    for id in http.retired.keys() {
      state.http.exchanges.recycle(*id);
    }
  }
  state.workloads.remove(&socket);
  if let Some(connection) = state.sockets.remove(&socket) {
    let _ = connection.shutdown(std::net::Shutdown::Both);
    for (operation, pending) in &state.operations {
      if pending.socket == socket {
        state.driver.cancel(*operation);
      }
    }
  }
  if !retiring {
    events.push_back(event(EVENT_CLOSED, 0, socket, 0, 0));
  }
}

pub(super) fn on_persistent_retired(state: &mut DriverState, socket: u64, events: &mut VecDeque<NativeEvent>) {
  if let Some(http) = state.http.sockets.get_mut(&socket) {
    http.persistent = None;
    close_socket(state, socket, events);
  } else {
    events.push_back(event(EVENT_CLOSED, 0, socket, 0, 0));
  }
}

/// Dereference an exchange handle.
///
/// The handle is the address of a slotted `HttpExchange` the owning driver keeps alive until
/// `free`; the caller guarantees it has not passed that yet. This is an unsafe
/// host contract shared with the JVM bindings, not a memory-safety boundary for guest code.
fn with_exchange<R>(exchange: u64, f: impl FnOnce(&Exchange) -> R) -> Option<R> {
  if exchange == 0 || !exchange.is_multiple_of(align_of::<HttpExchange>() as u64) {
    return None;
  }
  // SAFETY: ABI callers must hold a live exchange lease through this synchronous access.
  let entry = unsafe { &*(exchange as *const HttpExchange) };
  Some(f(&entry.exchange))
}

/// Method code of a request (see `http::Method`), or INVALID.
pub fn elide_transport_http_method(exchange: u64) -> i32 {
  with_exchange(exchange, |x| x.method as u8 as i32).unwrap_or(INVALID)
}

/// `0` for HTTP/1.0, `1` for HTTP/1.1, or INVALID.
pub fn elide_transport_http_version(exchange: u64) -> i32 {
  with_exchange(exchange, |x| x.version as i32).unwrap_or(INVALID)
}

/// Number of request headers, or INVALID.
pub fn elide_transport_http_header_count(exchange: u64) -> i32 {
  with_exchange(exchange, |x| x.headers.len() as i32).unwrap_or(INVALID)
}

/// Whether the connection stays open after this exchange (1) or closes (0), or INVALID.
pub fn elide_transport_http_keep_alive(exchange: u64) -> i32 {
  with_exchange(exchange, |x| x.keep_alive as i32).unwrap_or(INVALID)
}

/// View kinds for [`elide_transport_http_view`].
pub const VIEW_METHOD: u32 = 0;
pub const VIEW_PATH: u32 = 1;
pub const VIEW_HEADER_NAME: u32 = 2;
pub const VIEW_HEADER_VALUE: u32 = 3;
pub const VIEW_BODY: u32 = 4;
/// The whole request head (request line through the blank line).
pub const VIEW_HEAD: u32 = 5;

/// Write the address and length of a request byte range into `output` (two `u64`s).
///
/// The bytes stay valid until the exchange is responded to or released. `VIEW_BODY`
/// reports address zero and length zero: bodies are delivered as [`EVENT_BODY`] segments.
///
/// # Safety
/// `output` must point to 16 writable bytes owned by the caller.
pub unsafe fn elide_transport_http_view(exchange: u64, kind: u32, index: u32, output: *mut u64) -> i32 {
  if output.is_null() {
    return INVALID;
  }
  let span = with_exchange(exchange, |x| match kind {
    VIEW_METHOD => Some(raw(x.method_bytes())),
    VIEW_PATH => Some(raw(x.path_bytes())),
    VIEW_HEADER_NAME => x.header_name(index as usize).map(raw),
    VIEW_HEADER_VALUE => x.header_value(index as usize).map(raw),
    VIEW_BODY => Some((0, 0)),
    VIEW_HEAD => Some(raw(x.head.as_ref())),
    _ => None,
  });
  match span {
    Some(Some((address, length))) => {
      // SAFETY: The ABI caller provides two writable, aligned u64 output slots.
      unsafe {
        output.write(address);
        output.add(1).write(length);
      }
      0
    }
    _ => INVALID,
  }
}

fn raw(bytes: &[u8]) -> (u64, u64) {
  (bytes.as_ptr() as u64, bytes.len() as u64)
}

/// Write the request's byte ranges within the head as `u32` pairs into `output`:
/// method start/end, path start/end, then name start/end and value start/end per header.
/// `capacity` is the number of `u32` slots available; returns the number of slots needed,
/// writing nothing when it exceeds `capacity`, or INVALID.
///
/// # Safety
/// `output` must be writable for `capacity` `u32`s.
pub unsafe fn elide_transport_http_spans(exchange: u64, output: *mut u32, capacity: u32) -> i32 {
  with_exchange(exchange, |x| {
    let needed = 4 + x.headers.len() * 4;
    if needed > capacity as usize || output.is_null() {
      return needed as i32;
    }
    // SAFETY: The caller provides capacity writable u32 slots; needed was checked above.
    unsafe {
      output.write(x.method_span.start);
      output.add(1).write(x.method_span.end);
      output.add(2).write(x.path.start);
      output.add(3).write(x.path.end);
      for (i, span) in x.headers.iter().enumerate() {
        let base = output.add(4 + i * 4);
        base.write(span.name.start);
        base.add(1).write(span.name.end);
        base.add(2).write(span.value.start);
        base.add(3).write(span.value.end);
      }
    }
    needed as i32
  })
  .unwrap_or(INVALID)
}

/// Respond to an exchange; its memory stays readable until [`elide_transport_http_free`].
///
/// `headers` points to `count` records of four `u64`s: name address, name length,
/// value address, value length. `body` is `body_length` bytes. All memory is read
/// during the call only. A HEAD request sends the head with the body's length.
///
/// With [`RESPOND_STREAM`] in `flags` only the head is encoded and `body` is ignored:
/// `body_length` declares the body (`content-length`), or `u64::MAX` for an unknown length
/// (`transfer-encoding: chunked`; on HTTP/1.0 the connection closes after the body instead).
/// Parts then follow through [`elide_transport_http_chunk_send`].
///
/// # Safety
/// Every address must be readable for its stated length for the duration of the call.
#[allow(clippy::too_many_arguments)] // Preserve the transport ABI call shape.
pub unsafe fn elide_transport_http_respond(
  driver: u64,
  exchange: u64,
  status: u32,
  headers: *const u64,
  count: u32,
  body: *const u8,
  body_length: u64,
  flags: u32,
) -> i32 {
  if !(100..1000).contains(&status) || (count > 0 && headers.is_null()) {
    return INVALID;
  }
  let stream = flags & RESPOND_STREAM != 0;
  let framing = match body_length {
    u64::MAX if stream => Framing::Chunked,
    declared => Framing::Length(declared),
  };
  let body: &[u8] = match usize::try_from(body_length) {
    _ if stream => &[],
    Ok(0) => &[],
    // SAFETY: The ABI caller guarantees length readable bytes for the duration of this call.
    Ok(length) if !body.is_null() => unsafe { std::slice::from_raw_parts(body, length) },
    _ => return INVALID,
  };
  let headers: Vec<ResponseHeader<'_>> = (0..count as usize)
    // SAFETY: The ABI caller supplies count four-u64 records and live name/value byte ranges.
    .map(|i| unsafe {
      let record = headers.add(i * 4);
      let name = std::slice::from_raw_parts(record.read() as *const u8, record.add(1).read() as usize);
      let value = std::slice::from_raw_parts(record.add(2).read() as *const u8, record.add(3).read() as usize);
      ResponseHeader { name, value }
    })
    .collect();
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    if state
      .http
      .exchanges
      .get(&exchange)
      .is_some_and(|entry| entry.stream != 0)
    {
      return h2_socket::respond(state, exchange, status as u16, &headers, body, body_length, stream);
    }
    let Some(entry) = state.http.exchanges.get_mut(&exchange) else {
      return INVALID;
    };
    if entry.responded {
      return INVALID;
    }
    let socket = entry.socket;
    let Some(http) = state.http.sockets.get_mut(&socket) else {
      return INVALID;
    };
    let mut events = VecDeque::new();
    discard_body(http, socket, exchange, &mut events);
    // The encoder owns `connection` and drops the caller's copy; a declared close still ends
    // the connection, as `SEND_CLOSE` does for `elide_transport_http_send`.
    let keep_alive = entry.exchange.keep_alive && !http.closing && !declares_close(&headers);
    let version = entry.exchange.version;
    let head_only = entry.exchange.method == Method::Head;
    let status = status as u16;
    // Mirror the encoder: chunked cannot ride HTTP/1.0, and these responses carry no body.
    let framing = match framing {
      Framing::Chunked if status == 205 => Framing::Length(0),
      Framing::Chunked if version == 0 => Framing::Close,
      other => other,
    };
    let bodiless = head_only || matches!(status, 204 | 205 | 304) || (100..200).contains(&status);
    let encoded = if stream {
      encode_head(
        &http.budget,
        &mut state.http.date,
        version,
        status,
        &headers,
        framing,
        head_only,
        keep_alive,
      )
    } else {
      encode_response(
        &http.budget,
        &mut state.http.date,
        version,
        status,
        &headers,
        body,
        head_only,
        keep_alive,
      )
    };
    let Ok(encoded) = encoded else {
      state.http.overflow.extend(events);
      abandon(state, exchange, true);
      return INVALID;
    };
    entry.responded = true;
    let mut parts = Parts::single(encoded);
    if stream {
      parts.complete = false;
      parts.streaming = true;
      parts.framing = framing;
      parts.bodiless = bodiless;
    }
    http.queue(exchange, parts);
    if !keep_alive || framing == Framing::Close {
      http.closing = true;
    }
    pump(state, socket, &mut events);
    state.http.overflow.extend(events);
    0
  })
}

/// Allocate storage for one response part of a streaming exchange: `capacity` payload bytes the
/// caller fills at `*address`, framed in place by [`elide_transport_http_chunk_send`]. Any
/// thread, while the exchange is unfreed; several parts may be prepared ahead. Returns the
/// buffer handle, which the caller owns until `chunk_send` takes it, or zero on failure.
///
/// # Safety
/// `exchange` must be a live handle and `address` writable.
pub unsafe fn elide_transport_http_chunk_prepare(exchange: u64, capacity: u64, address: *mut u64) -> u64 {
  let Ok(capacity) = usize::try_from(capacity) else {
    return 0;
  };
  if address.is_null() || exchange == 0 || !exchange.is_multiple_of(align_of::<HttpExchange>() as u64) {
    return 0;
  }
  let Some(total) = capacity.checked_add(CHUNK_HEADROOM + CHUNK_TAIL) else {
    return 0;
  };
  // SAFETY: The ABI caller retains the exchange lease throughout preparation.
  let entry = unsafe { &*(exchange as *const HttpExchange) };
  let Ok(mut buffer) = Buffer::new(total, entry.budget.clone()) else {
    return 0;
  };
  buffer.ensure_init();
  // SAFETY: The checked allocation includes CHUNK_HEADROOM bytes before the payload.
  let payload = unsafe { buffer.buf_mut_ptr().add(CHUNK_HEADROOM) } as u64;
  let id = identity();
  if id == 0 {
    return 0;
  }
  lock(registry(id)).insert(id, Storage::Mutable(buffer));
  // SAFETY: The ABI caller supplies a non-null, writable u64 output slot.
  unsafe { address.write(payload) };
  id
}

/// Queue the first `length` payload bytes of a prepared part on a streaming exchange, framed
/// per the response; [`CHUNK_FINAL`] in `flags` ends the response. Driver thread only.
///
/// Returns zero and takes the buffer on success. `BUSY` leaves the buffer with the caller when
/// the framed part would exceed [`RESPONSE_WINDOW_BYTES`] queued or in flight; wait for
/// [`EVENT_PART_SENT`]. `INVALID` leaves it with the caller for a bad handle, a length beyond the
/// prepared capacity, or an exchange that is not streaming. A payload that diverges from a
/// declared `content-length` fails the connection and returns a negative portable error.
/// With [`CHUNK_RETAIN`], `buffer` is a frozen handle and payload starts at offset zero. The
/// caller keeps the handle on every result; the driver retains its own immutable lease on
/// success. HTTP/1 chunked framing rejects this flag; use prepared mutable parts instead.
pub fn elide_transport_http_chunk_send(driver: u64, exchange: u64, buffer: u64, length: u64, flags: u32) -> i32 {
  let Ok(length) = usize::try_from(length) else {
    return INVALID;
  };
  let final_part = flags & CHUNK_FINAL != 0;
  let retain = flags & CHUNK_RETAIN != 0;
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    if state
      .http
      .exchanges
      .get(&exchange)
      .is_some_and(|entry| entry.stream != 0)
    {
      return h2_socket::chunk(state, exchange, buffer, length, final_part, retain);
    }
    let Some(entry) = state.http.exchanges.get(&exchange) else {
      return INVALID;
    };
    let socket = entry.socket;
    let Some(http) = state.http.sockets.get_mut(&socket) else {
      return INVALID;
    };
    let Some(parts) = http.ready.get_mut(&exchange) else {
      return INVALID;
    };
    if !parts.streaming || parts.complete {
      return INVALID;
    }
    let part = if retain {
      if parts.framing == Framing::Chunked {
        return INVALID;
      }
      let Some(part) = retained_body(buffer, length) else {
        return INVALID;
      };
      let part = if parts.bodiless {
        FrozenBuffer::slice(&part, 0..0).unwrap()
      } else {
        part
      };
      if parts.queued_bytes + part.as_ref().len() > RESPONSE_WINDOW_BYTES {
        return BUSY;
      }
      part
    } else {
      let mut buffers = lock(registry(buffer));
      let Some(Storage::Mutable(storage)) = buffers.get_mut(&buffer) else {
        return INVALID;
      };
      // Any mutable handle can arrive here, not only a prepared part; never underflow.
      if storage
        .buf_capacity()
        .checked_sub(CHUNK_HEADROOM + CHUNK_TAIL)
        .is_none_or(|max| length > max)
      {
        return INVALID;
      }
      // Capacity was initialized by prepare. A part that puts nothing on the wire (bodiless
      // response, empty non-final chunk) is queued empty so it still reports in order.
      let range = match parts.framing {
        _ if parts.bodiless || (length == 0 && !final_part) => {
          // SAFETY: prepare initialized this headroom; capacity was checked before selecting framing.
          unsafe { storage.set_len(CHUNK_HEADROOM) };
          CHUNK_HEADROOM..CHUNK_HEADROOM
        }
        // SAFETY: prepare initialized the full capacity and the payload length was bounded above.
        Framing::Chunked => unsafe { frame_chunk(storage, length, final_part) },
        _ => {
          // SAFETY: prepare initialized the capacity and length is bounded by that capacity.
          unsafe { storage.set_len(CHUNK_HEADROOM + length) };
          CHUNK_HEADROOM..CHUNK_HEADROOM + length
        }
      };
      if parts.queued_bytes + range.len() > RESPONSE_WINDOW_BYTES {
        return BUSY;
      }
      let Some(Storage::Mutable(storage)) = buffers.remove(&buffer) else {
        return INVALID;
      };
      drop(buffers);
      FrozenBuffer::slice(&storage.freeze(), range).unwrap()
    };
    let mut events = VecDeque::new();
    let accepted = parts.body_bytes.saturating_add(length as u64);
    if let (false, Framing::Length(declared)) = (parts.bodiless, parts.framing)
      && (accepted > declared || (final_part && accepted != declared))
    {
      drop(part);
      close_socket(state, socket, &mut events);
      state.http.overflow.extend(events);
      return malformed() as i32;
    }
    parts.body_bytes = accepted;
    let queued = part.as_ref().len();
    parts.queued_bytes += queued;
    parts.push_back(part);
    if final_part {
      parts.complete = true;
    }
    http.cork_write(queued);
    pump(state, socket, &mut events);
    state.http.overflow.extend(events);
    0
  })
}

/// Clone only initialized immutable bytes; the registry borrow ends before queueing or pumping.
fn retained_body(buffer: u64, length: usize) -> Option<FrozenBuffer> {
  let buffers = lock(registry(buffer));
  let Storage::Frozen(storage) = buffers.get(&buffer)? else {
    return None;
  };
  storage.slice(0..length).ok()
}

/// Release a retained head delivered in a request event's `result`.
///
/// Any thread may call this, exactly once per event. Zero is ignored.
///
/// # Safety
/// `head` must be a value delivered by a request event that has not been released.
pub unsafe fn elide_transport_http_head_release(head: u64) -> i32 {
  if head == 0 {
    return INVALID;
  }
  // SAFETY: The caller transfers one live retained-head allocation to this release function.
  let length = unsafe { RetainedHead::len(head) };
  // SAFETY: retain used Box::into_raw on this byte slice; its stored length reconstructs the layout.
  drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(head as *mut u8, length)) });
  0
}

/// Allocate the exchange's response buffer: `capacity` writable bytes the caller fills with the
/// complete response before [`elide_transport_http_send`]. Any thread, once per exchange, while
/// the exchange is unfreed. Returns the buffer address, or zero on failure.
///
/// # Safety
/// `exchange` must be a live handle; the caller must not call this concurrently with `send` or
/// `free` for the same exchange.
pub unsafe fn elide_transport_http_prepare(exchange: u64, capacity: u64) -> u64 {
  let Ok(capacity) = usize::try_from(capacity) else {
    return 0;
  };
  if exchange == 0 || !exchange.is_multiple_of(align_of::<HttpExchange>() as u64) {
    return 0;
  }
  // SAFETY: The caller holds a live exchange lease throughout response preparation.
  let entry = unsafe { &*(exchange as *const HttpExchange) };
  let Ok(mut buffer) = Buffer::response(capacity, &entry.budget) else {
    return 0;
  };
  buffer.ensure_init();
  let address = buffer.buf_mut_ptr() as u64;
  // SAFETY: The exchange is owner-thread confined; preparation exclusively replaces its pending buffer.
  unsafe { *entry.pending.get() = Some(buffer) };
  address
}

/// Send the response written into the buffer from [`elide_transport_http_prepare`]: its first
/// `length` bytes are the complete response (status line, headers, blank line and body). `flags`
/// may carry [`SEND_CLOSE`] when the response declared `connection: close`. Driver thread only;
/// the exchange stays readable until [`elide_transport_http_free`].
pub fn elide_transport_http_send(driver: u64, exchange: u64, length: u64, flags: u32) -> i32 {
  let Ok(length) = usize::try_from(length) else {
    return INVALID;
  };
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    let Some(entry) = state.http.exchanges.get_mut(&exchange) else {
      return INVALID;
    };
    if entry.responded || entry.stream != 0 {
      return INVALID;
    }
    let socket = entry.socket;
    let Some(http) = state.http.sockets.get_mut(&socket) else {
      return INVALID;
    };
    // A rejected send leaves the prepared buffer with the exchange.
    let pending = entry.pending.get_mut();
    if pending.as_mut().is_none_or(|buffer| length > buffer.buf_capacity()) {
      return INVALID;
    }
    let Some(mut buffer) = pending.take() else {
      return INVALID;
    };
    entry.responded = true;
    // All foreign-accessible capacity was initialized by prepare.
    // SAFETY: prepare initialized all capacity, and length was checked against capacity above.
    unsafe { buffer.set_len(length) };
    let encoded = buffer.freeze();
    let close = !entry.exchange.keep_alive || flags & SEND_CLOSE != 0;
    let mut events = VecDeque::new();
    discard_body(http, socket, exchange, &mut events);
    http.queue(exchange, Parts::single(encoded));
    if close {
      http.closing = true;
    }
    pump(state, socket, &mut events);
    state.http.overflow.extend(events);
    0
  })
}

/// Abandon an exchange without responding; the connection closes after earlier responses.
/// The exchange memory stays readable until [`elide_transport_http_free`].
pub fn elide_transport_http_release(driver: u64, exchange: u64) -> i32 {
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    abandon(state, exchange, true)
  })
}

/// Mark an exchange answered without a response. A pending body ends with an error when
/// `report` is set; a free forfeits that event instead, since its handle is about to die.
fn abandon(state: &mut DriverState, exchange: u64, report: bool) -> i32 {
  if state
    .http
    .exchanges
    .get(&exchange)
    .is_some_and(|entry| entry.stream != 0)
  {
    return h2_socket::abandon(state, exchange, report);
  }
  let Some(entry) = state.http.exchanges.get_mut(&exchange) else {
    return INVALID;
  };
  if entry.responded {
    return INVALID;
  }
  entry.responded = true;
  let socket = entry.socket;
  let mut events = VecDeque::new();
  if let Some(http) = state.http.sockets.get_mut(&socket) {
    discard_body(http, socket, exchange, &mut events);
    http.order.retain(|id| *id != exchange);
    http.closing = true;
  }
  pump(state, socket, &mut events);
  if !report {
    events.retain(|e| !(e.kind == EVENT_BODY_END && e.value == exchange));
  }
  state.http.overflow.extend(events);
  0
}

/// Free an exchange once the JVM no longer reads it. An exchange that was never responded to or
/// released is abandoned first. Driver thread only; every request event must end here exactly once.
///
/// Freeing forfeits every undelivered event naming the exchange: a pending body end is dropped
/// and its remaining parts still go out but no longer report. A streaming exchange freed before
/// its final part is truncated and the connection closes after it.
pub fn elide_transport_http_free(driver: u64, exchange: u64) -> i32 {
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    let Some(entry) = state.http.exchanges.get(&exchange) else {
      return INVALID;
    };
    if entry.stream != 0 {
      return h2_socket::free(state, exchange);
    }
    let socket = entry.socket;
    if !entry.responded {
      abandon(state, exchange, false);
    }
    state.http.overflow.forget_exchange(exchange);
    // Freeing forfeits every undelivered event naming the exchange, not only control events:
    // EVENT_BODY names the exchange through its `value` and is not a control event, so
    // forget_exchange leaves it behind. Strip it before the retirement decision so a cached
    // address never carries a stale body event into a reused slot, and release each orphaned
    // segment once on the driver thread, exactly as the driver-shutdown path does (retire below).
    let stale_body_segments: Vec<u64> = state
      .http
      .overflow
      .iter()
      .filter(|event| event.kind == EVENT_BODY && event.value == exchange)
      .map(|event| event.operation)
      .collect();
    state
      .http
      .overflow
      .retain(|event| !(event.kind == EVENT_BODY && event.value == exchange));
    for segment in &stale_body_segments {
      state.http.segments.remove(segment);
    }
    if let Some(http) = state.http.sockets.get_mut(&socket) {
      let queued = if let Some(parts) = http.ready.get_mut(&exchange) {
        // Buffered parts never report, and queue ownership already proves quarantine is needed.
        if parts.streaming {
          for part in http.inflight.iter_mut().filter(|p| p.exchange == exchange) {
            part.report = false;
          }
          parts.streaming = false;
        }
        if !parts.complete {
          parts.complete = true;
          http.closing = true;
        }
        true
      } else {
        let mut inflight = false;
        for part in http.inflight.iter_mut().filter(|p| p.exchange == exchange) {
          part.report = false;
          inflight = true;
        }
        inflight
      };
      if queued {
        state.http.exchanges.retire(exchange, true);
        http.retired.insert(exchange, ());
      } else {
        state.http.exchanges.retire(exchange, false);
        http.outstanding -= 1;
      }
      let pending = http.pending_input.pop_front();
      let mut events = VecDeque::new();
      if let Some(pending) = pending {
        process_pending(state, socket, pending, &mut events);
      } else {
        pump(state, socket, &mut events);
      }
      state.http.overflow.extend(events);
    } else {
      state.http.exchanges.retire(exchange, false);
    }
    0
  })
}

/// Resume receiving on `socket` after its pinned capacity dropped.
fn resume_receiving(state: &mut DriverState, socket: u64) {
  if state
    .http
    .sockets
    .get(&socket)
    .is_some_and(|http| !http.closing && (http.h2.is_some() || http.pinned.get() < BODY_WINDOW_BYTES))
  {
    arm_receive(state, socket);
  }
}

/// Stop charging a body segment against its socket's receive window, keeping its bytes valid.
/// Driver thread only; idempotent, and implied by [`elide_transport_http_segment_release`].
///
/// The window bounds the transport's read-ahead: capacity pinned by bytes the driver has read but
/// the consumer has not taken. Once a consumer has handed a segment on — to a guest, or anywhere
/// its lifetime stops being the transport's concern — those bytes are application memory under the
/// consumer's own cap, so they must stop throttling the socket. Acking drops only that charge; the
/// segment's allocation, and therefore its address and contents, live until release, so nothing is
/// copied or moved. A segment the consumer is merely holding must not be acked, or the window
/// becomes a no-op. Returns INVALID for an unknown driver or segment.
pub fn elide_transport_http_segment_ack(driver: u64, segment: u64) -> i32 {
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    let Some(segment) = state.http.segments.get_mut(&segment) else {
      return INVALID;
    };
    let socket = segment.socket;
    // Dropping the charge un-pins the receive; the segment's bytes are untouched.
    let charge = segment.charge.take();
    if charge.is_none() {
      return 0;
    }
    let h2 = segment.h2;
    drop(charge);
    if let Some((stream, length)) = h2 {
      h2_socket::ack(state, socket, stream, length);
    }
    resume_receiving(state, socket);
    0
  })
}

/// Release a body segment delivered by an [`EVENT_BODY`] event: its bytes are invalid afterwards
/// and its allocation returns to the receive pool. Driver thread only; exactly once per event.
/// Releasing also acks, so an unacked segment's window charge drops here.
pub fn elide_transport_http_segment_release(driver: u64, segment: u64) -> i32 {
  DRIVERS.with(|drivers| {
    let mut drivers = drivers.borrow_mut();
    let Some(state) = drivers.0.get_mut(&driver) else {
      return INVALID;
    };
    let Some(segment) = state.http.segments.remove(&segment) else {
      return INVALID;
    };
    let socket = segment.socket;
    if segment.charge.is_some()
      && let Some((stream, length)) = segment.h2
    {
      h2_socket::ack(state, socket, stream, length);
    }
    drop(segment);
    resume_receiving(state, socket);
    0
  })
}

/// Copy a live exchange's head into a [`RetainedHead`] blob the caller owns; writes the blob's
/// length to `length`. Any thread, while the exchange is unfreed. Returns zero on failure.
///
/// # Safety
/// `length` must be writable; `exchange` must be a live handle.
pub unsafe fn elide_transport_http_retain(exchange: u64, length: *mut u64) -> u64 {
  if length.is_null() {
    return 0;
  }
  match with_exchange(exchange, RetainedHead::retain) {
    Some((address, total)) => {
      // SAFETY: The caller provides a non-null writable u64 slot for the retained length.
      unsafe { length.write(total as u64) };
      address
    }
    None => 0,
  }
}

/// Whether `socket` is in HTTP mode on `state`.
pub(super) fn is_http(state: &DriverState, socket: u64) -> bool {
  state.http.sockets.contains_key(&socket)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn retained_body_rejects_mutable_and_preserves_initialized_bounds_and_leases() {
    let owner = elide_transport_owner_new(128);
    let buffer = elide_transport_buffer_new(owner, 64);
    assert!(retained_body(buffer, 0).is_none());
    // SAFETY: buffer_new initializes the full allocation, and this handle is exclusively owned.
    assert_eq!(unsafe { elide_transport_buffer_freeze(buffer, 8) }, 0);
    assert!(retained_body(buffer, 9).is_none());
    let first = retained_body(buffer, 8).unwrap();
    let second = retained_body(buffer, 4).unwrap();
    assert_eq!(elide_transport_buffer_release(buffer), 0);
    assert!(retained_body(buffer, 8).is_none());
    assert_eq!(elide_transport_owner_used(owner), 64);
    drop(first);
    assert_eq!(elide_transport_owner_used(owner), 64);
    assert_eq!(second.as_ref(), &[0; 4]);
    drop(second);
    assert_eq!(elide_transport_owner_used(owner), 0);
    assert_eq!(elide_transport_owner_release(owner), 0);
  }

  #[test]
  fn single_response_does_not_allocate_a_part_queue() {
    let budget = Budget::new(1024);
    let mut bytes = Buffer::new(8, budget.clone()).unwrap();
    bytes.write(0, b"response").unwrap();
    let parts = Parts::single(bytes.freeze());
    assert_eq!(parts.queue.capacity(), 0);
    assert_eq!(parts.queued_bytes, 8);
    drop(parts);
    assert_eq!(budget.used(), 0);
  }

  #[test]
  fn response_parts_preserve_order_across_inline_spill_and_refill() {
    let budget = Budget::new(1024);
    let part = |value| {
      let mut bytes = Buffer::new(1, budget.clone()).unwrap();
      bytes.write(0, &[value]).unwrap();
      bytes.freeze()
    };
    let mut parts = Parts::single(part(1));
    parts.push_back(part(2));
    parts.push_back(part(3));
    assert_eq!(parts.len(), 3);
    assert_eq!(parts.pop_front().unwrap().as_ref(), &[1]);
    parts.push_back(part(4));
    for expected in [2, 3, 4] {
      assert_eq!(parts.pop_front().unwrap().as_ref(), &[expected]);
    }
    assert!(parts.is_empty());
    assert!(parts.pop_front().is_none());
    parts.push_back(part(5));
    assert_eq!(parts.len(), 1);
    assert_eq!(parts.pop_front().unwrap().as_ref(), &[5]);
    assert!(parts.is_empty());
    assert_eq!(budget.used(), 0);
  }

  #[test]
  #[cfg_attr(miri, ignore = "native driver is unavailable under miri")]
  fn freed_stream_suppresses_reports_until_all_wire_references_retire() {
    for queued in [false, true] {
      let owner = elide_transport_owner_new(1024 * 1024);
      let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 8);
      let socket = identity();
      let budget = budget(owner).unwrap();
      let request = || {
        let mut bytes = Buffer::new(64, budget.clone()).unwrap();
        bytes.write(0, b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let mut parser = HttpConnection::new(budget.clone());
        let mut out = VecDeque::new();
        parser.ingest(bytes, &mut out);
        let Some(Outcome::Request(exchange)) = out.pop_front() else {
          panic!("request expected")
        };
        exchange
      };
      let byte = || {
        let mut bytes = Buffer::new(1, budget.clone()).unwrap();
        bytes.write(0, b"x").unwrap();
        bytes.freeze()
      };
      let exchange = DRIVERS.with(|drivers| {
        let mut drivers = drivers.borrow_mut();
        let state = drivers.0.get_mut(&driver).unwrap();
        let exchange = state.http.exchanges.insert(socket, request(), budget.clone(), 0);
        state.http.exchanges.get_mut(&exchange).unwrap().responded = true;
        let mut http = HttpSocket::new(budget.clone(), 1024, None);
        // Keep the synthetic write lane unchanged while explicit completions exercise retirement.
        http.cork_depth = 1;
        http.outstanding = 1;
        for _ in 0..2 {
          http.inflight.push_back(Inflight {
            exchange,
            len: 1,
            remaining: 1,
            report: true,
          });
        }
        if queued {
          let mut parts = Parts::single(byte());
          parts.streaming = true;
          parts.complete = false;
          parts.queued_bytes += 2;
          http.queue(exchange, parts);
        }
        state.http.sockets.insert(socket, http);
        exchange
      });
      assert_eq!(elide_transport_http_free(driver, exchange), 0);
      assert_eq!(elide_transport_http_free(driver, exchange), INVALID);
      DRIVERS.with(|drivers| {
        let mut drivers = drivers.borrow_mut();
        let state = drivers.0.get_mut(&driver).unwrap();
        let mut events = VecDeque::new();
        on_plain_sent(state, socket, Ok(1), vec![byte(), byte()], &mut events);
        assert!(state.http.sockets[&socket].retired.contains_key(&exchange));
        let other = state.http.exchanges.insert(socket, request(), budget.clone(), 0);
        assert_ne!(other, exchange, "a partial completion must not recycle the address");
        on_plain_sent(state, socket, Ok(1), vec![byte()], &mut events);
        assert_eq!(state.http.sockets[&socket].retired.contains_key(&exchange), queued);
        assert!(events.iter().all(|event| event.kind != EVENT_PART_SENT));
        close_socket(state, socket, &mut events);
        assert!(events.iter().all(|event| event.kind != EVENT_PART_SENT));
        let reused = state.http.exchanges.insert(socket, request(), budget.clone(), 0);
        assert_eq!(reused, exchange, "last wire retirement permits address reuse");
      });
      assert_eq!(elide_transport_driver_release(driver), 0);
      assert_eq!(budget.used(), 0);
      assert_eq!(elide_transport_owner_release(owner), 0);
    }
  }

  #[test]
  fn exchange_slots_release_payloads_but_quarantine_wire_identities() {
    fn request(budget: &Budget) -> Exchange {
      let mut buffer = Buffer::new(128, budget.clone()).unwrap();
      buffer
        .write(0, b"GET /slot HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
      let mut parser = HttpConnection::new(budget.clone());
      let mut out = VecDeque::new();
      parser.ingest(buffer, &mut out);
      let Some(Outcome::Request(exchange)) = out.pop_front() else {
        panic!("request head expected")
      };
      exchange
    }
    let budget = Budget::new(1024 * 1024);
    let mut slots = ExchangeStore::default();
    let first = slots.insert(1, request(&budget), budget.clone(), 0);
    let spans = slots.get(&first).unwrap().layout.spans_ptr;
    let others: Vec<_> = (0..32)
      .map(|_| slots.insert(2, request(&budget), budget.clone(), 0))
      .collect();
    assert_eq!(
      // SAFETY: first is a live slot owned by slots; insertions preserve its allocation address.
      unsafe { &*(first as *const HttpExchange) }.exchange.path_bytes(),
      b"/slot"
    );
    for other in others {
      assert!(slots.retire(other, false));
    }
    // SAFETY: first remains a live exchange owned by slots on this thread.
    let prepared = unsafe { elide_transport_http_prepare(first, 8) };
    assert_ne!(prepared, 0);
    // SAFETY: prepare returned an allocation of at least eight bytes and it has not been retired.
    unsafe { (prepared as *mut u8).write_bytes(0, 8) };
    assert!(slots.retire(first, true));
    assert!(slots.get(&first).is_none());
    assert!(!slots.retire(first, false));
    assert_eq!(budget.used(), 0, "quarantine must not retain request bytes");
    let second = slots.insert(2, request(&budget), budget.clone(), 0);
    assert_ne!(first, second, "pending wire identity cannot be reused");
    slots.recycle(first);
    let reused = slots.insert(3, request(&budget), budget.clone(), 0);
    assert_eq!(first, reused);
    assert_eq!(slots.get(&reused).unwrap().layout.spans_ptr, spans);
    assert_eq!(slots.get(&reused).unwrap().socket, 3);
    assert!(slots.get(&u64::MAX).is_none());
    assert!(slots.retire(reused, false));
    assert_eq!(slots.insert(4, request(&budget), budget.clone(), 7), reused);
    assert_eq!(slots.get(&reused).unwrap().stream, 7);
    drop(slots);
    assert_eq!(budget.used(), 0, "owner drop releases every live payload");
  }

  #[test]
  #[cfg_attr(miri, ignore = "native driver is unavailable under miri")]
  fn unfinished_retry_round_cannot_sleep_or_retry_one_socket_twice() {
    let owner = elide_transport_owner_new(1024 * 1024);
    let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 4);
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      let mut sockets = Vec::new();
      for _ in 0..RETRY_BATCH + 1 {
        let socket = identity();
        let mut http = HttpSocket::new(budget(owner).unwrap(), 1024, None);
        // A corked pending vector keeps requeuing, like idle TLS registrations, without I/O.
        http.cork_depth = 1;
        let mut bytes = Buffer::new(1, http.budget.clone()).unwrap();
        bytes.write(0, b"x").unwrap();
        http.vector.push(bytes.freeze());
        state.http.sockets.insert(socket, http);
        state.http.queue_retry(socket);
        sockets.push(socket);
      }
      retry_deferred(state, &mut Vec::new());
      assert_eq!(state.http.retry_head, sockets[RETRY_BATCH]);
      assert!(needs_poll(state), "unvisited work must prevent a blocking poll");
      retry_deferred(state, &mut Vec::new());
      assert_eq!(state.http.retry_head, sockets[0]);
      assert!(
        !needs_poll(state),
        "a finished round must not busy-spin on registrations"
      );
      assert_eq!(state.http.retry_len, RETRY_BATCH + 1);
      retry_deferred(state, &mut Vec::new());
      assert_eq!(state.http.retry_remaining, 1);
      let fresh = identity();
      let mut http = HttpSocket::new(budget(owner).unwrap(), 1024, None);
      http.cork_depth = 1;
      let mut bytes = Buffer::new(1, http.budget.clone()).unwrap();
      bytes.write(0, b"x").unwrap();
      http.vector.push(bytes.freeze());
      state.http.sockets.insert(fresh, http);
      state.http.queue_retry(fresh);
      retry_deferred(state, &mut Vec::new());
      assert!(
        needs_poll(state),
        "fresh work behind visited registrations must not sleep"
      );
      assert_eq!(state.http.retry_remaining, 2);
      retry_deferred(state, &mut Vec::new());
      assert!(!needs_poll(state));
      // An already registered TLS socket can also acquire fresh output between polls.
      retry_deferred(state, &mut Vec::new());
      state.http.queue_retry(fresh);
      retry_deferred(state, &mut Vec::new());
      assert!(
        needs_poll(state),
        "fresh work on an existing registration extends the round"
      );
      retry_deferred(state, &mut Vec::new());
      assert!(!needs_poll(state));
      state.http.queue_retry(fresh);
      for socket in sockets {
        close_socket(state, socket, &mut VecDeque::new());
      }
      assert_eq!(state.http.retry_len, 1);
      retry_deferred(state, &mut Vec::new());
      assert_eq!(state.http.retry_remaining, 0, "retirement shrinks the unfinished round");
      assert!(!needs_poll(state));
      retire(state);
      assert_eq!(state.http.retry_len, 0);
    });
    assert_eq!(elide_transport_driver_release(driver), 0);
    assert_eq!(elide_transport_owner_release(owner), 0);
  }

  #[test]
  #[cfg_attr(miri, ignore = "native driver and real sockets are unavailable under miri")]
  fn retries_are_deduplicated_fair_and_retired_with_the_socket() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let owner = elide_transport_owner_new(4 * 1024 * 1024);
    let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 8);
    let mut peers = Vec::new();
    let mut sockets = Vec::new();
    for _ in 0..3 {
      let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
      peers.push(listener.accept().unwrap().0);
      let socket = identity();
      DRIVERS.with(|drivers| {
        let mut drivers = drivers.borrow_mut();
        let state = drivers.0.get_mut(&driver).unwrap();
        let connection = state.driver.attach(client.into()).unwrap();
        state.sockets.insert(socket, connection);
        state.workloads.insert(socket, Workload::admit(owner).unwrap());
      });
      assert_eq!(elide_transport_socket_http(owner, driver, socket, owner, 1024), 0);
      sockets.push(socket);
    }
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      assert_eq!(state.http.retry_len, 0, "idle plaintext sockets never enter retries");
      for &socket in &sockets {
        state.http.queue_retry(socket);
        state.http.queue_retry(socket);
      }
      assert_eq!(state.http.retry_len, 3);
      let first = state.http.retry_head;
      state.http.remove_retry(first);
      state.http.queue_retry(first);
      assert_eq!(state.http.retry_head, sockets[1], "retries rotate to the back");
      close_socket(state, sockets[2], &mut VecDeque::new());
      close_socket(state, sockets[1], &mut VecDeque::new());
      assert_eq!(state.http.retry_len, 1);
      assert_eq!(state.http.retry_head, first);
      assert_eq!(state.http.retry_tail, first);
      retry_deferred(state, &mut Vec::new());
      assert_eq!(state.http.retry_len, 0, "a resolved retry leaves no stale entry");
      state.http.queue_retry(first);
      close_socket(state, first, &mut VecDeque::new());
      state.http.queue_retry(first);
      assert_eq!(state.http.retry_len, 0, "a retired identity cannot reenter");
      assert_eq!(state.http.retry_head, 0);
      assert_eq!(state.http.retry_tail, 0);
    });
    drop(peers);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while elide_transport_driver_release(driver) == BUSY {
      assert!(std::time::Instant::now() < deadline);
      std::thread::yield_now();
    }
    assert_eq!(elide_transport_owner_used(owner), 0);
    assert_eq!(elide_transport_owner_release(owner), 0);
  }

  #[test]
  #[cfg_attr(miri, ignore = "native driver and real sockets are unavailable under miri")]
  fn coalesced_responses_preserve_the_part_limit() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let owner = elide_transport_owner_new(1024 * 1024);
    let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 16);
    let socket = identity();
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      let connection = state.driver.attach(client.into()).unwrap();
      state.sockets.insert(socket, connection);
      state.workloads.insert(socket, Workload::admit(owner).unwrap());
    });
    assert_eq!(elide_transport_socket_http(owner, driver, socket, owner, 16384), 0);
    let cork = Cork::enter(driver, socket).unwrap();
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      let http = state.http.sockets.get_mut(&socket).unwrap();
      for index in 0..(SEND_PARTS + 6) {
        let mut part = Buffer::response(16, &http.budget).unwrap();
        part.write(0, &[index as u8; 16]).unwrap();
        let exchange = identity();
        http.order.push_back(exchange);
        http.queue(exchange, Parts::single(part.freeze()));
      }
    });
    drop(cork);
    DRIVERS.with(|drivers| {
      let drivers = drivers.borrow();
      let http = &drivers.0[&driver].http.sockets[&socket];
      assert!(http.sending);
      assert_eq!(http.inflight.len(), SEND_PARTS);
      assert_eq!(http.order.len(), 6, "coalescing must not extend a send batch");
    });
    assert_eq!(elide_transport_socket_close(driver, socket), 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while elide_transport_driver_release(driver) == BUSY {
      assert!(std::time::Instant::now() < deadline);
      std::thread::yield_now();
    }
    assert_eq!(elide_transport_owner_used(owner), 0);
    assert_eq!(elide_transport_owner_release(owner), 0);
  }

  #[test]
  #[cfg_attr(miri, ignore = "native driver and real sockets are unavailable under miri")]
  fn cork_nests_flushes_at_capacity_and_tolerates_retirement() {
    for capacity_flush in [false, true] {
      let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
      let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
      let (_peer, _) = listener.accept().unwrap();
      let owner = elide_transport_owner_new(1024 * 1024);
      let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 16);
      let socket = identity();
      DRIVERS.with(|drivers| {
        let mut drivers = drivers.borrow_mut();
        let state = drivers.0.get_mut(&driver).unwrap();
        let connection = state.driver.attach(client.into()).unwrap();
        state.sockets.insert(socket, connection);
        state.workloads.insert(socket, Workload::admit(owner).unwrap());
      });
      assert_eq!(elide_transport_socket_http(owner, driver, socket, owner, 16384), 0);
      let outer = Cork::enter(driver, socket).unwrap();
      let inner = Cork::enter(driver, socket).unwrap();
      let queue = |size| {
        DRIVERS.with(|drivers| {
          let mut drivers = drivers.borrow_mut();
          let state = drivers.0.get_mut(&driver).unwrap();
          let http = state.http.sockets.get_mut(&socket).unwrap();
          let mut buffer = Buffer::new(size, http.budget.clone()).unwrap();
          buffer.write(0, &vec![b'x'; size]).unwrap();
          let exchange = identity();
          http.order.push_back(exchange);
          http.queue(exchange, Parts::single(buffer.freeze()));
          pump(state, socket, &mut VecDeque::new());
        })
      };
      let sending = || {
        DRIVERS.with(|drivers| {
          drivers
            .borrow()
            .0
            .get(&driver)
            .unwrap()
            .http
            .sockets
            .get(&socket)
            .unwrap()
            .sending
        })
      };
      queue(CORK_BYTES - 1);
      assert!(!sending());
      drop(inner);
      assert!(!sending(), "inner exit must not flush the outer scope");
      if capacity_flush {
        queue(1);
        assert!(sending(), "capacity must submit without waiting for scope exit");
      }
      drop(outer);
      assert!(sending(), "outer exit must submit below capacity too");
      let retiring = Cork::enter(driver, socket).unwrap();
      assert_eq!(elide_transport_socket_close(driver, socket), 0);
      drop(retiring);
      let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
      while elide_transport_driver_release(driver) == BUSY {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
      }
      assert_eq!(elide_transport_owner_used(owner), 0);
      assert_eq!(elide_transport_owner_release(owner), 0);
    }
  }

  #[test]
  #[cfg_attr(miri, ignore = "native driver and real sockets are unavailable under miri")]
  fn http_activation_cannot_overtake_an_undelivered_raw_completion() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let owner = elide_transport_owner_new(65536);
    let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 4);
    assert_ne!(driver, 0);
    let socket = identity();
    let operation = identity();
    let original = elide_transport_buffer_new(owner, 16);
    let Storage::Mutable(mut storage) = lock(registry(original)).remove(&original).unwrap() else {
      panic!("mutable raw receive storage");
    };
    storage.write(0, b"raw").unwrap();
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      let connection = state.driver.attach(client.into()).unwrap();
      state.sockets.insert(socket, connection);
      state.workloads.insert(socket, Workload::admit(owner).unwrap());
      state.operations.insert(operation, Operation::raw(socket, original));
      // Native completion has cleared the read lane, but the ABI has not delivered the event.
      state.driver.defer_completed(vec![crate::driver::Event::Received {
        id: operation,
        result: Ok(3),
        buffer: storage,
      }]);
    });
    assert_eq!(
      elide_transport_socket_http(owner, driver, socket, owner, 16 * 1024),
      INVALID
    );
    let batch = elide_transport_buffer_new(owner, size_of::<NativeEvent>() as u64);
    // SAFETY: batch owns space for one event and driver is live on this thread.
    assert_eq!(unsafe { elide_transport_driver_poll(driver, 0, batch, 1) }, 1);
    let mut view = BufferView::default();
    // SAFETY: view is an aligned writable output and batch remains live.
    assert_eq!(unsafe { elide_transport_buffer_view(batch, &mut view) }, 0);
    // SAFETY: poll initialized one event in the live, allocator-aligned batch.
    let event = unsafe { &*view.address.cast::<NativeEvent>() };
    assert_eq!((event.kind, event.value, event.result), (3, original, 3));
    // SAFETY: view is an aligned writable output and original has not been released.
    assert_eq!(unsafe { elide_transport_buffer_view(original, &mut view) }, 0);
    assert_eq!(
      // SAFETY: The completed receive initialized three bytes in original, which remains live.
      unsafe { std::slice::from_raw_parts(view.address.cast::<u8>(), 3) },
      b"raw"
    );
    assert_eq!(elide_transport_socket_close(driver, socket), 0);
    assert_eq!(elide_transport_driver_release(driver), 0);
    assert_eq!(elide_transport_buffer_release(original), 0);
    assert_eq!(elide_transport_buffer_release(batch), 0);
    assert_eq!(elide_transport_owner_release(owner), 0);
  }

  #[test]
  #[cfg_attr(miri, ignore = "native driver is unavailable under miri")]
  fn free_mid_body_fails_to_clear_stale_event_body_before_id_reuse() {
    let owner = elide_transport_owner_new(1024 * 1024);
    let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 8);
    let socket = identity();
    let budget = budget(owner).unwrap();
    let head_and_partial = b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n12345";
    // Step 1: feed the request head plus a partial body; both events go to overflow.
    let (exchange, stale_segment) = {
      let mut events = VecDeque::new();
      DRIVERS.with(|drivers| {
        let mut drivers = drivers.borrow_mut();
        let state = drivers.0.get_mut(&driver).unwrap();
        let http = HttpSocket::new(budget.clone(), 1024, None);
        state.http.sockets.insert(socket, http);
        let mut buf = Buffer::new(head_and_partial.len(), budget.clone()).unwrap();
        buf.write(0, head_and_partial).unwrap();
        process_input(state, socket, buf.freeze(), &mut events);
        state.http.overflow.extend(events.drain(..));
      });
      DRIVERS.with(|drivers| {
        let drivers = drivers.borrow();
        let state = drivers.0.get(&driver).unwrap();
        let request = state
          .http
          .overflow
          .iter()
          .find(|e| e.kind == EVENT_REQUEST)
          .expect("EVENT_REQUEST emitted");
        let body = state
          .http
          .overflow
          .iter()
          .find(|e| e.kind == EVENT_BODY)
          .expect("EVENT_BODY emitted for the partial body");
        (request.value, body.operation)
      })
    };
    // Step 2: free the exchange while the body is mid-stream.
    assert_eq!(elide_transport_http_free(driver, exchange), 0);
    // Step 3: the stale EVENT_BODY naming the freed exchange must be forfeited from overflow, and
    // its orphaned segment released once on the driver thread (the guest never received the event).
    let stale_body_remains = DRIVERS.with(|drivers| {
      let drivers = drivers.borrow();
      let state = drivers.0.get(&driver).unwrap();
      state
        .http
        .overflow
        .iter()
        .any(|e| e.kind == EVENT_BODY && e.value == exchange && e.operation == stale_segment)
    });
    assert!(
      !stale_body_remains,
      "freeing must forfeit every undelivered EVENT_BODY naming the exchange, not only controls"
    );
    let segment_released = DRIVERS.with(|drivers| {
      let drivers = drivers.borrow();
      let state = drivers.0.get(&driver).unwrap();
      !state.http.segments.contains_key(&stale_segment)
    });
    assert!(
      segment_released,
      "the orphaned body segment must be released on the driver thread, not leaked"
    );
    // Step 4: feed a GET on a fresh socket; insert may reuse the cached address.
    let socket2 = identity();
    let mut events = VecDeque::new();
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      let http = HttpSocket::new(budget.clone(), 1024, None);
      state.http.sockets.insert(socket2, http);
      let mut buf = Buffer::new(b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n".len(), budget.clone()).unwrap();
      buf.write(0, b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
      process_input(state, socket2, buf.freeze(), &mut events);
      state.http.overflow.extend(events.drain(..));
    });
    let reused = DRIVERS.with(|drivers| {
      let drivers = drivers.borrow();
      let state = drivers.0.get(&driver).unwrap();
      state
        .http
        .overflow
        .iter()
        .find(|e| e.kind == EVENT_REQUEST && e.value != 0)
        .map(|e| e.value)
        .expect("a new EVENT_REQUEST")
    });
    let collided = reused == exchange && stale_body_remains;
    // cleanup
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      let mut ev = VecDeque::new();
      close_socket(state, socket2, &mut ev);
      state.http.overflow.extend(ev);
    });
    assert_eq!(elide_transport_driver_release(driver), 0);
    assert_eq!(elide_transport_owner_release(owner), 0);
    assert!(
      !collided,
      "stale EVENT_BODY(segment={:#x}, exchange={:#x}) coexists with a new EVENT_REQUEST reusing {:#x}: \
       forget_exchange leaves EVENT_BODY behind and retire(false) caches the id",
      stale_segment, exchange, exchange
    );
  }

  /// The already-responded free path (`abandon` not taken) must still strip a stale `EVENT_BODY`
  /// naming the freed exchange and release its segment before retirement.
  #[test]
  #[cfg_attr(miri, ignore = "native driver is unavailable under miri")]
  fn free_after_response_strips_stale_event_body_and_releases_segment() {
    let owner = elide_transport_owner_new(1024 * 1024);
    let driver = elide_transport_driver_new(owner, Backend::Auto as u32, 8);
    let socket = identity();
    let budget = budget(owner).unwrap();
    let head_and_partial = b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n12345";
    let (exchange, stale_segment) = {
      let mut events = VecDeque::new();
      DRIVERS.with(|drivers| {
        let mut drivers = drivers.borrow_mut();
        let state = drivers.0.get_mut(&driver).unwrap();
        let http = HttpSocket::new(budget.clone(), 1024, None);
        state.http.sockets.insert(socket, http);
        let mut buf = Buffer::new(head_and_partial.len(), budget.clone()).unwrap();
        buf.write(0, head_and_partial).unwrap();
        process_input(state, socket, buf.freeze(), &mut events);
        state.http.overflow.extend(events.drain(..));
      });
      DRIVERS.with(|drivers| {
        let drivers = drivers.borrow();
        let state = drivers.0.get(&driver).unwrap();
        let request = state
          .http
          .overflow
          .iter()
          .find(|e| e.kind == EVENT_REQUEST)
          .expect("EVENT_REQUEST emitted");
        let body = state
          .http
          .overflow
          .iter()
          .find(|e| e.kind == EVENT_BODY)
          .expect("EVENT_BODY emitted for the partial body");
        (request.value, body.operation)
      })
    };
    // Mark the exchange as already responded (the `else` branch in free: abandon is not taken),
    // while a body segment remains undelivered in overflow.
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      state.http.exchanges.get_mut(&exchange).unwrap().responded = true;
    });
    assert_eq!(elide_transport_http_free(driver, exchange), 0);
    let stale_body_remains = DRIVERS.with(|drivers| {
      let drivers = drivers.borrow();
      let state = drivers.0.get(&driver).unwrap();
      state
        .http
        .overflow
        .iter()
        .any(|e| e.kind == EVENT_BODY && e.value == exchange)
    });
    assert!(
      !stale_body_remains,
      "already-responded free must still forfeit undelivered EVENT_BODY naming the exchange"
    );
    let segment_released = DRIVERS.with(|drivers| {
      let drivers = drivers.borrow();
      let state = drivers.0.get(&driver).unwrap();
      !state.http.segments.contains_key(&stale_segment)
    });
    assert!(
      segment_released,
      "already-responded free must release the orphaned segment on the driver thread"
    );
    let mut ev = VecDeque::new();
    DRIVERS.with(|drivers| {
      let mut drivers = drivers.borrow_mut();
      let state = drivers.0.get_mut(&driver).unwrap();
      close_socket(state, socket, &mut ev);
      state.http.overflow.extend(ev);
    });
    assert_eq!(elide_transport_driver_release(driver), 0);
    assert_eq!(elide_transport_owner_release(owner), 0);
  }
}
