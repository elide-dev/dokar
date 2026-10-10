/*
 * Copyright (c) 2024-2026 Elide Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

//! `SSLEngine`-shaped Rustls records over caller-owned buffers. The engine performs no socket I/O;
//! each wrap or unwrap moves bytes between the caller's source and destination and reports
//! `SSLEngineResult` semantics.

use std::io;
use std::sync::Arc;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, EncodeTlsData, EncryptError, UnbufferedStatus, WriteTraffic};

mod storage;

use crate::buffer::Budget;
use storage::Storage;

const HEADER: usize = 5;
const MAX_FRAGMENT: usize = 16 * 1024;
/// Largest TLS 1.2 ciphertext record (RFC 5246 §6.2.3), which also bounds TLS 1.3 records.
pub const MAX_RECORD: usize = HEADER + MAX_FRAGMENT + 2048;
const MAX_RETAINED: usize = 1024 * 1024;
const MAX_TRANSITIONS: usize = 256;

/// `SSLEngineResult.Status` ordinals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Status {
  /// A complete record is not yet available.
  BufferUnderflow = 0,
  /// The destination cannot hold the result; retry with more space.
  BufferOverflow = 1,
  /// Progress was made.
  Ok = 2,
  /// This direction is closed.
  Closed = 3,
}

/// `SSLEngineResult.HandshakeStatus` ordinals; delegated tasks are never produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Handshake {
  /// No handshake is in progress.
  NotHandshaking = 0,
  /// This operation completed the handshake; reported exactly once.
  Finished = 1,
  /// Encoded records are pending and require a wrap.
  NeedWrap = 3,
  /// The handshake requires peer records.
  NeedUnwrap = 4,
}

/// Result of one wrap or unwrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
  /// Operation status.
  pub status: Status,
  /// Handshake status after the operation.
  pub handshake: Handshake,
  /// Source bytes consumed.
  pub consumed: usize,
  /// Destination bytes written.
  pub produced: usize,
}

/// Unwrap input. Mutable input is decrypted in place when the engine retains no earlier bytes;
/// consumed bytes are therefore undefined after the call.
pub enum Input<'a> {
  /// Caller-exclusive writable storage.
  Mutable(&'a mut [u8]),
  /// Storage the engine must not modify; records are staged into engine storage.
  Shared(&'a [u8]),
}

impl Input<'_> {
  fn bytes(&self) -> &[u8] {
    match self {
      Input::Mutable(bytes) => bytes,
      Input::Shared(bytes) => bytes,
    }
  }
}

enum Inner {
  Client(UnbufferedClientConnection),
  Server(UnbufferedServerConnection),
}

/// Destination of one operation. Wrapping encrypts `source` into `out`; unwrapping delivers
/// decrypted records into `out`.
struct Sink<'a> {
  out: &'a mut [u8],
  produced: usize,
  source: &'a [u8],
  consumed: usize,
  wrapping: bool,
}

impl Sink<'_> {
  fn room(&self) -> usize {
    self.out.len() - self.produced
  }
}

/// Engine bookkeeping outside the Rustls connection, so transitions can borrow both.
struct Pending {
  /// Encoded records awaiting a wrap, from `flushed` onward.
  output: Storage,
  flushed: usize,
  /// Decrypted bytes that did not fit the caller's destination, from `delivered` onward.
  plaintext: Storage,
  delivered: usize,
  close_requested: bool,
  close_queued: bool,
  peer_closed: bool,
}

impl Pending {
  fn new(budget: Budget) -> Self {
    Self {
      output: Storage::new(budget.clone()),
      plaintext: Storage::new(budget),
      flushed: 0,
      delivered: 0,
      close_requested: false,
      close_queued: false,
      peer_closed: false,
    }
  }

  fn output_pending(&self) -> bool {
    self.flushed < self.output.len()
  }

  fn plaintext_pending(&self) -> bool {
    self.delivered < self.plaintext.len()
  }

  fn flush(&mut self, sink: &mut Sink<'_>) {
    let count = (self.output.len() - self.flushed).min(sink.room());
    sink.out[sink.produced..sink.produced + count].copy_from_slice(&self.output[self.flushed..self.flushed + count]);
    sink.produced += count;
    self.flushed += count;
    if self.flushed == self.output.len() {
      self.output.clear();
      self.flushed = 0;
    }
  }

  fn drain_plaintext(&mut self, sink: &mut Sink<'_>) {
    let count = (self.plaintext.len() - self.delivered).min(sink.room());
    sink.out[sink.produced..sink.produced + count]
      .copy_from_slice(&self.plaintext[self.delivered..self.delivered + count]);
    sink.produced += count;
    self.delivered += count;
    if self.delivered == self.plaintext.len() {
      self.plaintext.clear();
      self.delivered = 0;
    }
  }

  fn encode<Data>(&mut self, encode: &mut EncodeTlsData<'_, Data>) -> io::Result<()> {
    let size = match encode.encode(&mut []) {
      Err(EncodeError::InsufficientSize(size)) => size.required_size,
      Err(error) => return Err(tls_error(error)),
      Ok(_) => return Ok(()),
    };
    if self.output.len() - self.flushed + size > MAX_RETAINED {
      return Err(io::Error::new(io::ErrorKind::OutOfMemory, "TLS output limit exceeded"));
    }
    self.output.consume(self.flushed);
    self.flushed = 0;
    let start = self.output.len();
    self.output.resize(start + size)?;
    let length = encode.encode(&mut self.output[start..]).map_err(tls_error)?;
    self.output.truncate(start + length);
    Ok(())
  }

  /// Rustls 0.23.43 retains decrypted records internally; this is the plaintext staging copy.
  fn deliver(&mut self, payload: &[u8], sink: &mut Sink<'_>) -> io::Result<()> {
    let direct = if sink.wrapping || self.plaintext_pending() {
      0
    } else {
      payload.len().min(sink.room())
    };
    sink.out[sink.produced..sink.produced + direct].copy_from_slice(&payload[..direct]);
    sink.produced += direct;
    let rest = &payload[direct..];
    if !rest.is_empty() {
      if self.plaintext.len() - self.delivered + rest.len() > MAX_RETAINED {
        return Err(io::Error::new(
          io::ErrorKind::OutOfMemory,
          "TLS plaintext limit exceeded",
        ));
      }
      self.plaintext.consume(self.delivered);
      self.delivered = 0;
      self.plaintext.extend_from_slice(rest)?;
    }
    Ok(())
  }

  /// Encrypt application data or close-notify directly into the destination, after any records
  /// that were encoded first.
  fn write<Data>(&mut self, traffic: &mut WriteTraffic<'_, Data>, sink: &mut Sink<'_>) -> io::Result<()> {
    if !sink.wrapping {
      return Ok(());
    }
    self.flush(sink);
    if self.output_pending() {
      return Ok(());
    }
    if self.close_requested {
      if !self.close_queued {
        self.close_queued = true;
        match traffic.queue_close_notify(&mut sink.out[sink.produced..]) {
          Ok(length) => sink.produced += length,
          // The alert stays queued inside Rustls and is encoded by the next transition.
          Err(EncryptError::InsufficientSize(_)) => {}
          Err(error) => return Err(tls_error(error)),
        }
      }
      return Ok(());
    }
    while sink.consumed < sink.source.len() {
      let chunk = &sink.source[sink.consumed..];
      let chunk = &chunk[..chunk.len().min(MAX_FRAGMENT)];
      match traffic.encrypt(chunk, &mut sink.out[sink.produced..]) {
        Ok(length) => {
          sink.produced += length;
          sink.consumed += chunk.len();
        }
        // A size probe encrypts nothing; a queued key update is encoded by the next transition.
        Err(EncryptError::InsufficientSize(_)) => break,
        Err(error) => return Err(tls_error(error)),
      }
    }
    Ok(())
  }
}

/// Apply one Rustls transition; returns bytes to discard and whether the connection is blocked.
fn transition<Data>(
  status: UnbufferedStatus<'_, '_, Data>,
  pending: &mut Pending,
  sink: &mut Sink<'_>,
) -> Result<(usize, bool), (rustls::Error, usize)> {
  let mut discard = status.discard;
  let io = |error: io::Error| rustls::Error::General(error.to_string());
  let result = (|| {
    let blocked = match status.state? {
      ConnectionState::EncodeTlsData(mut encode) => {
        pending.encode(&mut encode).map_err(io)?;
        false
      }
      ConnectionState::TransmitTlsData(transmit) => {
        // Encoded records belong to the engine until a wrap hands them to the caller.
        transmit.done();
        false
      }
      ConnectionState::ReadTraffic(mut traffic) => {
        while let Some(record) = traffic.next_record() {
          let record = record?;
          discard += record.discard;
          pending.deliver(record.payload, sink).map_err(io)?;
        }
        false
      }
      ConnectionState::WriteTraffic(mut traffic) => {
        let queue = pending.close_requested && !pending.close_queued;
        pending.write(&mut traffic, sink).map_err(io)?;
        // A newly queued close-notify may need encoding through the next transition.
        !(queue && pending.close_queued)
      }
      ConnectionState::PeerClosed => {
        pending.peer_closed = true;
        false
      }
      ConnectionState::Closed => {
        pending.peer_closed = true;
        true
      }
      ConnectionState::BlockedHandshake => true,
      _ => return Err(rustls::Error::General("unsupported TLS state".into())),
    };
    Ok(blocked)
  })();
  result
    .map(|blocked| (discard, blocked))
    .map_err(|error| (error, discard))
}

/// Encode the queued fatal alert without re-entering the failed deframer. A terminal engine
/// never resumes Rustls, so it does not need a subsequent TransmitTlsData acknowledgement.
fn alert<Data>(status: UnbufferedStatus<'_, '_, Data>, pending: &mut Pending) {
  if let Ok(ConnectionState::EncodeTlsData(mut encode)) = status.state {
    let _ = pending.encode(&mut encode);
  }
}

/// A Rustls connection driven with `SSLEngine` semantics. Not thread-safe; callers serialize.
pub struct Engine {
  inner: Inner,
  pending: Pending,
  /// Ciphertext Rustls has not discarded (partial handshake messages), kept in its processed form.
  input: Storage,
  started: bool,
  finished: bool,
  inbound_closed: bool,
  failure: Option<String>,
}

impl Engine {
  /// Create a verified client engine for `name`.
  ///
  /// # Errors
  /// Rejects early-data configuration and invalid Rustls settings.
  pub fn client(config: Arc<rustls::ClientConfig>, name: ServerName<'static>) -> io::Result<Self> {
    Self::client_with_budget(config, name, Budget::new(usize::MAX))
  }

  pub(crate) fn client_with_budget(
    config: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
    budget: Budget,
  ) -> io::Result<Self> {
    if config.enable_early_data {
      return Err(io::ErrorKind::Unsupported.into());
    }
    let connection = UnbufferedClientConnection::new(config, name).map_err(tls_error)?;
    Ok(Self::new(Inner::Client(connection), budget))
  }

  /// Create a server engine.
  ///
  /// # Errors
  /// Rejects early data and invalid Rustls settings.
  pub fn server(config: Arc<rustls::ServerConfig>) -> io::Result<Self> {
    Self::server_with_budget(config, Budget::new(usize::MAX))
  }

  pub(crate) fn server_with_budget(config: Arc<rustls::ServerConfig>, budget: Budget) -> io::Result<Self> {
    if config.max_early_data_size != 0 {
      return Err(io::ErrorKind::Unsupported.into());
    }
    let connection = UnbufferedServerConnection::new(config).map_err(tls_error)?;
    Ok(Self::new(Inner::Server(connection), budget))
  }

  fn new(inner: Inner, budget: Budget) -> Self {
    Self {
      inner,
      pending: Pending::new(budget.clone()),
      input: Storage::new(budget),
      started: false,
      finished: false,
      inbound_closed: false,
      failure: None,
    }
  }

  /// Whether this engine is a client.
  pub fn is_client(&self) -> bool {
    matches!(self.inner, Inner::Client(_))
  }

  /// Start the handshake, encoding any initial flight for the next wrap.
  ///
  /// # Errors
  /// Returns the Rustls failure; the engine then only emits queued alerts and reports closure.
  pub fn begin(&mut self) -> io::Result<()> {
    self.started = true;
    if self.failure.is_some() {
      return Ok(());
    }
    let mut sink = Sink {
      out: &mut [],
      produced: 0,
      source: &[],
      consumed: 0,
      wrapping: false,
    };
    let mut input = self.input.take();
    let result = self.pump(&mut input, &mut sink);
    self.retain(input, result.as_ref().copied().unwrap_or(0));
    result.map(|_| ())
  }

  /// Whether peer authentication is still in progress.
  pub fn is_handshaking(&self) -> bool {
    match &self.inner {
      Inner::Client(c) => c.is_handshaking(),
      Inner::Server(c) => c.is_handshaking(),
    }
  }

  /// Encrypt `source` into `destination`, first emitting any encoded handshake or alert records.
  ///
  /// # Errors
  /// Returns the Rustls failure; the engine then only emits queued alerts and reports closure.
  pub fn wrap(&mut self, source: &[u8], destination: &mut [u8]) -> io::Result<Outcome> {
    self.started = true;
    let mut sink = Sink {
      out: destination,
      produced: 0,
      source,
      consumed: 0,
      wrapping: true,
    };
    self.pending.flush(&mut sink);
    if self.failure.is_none() && !self.pending.output_pending() && !self.pending.close_queued {
      let mut input = self.input.take();
      let result = self.pump(&mut input, &mut sink);
      self.retain(input, result.as_ref().copied().unwrap_or(0));
      result?;
      self.pending.flush(&mut sink);
    }
    let status = if self.outbound_done() {
      Status::Closed
    } else if sink.produced == 0 && (self.pending.output_pending() || sink.consumed < sink.source.len()) {
      Status::BufferOverflow
    } else {
      Status::Ok
    };
    Ok(self.outcome(status, sink.consumed, sink.produced))
  }

  /// Process at most one complete record from `source`, delivering plaintext to `destination`.
  ///
  /// # Errors
  /// Returns malformed-record and Rustls failures; the engine then reports inbound closure.
  pub fn unwrap(&mut self, mut source: Input<'_>, destination: &mut [u8]) -> io::Result<Outcome> {
    self.started = true;
    let mut sink = Sink {
      out: destination,
      produced: 0,
      source: &[],
      consumed: 0,
      wrapping: false,
    };
    self.pending.drain_plaintext(&mut sink);
    if self.pending.plaintext_pending() {
      return Ok(self.outcome(Status::BufferOverflow, 0, sink.produced));
    }
    if self.inbound_closed || self.failure.is_some() {
      return Ok(self.outcome(Status::Closed, 0, sink.produced));
    }
    let bytes = source.bytes();
    // Plaintext drained from an earlier overflow satisfies a call that brings no complete record.
    let starved = if sink.produced > 0 {
      Status::Ok
    } else {
      Status::BufferUnderflow
    };
    if bytes.len() < HEADER {
      return Ok(self.outcome(starved, 0, sink.produced));
    }
    if !(20..=24).contains(&bytes[0]) {
      return Err(self.terminate("not an SSL/TLS record".into()));
    }
    let length = HEADER + u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if length > MAX_RECORD {
      return Err(self.terminate("TLS record overflow".into()));
    }
    if bytes.len() < length {
      return Ok(self.outcome(starved, 0, sink.produced));
    }
    if bytes[0] == 23 && sink.room() < (length - HEADER).min(MAX_FRAGMENT) {
      return Ok(self.outcome(Status::BufferOverflow, 0, sink.produced));
    }
    match &mut source {
      Input::Mutable(bytes) if self.input.is_empty() => {
        let record = &mut bytes[..length];
        let discarded = self.pump(record, &mut sink)?;
        if let Err(error) = self.input.extend_from_slice(&record[discarded..]) {
          return Err(self.terminate(error.to_string()));
        }
      }
      _ => {
        if self.input.len() + length > MAX_RETAINED {
          return Err(self.terminate("TLS input limit exceeded".into()));
        }
        let mut input = self.input.take();
        if let Err(error) = input.extend_from_slice(&source.bytes()[..length]) {
          self.input = input;
          return Err(self.terminate(error.to_string()));
        }
        let result = self.pump(&mut input, &mut sink);
        self.retain(input, result.as_ref().copied().unwrap_or(0));
        result?;
      }
    }
    if self.pending.peer_closed {
      self.inbound_closed = true;
    }
    let status = if self.pending.plaintext_pending() {
      Status::BufferOverflow
    } else if self.inbound_closed {
      Status::Closed
    } else {
      Status::Ok
    };
    Ok(self.outcome(status, length, sink.produced))
  }

  fn retain(&mut self, mut input: Storage, discarded: usize) {
    input.consume(discarded);
    self.input = input;
  }

  /// Advance until the connection blocks; returns the bytes Rustls discarded from `buffer`.
  fn pump(&mut self, buffer: &mut [u8], sink: &mut Sink<'_>) -> io::Result<usize> {
    let mut start = 0;
    for _ in 0..MAX_TRANSITIONS {
      let result = match &mut self.inner {
        Inner::Client(c) => transition(c.process_tls_records(&mut buffer[start..]), &mut self.pending, sink),
        Inner::Server(c) => transition(c.process_tls_records(&mut buffer[start..]), &mut self.pending, sink),
      };
      match result {
        Ok((discard, blocked)) => {
          start += discard;
          if blocked {
            return Ok(start);
          }
        }
        Err((error, discard)) => return Err(self.fail(error, &mut buffer[start + discard..])),
      }
    }
    Err(self.terminate("TLS state machine did not settle".into()))
  }

  /// Record a terminal failure and collect any alert Rustls queued for the peer. Rustls must see
  /// the same buffer it failed on, since its deframer may still reference retained ranges.
  fn fail(&mut self, error: rustls::Error, buffer: &mut [u8]) -> io::Error {
    match &mut self.inner {
      Inner::Client(c) => alert(c.process_tls_records(buffer), &mut self.pending),
      Inner::Server(c) => alert(c.process_tls_records(buffer), &mut self.pending),
    }
    self.terminate(error.to_string())
  }

  fn terminate(&mut self, message: String) -> io::Error {
    self.inbound_closed = true;
    let error = io::Error::new(io::ErrorKind::InvalidData, message.clone());
    self.failure = Some(message);
    error
  }

  fn outcome(&mut self, status: Status, consumed: usize, produced: usize) -> Outcome {
    let mut handshake = self.handshake_status();
    if handshake == Handshake::NotHandshaking
      && self.started
      && !self.finished
      && self.failure.is_none()
      && !self.is_handshaking()
    {
      self.finished = true;
      handshake = Handshake::Finished;
    }
    Outcome {
      status,
      handshake,
      consumed,
      produced,
    }
  }

  /// Current handshake status; never `Finished`.
  pub fn handshake_status(&self) -> Handshake {
    if !self.started || self.outbound_done() && (self.failure.is_some() || self.is_handshaking()) {
      Handshake::NotHandshaking
    } else if self.pending.output_pending()
      || self.pending.close_requested && !self.pending.close_queued && !self.is_handshaking()
    {
      Handshake::NeedWrap
    } else if self.is_handshaking() {
      Handshake::NeedUnwrap
    } else {
      Handshake::NotHandshaking
    }
  }

  /// Queue close-notify for the next wrap.
  pub fn close_outbound(&mut self) {
    self.started = true;
    self.pending.close_requested = true;
  }

  /// Stop accepting records; returns whether the peer's close-notify is missing after the handshake
  /// began, which callers report as possible truncation.
  pub fn close_inbound(&mut self) -> bool {
    let truncated = self.started && !self.pending.peer_closed && self.failure.is_none();
    self.inbound_closed = true;
    self.pending.plaintext.clear();
    self.pending.delivered = 0;
    truncated
  }

  /// Whether no more records will be accepted.
  pub fn inbound_done(&self) -> bool {
    self.inbound_closed && !self.pending.plaintext_pending()
  }

  /// Whether close-notify (or a failure alert) has been fully handed to the caller.
  pub fn outbound_done(&self) -> bool {
    (self.pending.close_queued || self.failure.is_some()) && !self.pending.output_pending()
  }

  /// Negotiated ALPN identifier.
  pub fn alpn_protocol(&self) -> Option<&[u8]> {
    match &self.inner {
      Inner::Client(c) => c.alpn_protocol(),
      Inner::Server(c) => c.alpn_protocol(),
    }
  }

  /// Negotiated protocol version as its IANA code.
  pub fn protocol_version(&self) -> Option<u16> {
    match &self.inner {
      Inner::Client(c) => c.protocol_version(),
      Inner::Server(c) => c.protocol_version(),
    }
    .map(u16::from)
  }

  /// Negotiated cipher suite as its IANA code.
  pub fn cipher_suite(&self) -> Option<u16> {
    match &self.inner {
      Inner::Client(c) => c.negotiated_cipher_suite(),
      Inner::Server(c) => c.negotiated_cipher_suite(),
    }
    .map(|suite| u16::from(suite.suite()))
  }

  /// Authenticated peer chain, leaf first.
  pub fn peer_certificates(&self) -> &[CertificateDer<'static>] {
    match &self.inner {
      Inner::Client(c) => c.peer_certificates(),
      Inner::Server(c) => c.peer_certificates(),
    }
    .unwrap_or_default()
  }

  /// Terminal failure description, if any.
  pub fn failure(&self) -> Option<&str> {
    self.failure.as_deref()
  }
}

fn tls_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
  use super::*;
  use rustls::pki_types::{PrivateKeyDer, pem::PemObject};

  fn configs(
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
  ) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let cert = CertificateDer::from_pem_slice(include_bytes!("../../tests/fixtures/localhost-cert.pem")).unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../tests/fixtures/localhost-key.pem")).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
      .with_protocol_versions(versions)
      .unwrap()
      .with_root_certificates(roots)
      .with_no_client_auth();
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
      .with_protocol_versions(versions)
      .unwrap()
      .with_no_client_auth()
      .with_single_cert(vec![cert], key)
      .unwrap();
    client.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    server.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    (Arc::new(client), Arc::new(server))
  }

  fn pair(versions: &[&'static rustls::SupportedProtocolVersion], name: &str) -> (Engine, Engine) {
    let (client, server) = configs(versions, &[b"h2", b"http/1.1"]);
    let client = Engine::client(client, ServerName::try_from(name.to_owned()).unwrap()).unwrap();
    (client, Engine::server(server).unwrap())
  }

  /// Deliver `wire` one record at a time, as `SslHandler` does, returning produced plaintext.
  fn feed(engine: &mut Engine, wire: &mut Vec<u8>, plaintext: &mut Vec<u8>) -> io::Result<()> {
    feed_states(engine, wire, plaintext, &mut Vec::new())
  }

  fn feed_states(
    engine: &mut Engine,
    wire: &mut Vec<u8>,
    plaintext: &mut Vec<u8>,
    states: &mut Vec<Handshake>,
  ) -> io::Result<()> {
    loop {
      let mut out = vec![0; MAX_RECORD];
      let mut record = wire.clone();
      let outcome = engine.unwrap(Input::Mutable(&mut record), &mut out)?;
      states.push(outcome.handshake);
      wire.drain(..outcome.consumed);
      plaintext.extend_from_slice(&out[..outcome.produced]);
      if outcome.status == Status::BufferUnderflow || outcome.consumed == 0 && outcome.produced == 0 {
        return Ok(());
      }
    }
  }

  fn drain(engine: &mut Engine, source: &[u8], wire: &mut Vec<u8>) -> io::Result<usize> {
    let mut consumed = 0;
    loop {
      let mut out = vec![0; MAX_RECORD];
      let outcome = engine.wrap(&source[consumed..], &mut out)?;
      consumed += outcome.consumed;
      wire.extend_from_slice(&out[..outcome.produced]);
      if outcome.produced == 0 || outcome.status == Status::Closed {
        return Ok(consumed);
      }
    }
  }

  fn handshake(client: &mut Engine, server: &mut Engine) -> (Vec<Handshake>, Vec<Handshake>) {
    let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
    let (mut client_states, mut server_states) = (Vec::new(), Vec::new());
    let mut sink = Vec::new();
    for _ in 0..16 {
      let mut out = vec![0; MAX_RECORD];
      let outcome = client.wrap(&[], &mut out).unwrap();
      client_states.push(outcome.handshake);
      to_server.extend_from_slice(&out[..outcome.produced]);
      loop {
        let mut out = vec![0; MAX_RECORD];
        let mut record = to_server.clone();
        let outcome = server.unwrap(Input::Mutable(&mut record), &mut out).unwrap();
        to_server.drain(..outcome.consumed);
        server_states.push(outcome.handshake);
        if outcome.consumed == 0 {
          break;
        }
      }
      let mut out = vec![0; MAX_RECORD];
      let outcome = server.wrap(&[], &mut out).unwrap();
      server_states.push(outcome.handshake);
      to_client.extend_from_slice(&out[..outcome.produced]);
      feed_states(client, &mut to_client, &mut sink, &mut client_states).unwrap();
      if !client.is_handshaking() && !server.is_handshaking() {
        let mut out = vec![0; MAX_RECORD];
        let outcome = client.wrap(&[], &mut out).unwrap();
        client_states.push(outcome.handshake);
        to_server.extend_from_slice(&out[..outcome.produced]);
        feed_states(server, &mut to_server, &mut sink, &mut server_states).unwrap();
        let outcome = server.wrap(&[], &mut out).unwrap();
        server_states.push(outcome.handshake);
        to_client.extend_from_slice(&out[..outcome.produced]);
        feed_states(client, &mut to_client, &mut sink, &mut client_states).unwrap();
        assert!(sink.is_empty());
        return (client_states, server_states);
      }
    }
    panic!("handshake did not complete");
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_receive_budget_exhaustion_is_terminal_for_shared_and_mutable_input() {
    for shared in [false, true] {
      let (client_config, server_config) = configs(&[&rustls::version::TLS13], &[]);
      let mut client = Engine::client(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
      let budget = Budget::new(0);
      let mut server = Engine::server_with_budget(server_config, budget.clone()).unwrap();
      let mut wire = Vec::new();
      drain(&mut client, &[], &mut wire).unwrap();
      let input = if shared {
        Input::Shared(&wire)
      } else {
        Input::Mutable(&mut wire)
      };
      assert!(server.unwrap(input, &mut vec![0; MAX_RECORD]).is_err());
      assert!(server.failure().is_some());
      assert!(server.inbound_done());
      assert_eq!(
        server.wrap(&[], &mut vec![0; MAX_RECORD]).unwrap().status,
        Status::Closed
      );
      assert_eq!(budget.used(), 0);
    }
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_staging_is_charged_until_release_and_exhaustion_is_isolated() {
    let (client_config, server_config) = configs(&[&rustls::version::TLS13], &[]);
    let budget = Budget::new(256 * 1024);
    let mut client = Engine::client_with_budget(
      client_config.clone(),
      ServerName::try_from("localhost").unwrap(),
      budget.clone(),
    )
    .unwrap();
    let mut server = Engine::server_with_budget(server_config, budget.clone()).unwrap();
    assert_eq!(budget.used(), 0);
    handshake(&mut client, &mut server);
    assert!(budget.used() > 0);
    let retained = budget.used();
    let exhausted = Budget::new(0);
    let mut rejected = Engine::client_with_budget(
      client_config,
      ServerName::try_from("localhost").unwrap(),
      exhausted.clone(),
    )
    .unwrap();
    assert!(rejected.begin().is_err());
    assert!(rejected.failure().is_some());
    assert!(rejected.inbound_done());
    assert_eq!(exhausted.used(), 0);
    assert_eq!(budget.used(), retained);
    let mut wire = Vec::new();
    drain(&mut client, b"still alive", &mut wire).unwrap();
    let mut received = Vec::new();
    feed(&mut server, &mut wire, &mut received).unwrap();
    assert_eq!(received, b"still alive");
    budget.close();
    assert!(budget.used() > 0);
    drop(client);
    drop(server);
    assert_eq!(budget.used(), 0);
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_handshake_reports_finished_once_and_transfers_both_ways() {
    for versions in [&[&rustls::version::TLS13][..], &[&rustls::version::TLS12][..]] {
      let (mut client, mut server) = pair(versions, "localhost");
      assert_eq!(client.handshake_status(), Handshake::NotHandshaking);
      let (client_states, server_states) = handshake(&mut client, &mut server);
      assert_eq!(client_states.iter().filter(|s| **s == Handshake::Finished).count(), 1);
      assert_eq!(server_states.iter().filter(|s| **s == Handshake::Finished).count(), 1);
      assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
      assert_eq!(server.alpn_protocol(), Some(&b"h2"[..]));
      assert_eq!(client.peer_certificates().len(), 1);
      assert!(client.cipher_suite().is_some());
      let expected = if versions[0] == &rustls::version::TLS13 {
        0x0304
      } else {
        0x0303
      };
      assert_eq!(client.protocol_version(), Some(expected));

      let payload: Vec<u8> = (0..70_000u32).map(|i| (i * 31 + 7) as u8).collect();
      let mut wire = Vec::new();
      assert_eq!(drain(&mut client, &payload, &mut wire).unwrap(), payload.len());
      let mut received = Vec::new();
      feed(&mut server, &mut wire, &mut received).unwrap();
      assert_eq!(received, payload);

      let mut wire = Vec::new();
      drain(&mut server, b"world", &mut wire).unwrap();
      let mut received = Vec::new();
      feed(&mut client, &mut wire, &mut received).unwrap();
      assert_eq!(received, b"world");
    }
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_close_notify_closes_each_direction_independently() {
    let (mut client, mut server) = pair(&[&rustls::version::TLS13], "localhost");
    handshake(&mut client, &mut server);
    client.close_outbound();
    assert_eq!(client.handshake_status(), Handshake::NeedWrap);
    let mut out = vec![0; MAX_RECORD];
    let outcome = client.wrap(b"ignored", &mut out).unwrap();
    assert_eq!(outcome.status, Status::Closed);
    assert_eq!(outcome.consumed, 0);
    assert!(outcome.produced > 0);
    assert!(client.outbound_done());
    let mut wire = out[..outcome.produced].to_vec();
    let mut received = Vec::new();
    let mut record = wire.clone();
    let result = server.unwrap(Input::Shared(&record), &mut out).unwrap();
    assert_eq!(result.status, Status::Closed);
    assert!(server.inbound_done());
    assert!(!server.outbound_done());
    record.clear();
    // Half-closed servers keep writing, as JSSE does for TLS 1.3.
    let mut reply = Vec::new();
    drain(&mut server, b"late", &mut reply).unwrap();
    feed(&mut client, &mut reply, &mut received).unwrap();
    assert_eq!(received, b"late");
    wire.clear();
    assert!(!server.close_inbound());
    assert!(client.close_inbound());
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_close_outbound_during_handshake_emits_close_notify_after_completion() {
    for versions in [&[&rustls::version::TLS13][..], &[&rustls::version::TLS12][..]] {
      let (mut client, mut server) = pair(versions, "localhost");

      let mut to_server = Vec::new();
      drain(&mut client, &[], &mut to_server).unwrap();
      assert!(client.is_handshaking());

      feed(&mut server, &mut to_server, &mut Vec::new()).unwrap();
      let mut to_client = Vec::new();
      drain(&mut server, &[], &mut to_client).unwrap();

      client.close_outbound();
      assert!(
        !client.outbound_done(),
        "outbound not done: close-notify not yet queued"
      );

      feed(&mut client, &mut to_client, &mut Vec::new()).unwrap();

      if versions[0] == &rustls::version::TLS12 {
        let mut to_server = Vec::new();
        drain(&mut client, &[], &mut to_server).unwrap();
        feed(&mut server, &mut to_server, &mut Vec::new()).unwrap();
        let mut to_client = Vec::new();
        drain(&mut server, &[], &mut to_client).unwrap();
        feed(&mut client, &mut to_client, &mut Vec::new()).unwrap();
      }

      assert!(!client.is_handshaking(), "client handshake completed");
      assert!(
        !client.outbound_done(),
        "outbound not done until close-notify is handed to caller"
      );

      let mut wire = Vec::new();
      drain(&mut client, &[], &mut wire).unwrap();
      assert!(!wire.is_empty(), "client emitted Finished flight and close-notify");
      assert!(client.outbound_done(), "outbound done after close-notify emitted");

      let mut received = Vec::new();
      feed(&mut server, &mut wire, &mut received).unwrap();
      assert!(!server.is_handshaking(), "server handshake completed");
      assert!(server.inbound_done(), "peer received close-notify");
      assert!(server.failure().is_none());
    }
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_close_outbound_during_handshake_abi_state_not_contradictory() {
    let (mut client, _server) = pair(&[&rustls::version::TLS13], "localhost");
    let mut to_server = Vec::new();
    drain(&mut client, &[], &mut to_server).unwrap();
    assert!(client.is_handshaking());

    client.close_outbound();

    assert!(
      !client.outbound_done(),
      "outbound_done must be false while close-notify is not yet emitted"
    );
    assert!(client.is_handshaking(), "handshake must still be in progress");

    let hs = client.handshake_status();
    assert!(
      hs != Handshake::NotHandshaking,
      "handshake status must not report settled while still handshaking"
    );
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_close_outbound_during_handshake_outbound_stays_open_until_wrap() {
    let (mut client, mut server) = pair(&[&rustls::version::TLS13], "localhost");

    let mut to_server = Vec::new();
    drain(&mut client, &[], &mut to_server).unwrap();
    assert!(client.is_handshaking());

    feed(&mut server, &mut to_server, &mut Vec::new()).unwrap();
    let mut to_client = Vec::new();
    drain(&mut server, &[], &mut to_client).unwrap();

    client.close_outbound();

    feed(&mut client, &mut to_client, &mut Vec::new()).unwrap();
    assert!(!client.is_handshaking());
    assert!(!client.outbound_done());

    assert_eq!(
      client.handshake_status(),
      Handshake::NeedWrap,
      "engine must prompt a wrap to queue and emit close-notify"
    );

    let mut wire = Vec::new();
    drain(&mut client, &[], &mut wire).unwrap();
    assert!(client.outbound_done());

    let mut received = Vec::new();
    feed(&mut server, &mut wire, &mut received).unwrap();
    assert!(server.inbound_done());
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_rejects_tampered_record_and_emits_one_alert() {
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
      let (mut client, mut server) = pair(&[version], "localhost");
      handshake(&mut client, &mut server);
      let mut wire = Vec::new();
      drain(&mut client, b"authenticated plaintext", &mut wire).unwrap();
      *wire.last_mut().unwrap() ^= 0x80;
      let mut out = vec![0; MAX_RECORD];
      let error = server.unwrap(Input::Mutable(&mut wire), &mut out).unwrap_err();
      assert!(error.to_string().contains("decrypt"), "{error}");
      assert!(out.iter().all(|byte| *byte == 0), "unauthenticated plaintext escaped");
      let alert = server.wrap(&[], &mut out).unwrap();
      assert_eq!(alert.status, Status::Closed);
      assert!(alert.produced > 0);
      let mut wire = out[..alert.produced].to_vec();
      let error = client.unwrap(Input::Mutable(&mut wire), &mut out).unwrap_err();
      assert!(error.to_string().contains("alert"), "{error}");
      assert_eq!(server.wrap(&[], &mut out).unwrap().produced, 0);
      assert_eq!(client.wrap(&[], &mut out).unwrap().status, Status::Closed);
    }
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_rejects_wrong_name_and_emits_an_alert() {
    let (mut client, mut server) = pair(&[&rustls::version::TLS13], "example.com");
    let mut out = vec![0; MAX_RECORD];
    let hello = client.wrap(&[], &mut out).unwrap();
    let mut wire = out[..hello.produced].to_vec();
    feed(&mut server, &mut wire, &mut Vec::new()).unwrap();
    let mut wire = Vec::new();
    drain(&mut server, &[], &mut wire).unwrap();
    let error = feed(&mut client, &mut wire, &mut Vec::new()).unwrap_err();
    assert!(error.to_string().contains("certificate"), "{error}");
    assert!(client.failure().is_some());
    let alert = client.wrap(&[], &mut out).unwrap();
    assert!(alert.produced > 0);
    assert_eq!(alert.status, Status::Closed);
    // A failed peer's alert can arrive in mutable native receive storage. Its discarded
    // ciphertext must never be fed back to the deframer while draining local output.
    let mut wire = out[..alert.produced].to_vec();
    let peer_error = feed(&mut server, &mut wire, &mut Vec::new()).unwrap_err();
    assert!(peer_error.to_string().contains("alert"), "{peer_error}");
    assert!(server.failure().is_some());
    assert_eq!(server.wrap(&[], &mut out).unwrap().status, Status::Closed);
    assert_eq!(
      client.unwrap(Input::Shared(&[]), &mut out).unwrap().status,
      Status::Closed
    );
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_reports_underflow_overflow_and_small_destinations() {
    let (mut client, mut server) = pair(&[&rustls::version::TLS13], "localhost");
    handshake(&mut client, &mut server);
    let mut wire = Vec::new();
    drain(&mut client, &[7; 4096], &mut wire).unwrap();
    let mut out = vec![0; 16];
    let partial = wire[..wire.len() - 1].to_vec();
    let outcome = server.unwrap(Input::Shared(&partial), &mut out).unwrap();
    assert_eq!((outcome.status, outcome.consumed), (Status::BufferUnderflow, 0));
    let outcome = server.unwrap(Input::Shared(&wire), &mut out).unwrap();
    assert_eq!((outcome.status, outcome.consumed), (Status::BufferOverflow, 0));
    let mut small = [0; 1];
    let outcome = client.wrap(&[1; 100], &mut small).unwrap();
    assert_eq!(
      (outcome.status, outcome.consumed, outcome.produced),
      (Status::BufferOverflow, 0, 0)
    );
    let mut received = Vec::new();
    feed(&mut server, &mut wire, &mut received).unwrap();
    assert_eq!(received, vec![7; 4096]);
    let error = server
      .unwrap(Input::Shared(&[0x16, 3, 3, 0xff, 0xff]), &mut out)
      .unwrap_err();
    assert!(error.to_string().contains("overflow"));
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn engine_retains_fragmented_handshake_records() {
    let (mut client, mut server) = pair(&[&rustls::version::TLS13], "localhost");
    let mut out = vec![0; MAX_RECORD];
    let hello = client.wrap(&[], &mut out).unwrap();
    let wire = &out[..hello.produced];
    // Split the ClientHello handshake message across two records, as a fragmenting peer might.
    let body = &wire[HEADER..];
    let split = body.len() / 2;
    let mut fragmented = Vec::new();
    for part in [&body[..split], &body[split..]] {
      fragmented.extend_from_slice(&[0x16, 3, 1]);
      fragmented.extend_from_slice(&(part.len() as u16).to_be_bytes());
      fragmented.extend_from_slice(part);
    }
    let mut sink = Vec::new();
    feed(&mut server, &mut fragmented, &mut sink).unwrap();
    assert!(fragmented.is_empty());
    assert_eq!(server.handshake_status(), Handshake::NeedWrap);
  }
}
