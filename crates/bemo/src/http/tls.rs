/*
 * Copyright (c) 2024-2026 Elide Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Bounded TLS record lane for native HTTP; socket completion owns transmission acknowledgements.

use crate::buffer::{Budget, Buffer, FrozenBuffer};
use crate::tls::{Action, Session, State};
use compio_buf::{IoBuf, IoBufMut, SetLen};
use std::io;
use std::sync::Arc;

const MAX_INPUT: usize = 1024 * 1024;
const RECORD_PLAINTEXT: usize = 16384;

pub(crate) enum Progress {
  Blocked,
  Output(FrozenBuffer),
  Plaintext(Buffer),
  Complete(Vec<FrozenBuffer>),
  InputClosed,
  Closed,
}

pub(crate) struct Lane {
  session: Session,
  budget: Budget,
  input: Option<Buffer>,
  application: Option<Vec<FrozenBuffer>>,
  part: usize,
  offset: usize,
  waiting: bool,
  handshake_output: bool,
  acknowledge: bool,
  closing: bool,
  close_sent: bool,
  input_closed: bool,
}

impl Lane {
  pub(crate) fn new(config: Arc<rustls::ServerConfig>, budget: Budget) -> io::Result<Self> {
    if config
      .alpn_protocols
      .iter()
      .any(|protocol| protocol != b"http/1.1" && protocol != b"h2")
    {
      return Err(io::ErrorKind::Unsupported.into());
    }
    Ok(Self {
      session: Session::server(config, budget.clone())?,
      budget,
      input: None,
      application: None,
      part: 0,
      offset: 0,
      waiting: false,
      handshake_output: false,
      acknowledge: false,
      closing: false,
      close_sent: false,
      input_closed: false,
    })
  }

  pub(crate) fn feed(&mut self, buffer: Buffer) -> io::Result<()> {
    let previous = self.input.as_ref().map_or(0, IoBuf::buf_len);
    if buffer.buf_len() > MAX_INPUT - previous {
      return Err(io::ErrorKind::InvalidData.into());
    }
    if previous == 0 {
      self.input = Some(buffer.into_private());
    } else {
      let total = previous + buffer.buf_len();
      let input = self.input.as_mut().unwrap();
      if input.buf_capacity() < total {
        let mut grown = Buffer::new(total, self.budget.clone())?;
        grown.write(0, IoBuf::as_init(&*input))?;
        self.input = Some(grown);
      }
      self.input.as_mut().unwrap().write(previous, buffer.as_init())?;
    }
    Ok(())
  }

  pub(crate) fn enqueue(&mut self, parts: Vec<FrozenBuffer>) {
    assert!(self.application.is_none());
    self.application = Some(parts);
    self.part = 0;
    self.offset = 0;
  }

  pub(crate) fn alpn_protocol(&self) -> Option<&[u8]> {
    self.session.alpn_protocol()
  }

  pub(crate) fn input_closed(&self) -> bool {
    self.input_closed
  }

  pub(crate) fn is_handshaking(&self) -> bool {
    self.session.is_handshaking()
  }

  pub(crate) fn has_application(&self) -> bool {
    self.application.is_some()
  }

  pub(crate) fn transmitted(&mut self) {
    assert!(self.waiting);
    self.waiting = false;
    self.acknowledge = self.handshake_output;
  }

  pub(crate) fn close(&mut self) {
    self.closing = true;
  }

  pub(crate) fn progress(&mut self) -> io::Result<Progress> {
    if self.waiting {
      return Ok(Progress::Blocked);
    }
    if self.close_sent {
      return Ok(Progress::Closed);
    }
    if let Some(parts) = &self.application {
      while self.part < parts.len() && self.offset == parts[self.part].as_ref().len() {
        self.part += 1;
        self.offset = 0;
      }
      if self.part == parts.len() {
        return Ok(Progress::Complete(self.application.take().unwrap()));
      }
    }
    for _ in 0..128 {
      let ack = self.acknowledge;
      // Only stage across allocation boundaries when it reduces record count. Original parts
      // remain owned until every ciphertext write has physically retired.
      let mut staged = None;
      if !ack && let Some(parts) = &self.application {
        let first = &parts[self.part].as_ref()[self.offset..];
        if first.len() < RECORD_PLAINTEXT && saves_record(first.len(), &parts[self.part + 1..]) {
          let length = parts[self.part + 1..].iter().fold(first.len(), |length, part| {
            length.saturating_add(part.as_ref().len()).min(RECORD_PLAINTEXT)
          });
          let mut record = Buffer::new(length, self.budget.clone())?;
          record.write(0, first)?;
          let mut written = first.len();
          for part in &parts[self.part + 1..] {
            let count = part.as_ref().len().min(length - written);
            record.write(written, &part.as_ref()[..count])?;
            written += count;
            if written == length {
              break;
            }
          }
          staged = Some(record);
        }
      }
      let action = if ack {
        Action::Transmitted
      } else if let Some(parts) = &self.application {
        Action::Write(
          staged
            .as_ref()
            .map_or(&parts[self.part].as_ref()[self.offset..], IoBuf::as_init),
        )
      } else if self.closing && !self.session.is_handshaking() {
        Action::Close
      } else {
        Action::Continue
      };
      let input = self.input.as_mut().map_or(&mut [][..], |input| input.as_mut_slice());
      let step = self.session.step(input, action)?;
      if step.discard > input.len() {
        return Err(io::ErrorKind::InvalidData.into());
      }
      let remaining = input.len() - step.discard;
      input.copy_within(step.discard.., 0);
      if let Some(input) = &mut self.input {
        // SAFETY: Compaction only shortens the initialized input prefix.
        unsafe { input.set_len(remaining) };
      }
      if remaining == 0 {
        self.input = None;
      }
      if step.state == State::NeedTransmit && ack {
        self.acknowledge = false;
      }
      if let Some(parts) = &self.application {
        let mut accepted = step.accepted;
        while accepted > 0 {
          let available = parts[self.part].as_ref().len() - self.offset;
          let count = available.min(accepted);
          self.offset += count;
          accepted -= count;
          if self.offset == parts[self.part].as_ref().len() && self.part + 1 < parts.len() {
            self.part += 1;
            self.offset = 0;
          } else if accepted > 0 {
            return Err(io::ErrorKind::InvalidData.into());
          }
        }
      }
      if let Some(output) = step.output {
        self.waiting = true;
        self.handshake_output = step.state == State::Encoded;
        self.close_sent = matches!(action, Action::Close) && step.state == State::Ready;
        return Ok(Progress::Output(output));
      }
      if let Some(plaintext) = step.plaintext {
        return plaintext
          .try_into_mut()
          .map(Progress::Plaintext)
          .map_err(|_| io::ErrorKind::InvalidData.into());
      }
      match step.state {
        State::NeedRead | State::Ready => return Ok(Progress::Blocked),
        State::NeedTransmit if !ack => return Ok(Progress::Blocked),
        State::PeerClosed => {
          self.input_closed = true;
          return Ok(Progress::InputClosed);
        }
        State::Closed => return Ok(Progress::Closed),
        _ => {}
      }
    }
    Err(io::ErrorKind::InvalidData.into())
  }
}

fn saves_record(first: usize, remaining: &[FrozenBuffer]) -> bool {
  let separate = remaining
    .iter()
    .fold(first.div_ceil(RECORD_PLAINTEXT), |records, part| {
      records.saturating_add(part.as_ref().len().div_ceil(RECORD_PLAINTEXT))
    });
  let staged = remaining.iter().fold(first, |length, part| {
    length.saturating_add(part.as_ref().len()).min(RECORD_PLAINTEXT)
  });
  let mut leftover = staged - first;
  let mut remainder = 0;
  for part in remaining {
    let len = part.as_ref().len();
    let consumed = len.min(leftover);
    remainder += (len - consumed).div_ceil(RECORD_PLAINTEXT);
    leftover -= consumed;
  }
  separate > 1 + remainder
}

#[cfg(test)]
mod tests {
  use super::*;
  use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
  use std::io::{Cursor, Read, Write};
  use std::sync::Arc;

  fn pair() -> (Lane, rustls::ClientConnection) {
    pair_with_budget(Budget::new(1024 * 1024))
  }

  fn pair_with_budget(budget: Budget) -> (Lane, rustls::ClientConnection) {
    let cert = CertificateDer::from_pem_slice(include_bytes!("../../tests/fixtures/localhost-cert.pem")).unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../tests/fixtures/localhost-key.pem")).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_root_certificates(roots)
      .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_no_client_auth()
      .with_single_cert(vec![cert], key)
      .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    (
      Lane::new(Arc::new(server), budget).unwrap(),
      rustls::ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap()).unwrap(),
    )
  }

  fn bytes(data: &[u8]) -> Buffer {
    let mut result = Buffer::new(data.len().max(1), Budget::new(1024 * 1024)).unwrap();
    result.write(0, data).unwrap();
    result
  }

  fn frozen(len: usize) -> FrozenBuffer {
    if len == 0 {
      bytes(&[]).freeze()
    } else {
      bytes(&vec![0; len]).freeze()
    }
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn handshake_waits_for_wire_ack_and_application_completion_follows_ciphertext() {
    let (mut lane, mut client) = pair();
    let mut received = Vec::new();
    let mut delivered = false;
    let mut request = None;
    for _ in 0..200 {
      let mut wire = Vec::new();
      client.write_tls(&mut wire).unwrap();
      if !wire.is_empty() {
        // Force TLS headers and records to span input buffers.
        for fragment in wire.chunks(7) {
          lane.feed(bytes(fragment)).unwrap();
        }
      }
      match lane.progress().unwrap() {
        Progress::Output(output) => {
          assert!(matches!(lane.progress().unwrap(), Progress::Blocked));
          let mut wire = Cursor::new(output.as_ref());
          while wire.position() < output.as_ref().len() as u64 {
            client.read_tls(&mut wire).unwrap();
            client.process_new_packets().unwrap();
          }
          lane.transmitted();
        }
        Progress::Plaintext(buffer) => request = Some(buffer.freeze()),
        Progress::Complete(parts) => {
          assert_eq!(parts.iter().map(|part| part.as_ref().len()).sum::<usize>(), 32768);
          delivered = true;
        }
        Progress::Blocked => {
          if !client.is_handshaking() && !lane.has_application() && !delivered {
            client
              .writer()
              .write_all(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata")
              .unwrap();
            lane.enqueue(vec![bytes(&vec![b'x'; 32768]).freeze()]);
          }
        }
        Progress::InputClosed | Progress::Closed => panic!("unexpected TLS close"),
      }
      let mut chunk = [0; 8192];
      while let Ok(length) = client.reader().read(&mut chunk) {
        if length == 0 {
          break;
        }
        received.extend_from_slice(&chunk[..length]);
      }
      if delivered && request.is_some() {
        break;
      }
    }
    assert!(delivered);
    assert_eq!(received.len(), 32768);
    assert!(received.iter().all(|b| *b == b'x'));
    drop(lane);
    assert!(request.unwrap().as_ref().ends_with(b"data"));
  }
  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn split_parts_fill_records_and_keep_original_leases_until_retirement() {
    for body_length in [1024, 16384, 16385, 65536, 131072] {
      let (mut lane, mut client) = pair();
      for _ in 0..100 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        if !wire.is_empty() {
          lane.feed(bytes(&wire)).unwrap();
        }
        match lane.progress().unwrap() {
          Progress::Output(output) => {
            let mut wire = Cursor::new(output.as_ref());
            while wire.position() < output.as_ref().len() as u64 {
              client.read_tls(&mut wire).unwrap();
              client.process_new_packets().unwrap();
            }
            lane.transmitted();
          }
          Progress::Blocked if !client.is_handshaking() && !lane.is_handshaking() => break,
          Progress::Blocked => {}
          _ => panic!("unexpected handshake progress"),
        }
      }
      assert!(!lane.is_handshaking());
      let owner = Budget::new(128 + body_length);
      let mut header = Buffer::new(128, owner.clone()).unwrap();
      header.write(0, &[b'h'; 128]).unwrap();
      let mut body = Buffer::new(body_length, owner.clone()).unwrap();
      body.write(0, &vec![b'b'; body_length]).unwrap();
      lane.enqueue(vec![header.freeze(), bytes(&[]).freeze(), body.freeze()]);
      let mut outputs = 0;
      let mut received = Vec::new();
      loop {
        match lane.progress().unwrap() {
          Progress::Output(output) => {
            outputs += 1;
            assert_eq!(owner.used(), 128 + body_length);
            assert!(matches!(lane.progress().unwrap(), Progress::Blocked));
            let mut wire = Cursor::new(output.as_ref());
            while wire.position() < output.as_ref().len() as u64 {
              client.read_tls(&mut wire).unwrap();
              client.process_new_packets().unwrap();
              let mut chunk = [0; RECORD_PLAINTEXT];
              while let Ok(length) = client.reader().read(&mut chunk) {
                if length == 0 {
                  break;
                }
                received.extend_from_slice(&chunk[..length]);
              }
            }
            lane.transmitted();
          }
          Progress::Complete(parts) => {
            assert_eq!(parts.len(), 3);
            assert_eq!(owner.used(), 128 + body_length);
            drop(parts);
            assert_eq!(owner.used(), 0);
            break;
          }
          _ => panic!("unexpected application progress"),
        }
      }
      let first_body = if body_length % RECORD_PLAINTEXT == 0 {
        0
      } else {
        body_length.min(RECORD_PLAINTEXT - 128)
      };
      assert_eq!(outputs, 1 + (body_length - first_body).div_ceil(crate::tls::MAX_WRITE));
      assert_eq!(&received[..128], &[b'h'; 128]);
      assert_eq!(&received[128..], vec![b'b'; body_length]);
    }
  }

  #[test]
  fn saves_record_false_when_exact_multiple_prevents_savings() {
    assert!(!saves_record(100, &[frozen(32768), frozen(100)]));
    assert!(!saves_record(50, &[frozen(32768), frozen(50)]));
    assert!(!saves_record(1, &[frozen(49152), frozen(1)]));
  }

  #[test]
  fn saves_record_true_when_staging_merges_small_parts() {
    assert!(saves_record(100, &[frozen(100)]));
    assert!(saves_record(200, &[frozen(200)]));
  }

  #[test]
  fn saves_record_false_with_no_remaining() {
    assert!(!saves_record(100, &[]));
    assert!(!saves_record(RECORD_PLAINTEXT, &[]));
  }

  #[test]
  fn saves_record_false_when_first_fills_a_record() {
    assert!(!saves_record(RECORD_PLAINTEXT, &[frozen(100)]));
  }

  #[test]
  #[cfg_attr(miri, ignore = "rustls handshakes call into AWS-LC")]
  fn shared_budget_exact_multiple_parts_do_not_exhaust_connection() {
    let budget = Budget::new(50000);
    let (mut lane, mut client) = pair_with_budget(budget.clone());
    for _ in 0..100 {
      let mut wire = Vec::new();
      client.write_tls(&mut wire).unwrap();
      if !wire.is_empty() {
        lane.feed(bytes(&wire)).unwrap();
      }
      match lane.progress().unwrap() {
        Progress::Output(output) => {
          let mut wire = Cursor::new(output.as_ref());
          while wire.position() < output.as_ref().len() as u64 {
            client.read_tls(&mut wire).unwrap();
            client.process_new_packets().unwrap();
          }
          lane.transmitted();
        }
        Progress::Blocked if !client.is_handshaking() && !lane.is_handshaking() => break,
        Progress::Blocked => {}
        _ => panic!("unexpected handshake progress"),
      }
    }
    assert!(!lane.is_handshaking());
    let mut p1 = Buffer::new(100, budget.clone()).unwrap();
    p1.write(0, &[b'a'; 100]).unwrap();
    let mut p2 = Buffer::new(32768, budget.clone()).unwrap();
    p2.write(0, &vec![b'b'; 32768]).unwrap();
    let mut p3 = Buffer::new(100, budget).unwrap();
    p3.write(0, &[b'c'; 100]).unwrap();
    lane.enqueue(vec![p1.freeze(), p2.freeze(), p3.freeze()]);
    let mut received = Vec::new();
    loop {
      match lane.progress().unwrap() {
        Progress::Output(output) => {
          assert!(matches!(lane.progress().unwrap(), Progress::Blocked));
          let mut wire = Cursor::new(output.as_ref());
          while wire.position() < output.as_ref().len() as u64 {
            client.read_tls(&mut wire).unwrap();
            client.process_new_packets().unwrap();
            let mut chunk = [0; RECORD_PLAINTEXT];
            while let Ok(length) = client.reader().read(&mut chunk) {
              if length == 0 {
                break;
              }
              received.extend_from_slice(&chunk[..length]);
            }
          }
          lane.transmitted();
        }
        Progress::Complete(_) => break,
        _ => panic!("unexpected application progress"),
      }
    }
    assert_eq!(received.len(), 32968);
    assert_eq!(&received[..100], &[b'a'; 100]);
    assert_eq!(&received[100..32868], &vec![b'b'; 32768]);
    assert_eq!(&received[32868..], &[b'c'; 100]);
  }
}
