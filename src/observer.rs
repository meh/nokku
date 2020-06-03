//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::{net::IpAddr, collections, time::Instant, convert::TryInto, task::Poll, ops::Deref};
use bloom2::{CompressedBitmap, FilterSize};
use bounded_vec_deque::BoundedVecDeque;
use twox_hash::RandomXxHashBuilder32;
use thiserror::Error;
use color_eyre::Result;
use bytes::{BytesMut, BufMut};
use serde::de::DeserializeOwned;
use bincode::Options;
use packet::{ip::{Protocol, v4 as ip}, icmp, AsPacket as _, Packet as _};
use crate::agreement::{self, Agreement};

#[derive(Error, Debug)]
pub enum ObserverError {
	#[error("a nonce is being reused")]
	NonceReused,

	#[error("an invalid packet was received")]
	InvalidPacket,

	#[error("the stream has been closed")]
	StreamClosed,
}

type HashMap<K, V> = collections::HashMap<K, V, RandomXxHashBuilder32>;

pub struct Observer {
	agreement: Agreement,
	nonces: HashMap<[u8; 32], CompressedBitmap>,
	sessions: HashMap<IpAddr, HashMap<u16, Stream>>,
}

struct Stream {
	closed: bool,
	at: Instant,
	id: u16,
	packets: BoundedVecDeque<(Instant, [u8; 2])>
}

impl Stream {
	pub fn new(id: u16, at: Instant) -> Self {
		Self {
			id, at,
			closed: false,
			packets: BoundedVecDeque::new(agreement::MAX_LENGTH / 2),
		}
	}

	pub fn is_closed(&self) -> bool {
		self.closed
	}

	pub fn close(&mut self) {
		self.closed = true;
	}

	pub fn id(&self) -> u16 {
		self.id
	}

	pub fn at(&self) -> Instant {
		self.at
	}

	pub fn push(&mut self, value: (Instant, [u8; 2])) {
		self.packets.push_back(value);
	}

	pub fn pop(&mut self) -> Option<(Instant, [u8; 2])> {
		self.packets.pop_front()
	}
}

impl Deref for Stream {
	type Target = BoundedVecDeque<(Instant, [u8; 2])>;

	fn deref(&self) -> &Self::Target {
		&self.packets
	}
}

impl Observer {
	pub fn new(agreement: Agreement) -> Self {
		Observer {
			agreement,

			nonces: Default::default(),
			sessions: Default::default(),
		}
	}

	fn evict(&mut self) {
		// 5 seconds maximum latency.
		const TIMEOUT: u64 = (agreement::MAX_LENGTH as u64 / 2) * 5;

		let mut expired_sessions = Vec::new();

		for (&addr, session) in self.sessions.iter_mut() {
			let mut expired_streams = Vec::new();

			for (&id, stream) in session.iter_mut() {
				if stream.is_closed() {
					continue;
				}

				let now = Instant::now();

				if now.duration_since(stream.at()).as_secs() > TIMEOUT {
					expired_streams.push(stream.id());
					continue;
				}

				let mut valid_packet = None;
				for (i, (at, _)) in stream.packets.iter().enumerate() {
					if now.duration_since(*at).as_secs() < TIMEOUT {
						valid_packet = Some(i);
						break;
					}
				}

				match valid_packet {
					Some(i) if i > 0 => {
						stream.packets.drain(.. i);

						if stream.packets.is_empty() {
							expired_streams.push(id);
						}
					}

					None =>
						expired_streams.push(id),

					Some(_) =>
						()
				}
			}

			for id in &expired_streams {
				session.remove(id);
			}

			if session.is_empty() {
				expired_sessions.push(addr);
			}
		}

		for addr in &expired_sessions {
			self.sessions.remove(addr);
		}
	}

	#[tracing::instrument(skip(self, buffer))]
	pub fn receive<T>(&mut self, addr: IpAddr, buffer: &[u8], ts: Instant) -> Result<Poll<T>>
		where T: DeserializeOwned
	{
		self.evict();

		// Parse the packet and dig down to the proper layer and ICMP request type.
		let ip: ip::Packet<_> = buffer.as_packet()
			.or(Err(ObserverError::InvalidPacket))?;

		if ip.protocol() != Protocol::Icmp {
			Err(ObserverError::InvalidPacket)?
		}

		let buffer = ip.payload();
		let icmp: icmp::Packet<_> = buffer.as_packet()
			.or(Err(ObserverError::InvalidPacket))?;

		let echo = if let Ok(echo) = icmp.echo() {
			if !echo.is_request() {
				Err(ObserverError::InvalidPacket)?
			}

			echo
		}
		else {
			Err(ObserverError::InvalidPacket)?
		};

		// Find the stream from the session belonging to this packet.
		let stream = self.sessions
			.entry(addr)
			.or_insert_with(|| Default::default())
				.entry(echo.identifier())
				.or_insert_with(|| Stream::new(echo.identifier(), ts));

		if stream.is_closed() {
			Err(ObserverError::StreamClosed)?
		}

		let mut fragment = [0u8; 2];
		(&mut fragment[..]).put_u16(ip.id());
		stream.push((ts, fragment));

		// Try to decode a message until it either works or more packets are
		// needed.
		loop {
			let mut buffer = BytesMut::new();
			for (_, fragment) in stream.iter() {
				buffer.put(fragment.as_ref());
			}

			match self.agreement.decode(buffer.freeze()) {
				Ok(Poll::Ready((payload, _))) => {
					let decoded = bincode::DefaultOptions::new()
						.with_limit(255)
						.with_varint_encoding()
						.deserialize(&payload.data)?;

					// Check the nonce hasn't been used already.
					let nonces = self.nonces.entry((&self.agreement.peer.as_bytes()[..]).try_into()?)
						.or_insert_with(|| CompressedBitmap::new(FilterSize::KeyBytes4));

					if nonces.contains_hash(&payload.session) {
						Err(ObserverError::NonceReused)?
					}
					nonces.insert_hash(&payload.session);

					stream.close();

					break Ok(Poll::Ready(decoded));
				}

				Ok(Poll::Pending) => {
					tracing::trace!("need more data");
					break Ok(Poll::Pending);
				}

				Err(err) => {
					tracing::trace!("evicting first packet because of {}", err);
					stream.pop();
				}
			}
		}
	}
}
