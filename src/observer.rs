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

use std::{net::IpAddr, collections, time::Instant, convert::TryInto, task::Poll};
use bloom2::{CompressedBitmap, FilterSize};
use bounded_vec_deque::BoundedVecDeque;
use twox_hash::RandomXxHashBuilder32;
use thiserror::Error;
use color_eyre::Result;
use bytes::{BytesMut, BufMut};
use serde::de::DeserializeOwned;
use packet::{ip::{Protocol, v4 as ip}, icmp, AsPacket as _, Packet as _};
use crate::agreement::{self, Agreement};

#[derive(Error, Debug)]
pub enum ObserverError {
	#[error("a nonce is being reused")]
	NonceReused,

	#[error("an invalid packet was received")]
	InvalidPacket,
}

type HashMap<K, V> = collections::HashMap<K, V, RandomXxHashBuilder32>;

pub struct Observer {
	agreement: Agreement,
	nonces: HashMap<[u8; 32], CompressedBitmap>,
	sessions: HashMap<IpAddr, BoundedVecDeque<(Instant, [u8; 2])>>,
}

impl Observer {
	pub fn new(agreement: Agreement) -> Self {
		Observer {
			agreement,

			nonces: Default::default(),
			sessions: Default::default(),
		}
	}

	#[tracing::instrument(skip(self))]
	pub fn receive<T>(&mut self, addr: IpAddr, buffer: &[u8], ts: Instant) -> Result<Poll<T>>
		where T: DeserializeOwned
	{
		let ip: ip::Packet<_> = buffer.as_packet()
			.or(Err(ObserverError::InvalidPacket))?;

		if ip.protocol() != Protocol::Icmp {
			Err(ObserverError::InvalidPacket)?
		}

		let buffer = ip.payload();
		let icmp: icmp::Packet<_> = buffer.as_packet()
			.or(Err(ObserverError::InvalidPacket))?;

		if let Ok(echo) = icmp.echo() {
			if !echo.is_request() {
				Err(ObserverError::InvalidPacket)?
			}
		}
		else {
			Err(ObserverError::InvalidPacket)?
		}

		let mut fragment = [0u8; 2];
		(&mut fragment[..]).put_u16(ip.id());

		let session = self.sessions.entry(addr).or_insert(BoundedVecDeque::new(agreement::MAX_LENGTH));
		session.push_back((ts, fragment));

		// TODO(meh): evict expired packets from the session

		if session.len() * 2 < agreement::MIN_LENGTH {
			tracing::trace!("need more data");
			return Ok(Poll::Pending);
		}

		let mut buffer = BytesMut::new();
		for (_, data) in session.iter() {
			buffer.put(&data[..]);
		}

		tracing::trace!("attempting decryption");
		match self.agreement.decode(buffer.freeze()) {
			Ok(Poll::Pending) => {
				tracing::trace!("need more data");
				Ok(Poll::Pending)
			}

			Ok(Poll::Ready((payload, rest))) => {
				tracing::trace!("evicting {} packets", ((session.len() * 2) - rest.len()) / 2);
				session.drain(.. ((session.len() * 2) - rest.len()) / 2);

				let nonces = self.nonces.entry((&self.agreement.peer.as_bytes()[..]).try_into()?)
					.or_insert_with(|| CompressedBitmap::new(FilterSize::KeyBytes4));

				if nonces.contains_hash(&payload.session) {
					Err(ObserverError::NonceReused)?
				}
				nonces.insert_hash(&payload.session);

				Ok(Poll::Ready(bincode::deserialize(&payload.data)?))
			}
			
			Err(_) => {
				tracing::trace!("evicting first packet");
				session.pop_front();
				Ok(Poll::Pending)
			}
		}
	}
}
