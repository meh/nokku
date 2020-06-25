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

use std::{task::Poll, convert::{TryInto, TryFrom}, fs, path::Path};
use color_eyre::Result;
use base64;
use rand::prelude::*;
use thiserror::Error;
use x25519::{StaticSecret, PublicKey, SharedSecret, EphemeralSecret};
use hkdf::Hkdf;
use sha2::Sha512;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use aead::{Aead, NewAead, generic_array::{GenericArray, typenum::{self as N, Unsigned}}};

pub struct Agreement {
	pub me: StaticSecret,
	pub peers: Vec<Peer>,
}

pub struct Peer {
	pub key: PublicKey,
	pub shared: SharedSecret,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
pub struct PeerId(pub usize);

#[derive(Error, Debug)]
pub enum AgreementError {
	#[error("invalid cookie")]
	InvalidCookie,

	#[error("no valid known key")]
	InvalidKey,

	#[error("decryption failed")]
	DecryptionFailed,

	#[error("encryption failed")]
	EncryptionFailed,

	#[error("payload cannot exceed 255 bytes")]
	PayloadTooLong,
}

#[derive(Debug)]
pub struct Payload {
	pub session: Bytes,
	pub data: Bytes,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Mode {
	Confident,
	Paranoid,
}

impl Default for Mode {
	fn default() -> Self {
		Self::Confident
	}
}

#[derive(Debug)]
struct DerivedKeys {
	cookie: u16,
	length: u8,
	aead: GenericArray<u8, N::U32>,
	nonce: GenericArray<u8, N::U12>,
}

pub const COOKIE: u16 = 0x1337;

pub mod len {
	pub const SESSION: usize = 4;
	pub const PUBKEY: usize = 32;
	pub const COOKIE: usize = 2;
	pub const LENGTH: usize = 1;
	pub const MAC: usize = 16;

	pub const MIN_HEADER: usize = SESSION + 2 + 1;
	pub const MAX_HEADER: usize = PUBKEY + 2 + 1;
	pub const MAX: usize = MAX_HEADER + u8::MAX as usize + MAC;
}

impl Agreement {
	/// Create a new agreement with a private key and a set of public keys.
	///
	/// The private key will be used to encode and decode messages, and every
	/// public key will be tried until a valid message is found.
	pub fn new(me: &str, peers: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self> {
		let me = if Path::new(me).exists() {
			fs::read_to_string(me)?
		}
		else {
			me.to_owned()
		};
		let me = base64::decode_config(me.trim(), base64::CRYPT)?;
		let me: [u8; 32] = me.as_slice().try_into()?;
		let me = StaticSecret::from(me);

		let peers = peers.into_iter().map(|peer| {
			let peer = if Path::new(peer.as_ref()).exists() {
				fs::read_to_string(peer.as_ref())?
			}
			else {
				peer.as_ref().to_owned()
			};

			let peer = base64::decode_config(peer.trim(), base64::CRYPT)?;
			let peer: [u8; 32] = peer.as_slice().try_into()?;
			let peer = PublicKey::from(peer);
			let shared = me.diffie_hellman(&peer);

			Ok(Peer {
				key: PublicKey::from(peer),
				shared,
			})
		}).collect::<Result<Vec<_>>>()?;

		Ok(Self { me, peers })
	}

	/// Get a specific peer.
	pub fn peer(&self, id: PeerId) -> &Peer {
		&self.peers[id.0]
	}

	/// Derive keys from a shared secret and nonce.
	fn derive(&self, secret: &[u8], nonce: &[u8]) -> DerivedKeys {
		let key = Hkdf::<Sha512>::extract(Some(nonce), secret).0;
		let rest = key.as_slice();

		let (mut cookie, rest) = rest.split_at(2);
		let (length, rest) = rest.split_at(1);
		let (aead, rest) = rest.split_at(32);
		let (nonce, _rest) = rest.split_at(12);

		DerivedKeys {
			cookie: cookie.get_u16(),
			length: length[0],
			aead: GenericArray::clone_from_slice(aead),
			nonce: GenericArray::clone_from_slice(nonce),
		}
	}

	/// Decode a message.
	pub fn decode(&self, buffer: Bytes) -> Result<Poll<(PeerId, Payload, Bytes)>> {
		if buffer.len() < len::MIN_HEADER {
			return Ok(Poll::Pending);
		}

		let mut status = None;
		for (id, peer) in self.peers.iter().enumerate() {
			let mut rest = buffer.clone();
			let mut header = rest.split_to(len::SESSION + len::COOKIE + len::LENGTH);
			let mut authenticated = header.clone();

			let mut session = header.split_to(len::SESSION);
			let mut keys = self.derive(peer.shared.as_bytes(), &session[..]);

			let cookie = header.get_u16() ^ keys.cookie;
			if cookie != COOKIE {
				if buffer.len() < len::MAX_HEADER {
					status = Some(Ok(Poll::Pending));
					continue;
				}

				rest = buffer.clone();
				header = rest.split_to(len::PUBKEY + len::COOKIE + len::LENGTH);
				authenticated = header.clone();

				let public: [u8; 32] = header.split_to(len::PUBKEY).as_ref().try_into().unwrap();
				let public = PublicKey::from(public);
				let salt = self.me.diffie_hellman(&public);

				session = Bytes::copy_from_slice(public.as_bytes());
				keys = self.derive(peer.shared.as_bytes(), salt.as_bytes());

				let cookie = header.get_u16() ^ keys.cookie;
				if cookie != COOKIE {
					status = Some(Err(AgreementError::InvalidCookie));
					continue;
				}
			}

			let length = header.get_u8() ^ keys.length;
			let needed = usize::from(length) + <ChaCha20Poly1305 as Aead>::TagSize::to_usize();

			if rest.len() < needed {
				return Ok(Poll::Pending);
			}

			let data  = rest.split_to(needed);
			let data = Bytes::from(ChaCha20Poly1305::new(keys.aead)
				.decrypt(&keys.nonce, aead::Payload { msg: data.as_ref(), aad: &authenticated })
				.or(Err(AgreementError::DecryptionFailed))?);

			return Ok(Poll::Ready((PeerId(id), Payload { session, data }, rest)))
		}

		status.unwrap_or(Err(AgreementError::InvalidKey))
			.map_err(Into::into)
	}

	/// Encode a message for a specific peer in a specific mode.
	pub fn encode(&self, peer: PeerId, mode: Mode, value: Bytes) -> Result<Bytes> {
		let peer = &self.peers[peer.0];

		let (session, salt) = match mode {
			Mode::Confident => {
				let session: [u8; 4] = rand::thread_rng().gen();

				(Bytes::copy_from_slice(&session),
				 Bytes::copy_from_slice(&session))
			}

			Mode::Paranoid => {
				let private = EphemeralSecret::new(&mut thread_rng());
				let public = PublicKey::from(&private);
				let salt = private.diffie_hellman(&peer.key);

				(Bytes::copy_from_slice(public.as_bytes()),
				 Bytes::copy_from_slice(salt.as_bytes()))
			}
		};

		let keys = self.derive(peer.shared.as_bytes(), &salt);
		let length = u8::try_from(value.len())
			.or(Err(AgreementError::PayloadTooLong))?;

		let mut encoded = BytesMut::new();
		encoded.put(&session[..]);
		encoded.put_u16(COOKIE ^ keys.cookie);
		encoded.put_u8(length ^ keys.length);

		encoded.put(ChaCha20Poly1305::new(keys.aead)
			.encrypt(&keys.nonce, aead::Payload { msg: &value, aad: &encoded })
			.or(Err(AgreementError::EncryptionFailed))?
			.as_ref());

		Ok(encoded.freeze())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn confident_roundtrip() {
		let server = Agreement::new(include_str!("../tests/observer.priv"),
			vec![include_str!("../tests/client.pub"), include_str!("../tests/client2.pub")]).unwrap();

		let alice = Agreement::new(include_str!("../tests/client.priv"),
			Some(include_str!("../tests/observer.pub"))).unwrap();

		let bob = Agreement::new(include_str!("../tests/client2.priv"),
			Some(include_str!("../tests/observer.pub"))).unwrap();

		// Try message from Alice.
		{
			let encoded = alice.encode(PeerId(0), Mode::Confident, Bytes::from_static(b"foo")).unwrap();
			let decoded = server.decode(encoded.clone()).unwrap();

			if let Poll::Ready((peer, payload, _)) = decoded {
				assert_eq!(PeerId(0), peer);
				assert_eq!(b"foo", payload.data.as_ref());
			}
			else {
				panic!("decoding didn't happen");
			}
		}

		// Try message from Bob.
		{
			let encoded = bob.encode(PeerId(0), Mode::Confident, Bytes::from_static(b"foo")).unwrap();
			let decoded = server.decode(encoded.clone()).unwrap();

			if let Poll::Ready((peer, payload, _)) = decoded {
				assert_eq!(PeerId(1), peer);
				assert_eq!(b"foo", payload.data.as_ref());
			}
			else {
				panic!("decoding didn't happen");
			}
		}
	}

	#[test]
	fn paranoid_roundtrip() {
		let server = Agreement::new(include_str!("../tests/observer.priv"),
			vec![include_str!("../tests/client.pub"), include_str!("../tests/client2.pub")]).unwrap();

		let alice = Agreement::new(include_str!("../tests/client.priv"),
			Some(include_str!("../tests/observer.pub"))).unwrap();

		let bob = Agreement::new(include_str!("../tests/client2.priv"),
			Some(include_str!("../tests/observer.pub"))).unwrap();

		// Try message from Alice.
		{
			let encoded = alice.encode(PeerId(0), Mode::Paranoid, Bytes::from_static(b"foo")).unwrap();
			let decoded = server.decode(encoded.clone()).unwrap();

			if let Poll::Ready((peer, payload, _)) = decoded {
				assert_eq!(PeerId(0), peer);
				assert_eq!(b"foo", payload.data.as_ref());
			}
			else {
				panic!("decoding didn't happen");
			}
		}

		// Try message from Bob.
		{
			let encoded = bob.encode(PeerId(0), Mode::Paranoid, Bytes::from_static(b"foo")).unwrap();
			let decoded = server.decode(encoded.clone()).unwrap();

			if let Poll::Ready((peer, payload, _)) = decoded {
				assert_eq!(PeerId(1), peer);
				assert_eq!(b"foo", payload.data.as_ref());
			}
			else {
				panic!("decoding didn't happen");
			}
		}
	}
}
