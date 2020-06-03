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
	pub peer: PublicKey,
	pub secret: SharedSecret,
}

#[derive(Error, Debug)]
pub enum AgreementError {
	#[error("invalid cookie")]
	InvalidCookie,

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

pub const NONCE_LENGTH: usize = 4;
pub const PUBKEY_LENGTH: usize = 32;
pub const MAC_LENGTH: usize = 16;

pub const MIN_HEADER_LENGTH: usize = NONCE_LENGTH + 2 + 1;
pub const MAX_HEADER_LENGTH: usize = PUBKEY_LENGTH + 2 + 1;
pub const MAX_LENGTH: usize = MAX_HEADER_LENGTH + u8::MAX as usize + MAC_LENGTH;

impl Agreement {
	pub fn new(me: &str, peer: &str) -> Result<Self> {
		let me = if Path::new(me).exists() {
			fs::read_to_string(me)?
		}
		else {
			me.to_owned()
		};

		let peer = if Path::new(peer).exists() {
			fs::read_to_string(peer)?
		}
		else {
			peer.to_owned()
		};

		let private_key = base64::decode_config(me.trim(), base64::CRYPT)?;
		let public_key = base64::decode_config(peer.trim(), base64::CRYPT)?;

		let private_key: [u8; 32] = private_key.as_slice().try_into()?;
		let public_key: [u8; 32] = public_key.as_slice().try_into()?;
		
		let private_key = StaticSecret::from(private_key);
		let public_key = PublicKey::from(public_key);
		let secret = private_key.diffie_hellman(&public_key);

		Ok(Self {
			me: private_key,
			peer: public_key,
			secret,
		})
	}

	fn derive(&self, nonce: &[u8]) -> DerivedKeys {
		let key = Hkdf::<Sha512>::extract(Some(nonce), self.secret.as_bytes()).0;
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

	pub fn decode(&self, mut buffer: Bytes) -> Result<Poll<(Payload, Bytes)>> {
		if buffer.len() < MIN_HEADER_LENGTH {
			return Ok(Poll::Pending);
		}

		let session: [u8; 4] = buffer.split_to(4).as_ref().try_into().unwrap();
		let mut session = Bytes::copy_from_slice(&session);
		let mut keys = self.derive(&session[..]);

		let cookie = buffer.get_u16() ^ keys.cookie;
		if cookie != COOKIE {
			if 6 + buffer.len() < MAX_HEADER_LENGTH {
				return Ok(Poll::Pending);
			}

			let mut public = [0u8; 32];
			(&mut public[..]).put(&session[..]);
			(&mut public[4..]).put_u16(cookie ^ keys.cookie);
			(&mut public[6..]).put(buffer.split_to(26));

			let public = PublicKey::from(public);
			let salt = self.me.diffie_hellman(&public);

			session = Bytes::copy_from_slice(public.as_bytes());
			keys = self.derive(salt.as_bytes());

			let cookie = buffer.get_u16() ^ keys.cookie;
			if cookie != COOKIE {
				Err(AgreementError::InvalidCookie)?
			}
		}

		let length = buffer.get_u8() ^ keys.length;
		let needed = usize::from(length) + <ChaCha20Poly1305 as Aead>::TagSize::to_usize();

		if buffer.len() < needed {
			return Ok(Poll::Pending);
		}

		let rest      = buffer.split_off(needed);
		let plaintext = Bytes::from(ChaCha20Poly1305::new(keys.aead)
			.decrypt(&keys.nonce, aead::Payload { msg: buffer.as_ref(), aad: &session })
			.or(Err(AgreementError::DecryptionFailed))?);

		Ok(Poll::Ready((Payload { session, data: plaintext }, rest)))
	}

	pub fn encode(&self, mode: Mode, value: Bytes) -> Result<Bytes> {
		let (session, salt) = match mode {
			Mode::Confident => {
				let session: [u8; 4] = rand::thread_rng().gen();

				(Bytes::copy_from_slice(&session),
				 Bytes::copy_from_slice(&session))
			}

			Mode::Paranoid => {
				let private = EphemeralSecret::new(&mut thread_rng());
				let public = PublicKey::from(&private);
				let salt = private.diffie_hellman(&self.peer);

				(Bytes::copy_from_slice(public.as_bytes()),
				 Bytes::copy_from_slice(salt.as_bytes()))
			}
		};

		let keys = self.derive(&salt);
		let length = u8::try_from(value.len())
			.or(Err(AgreementError::PayloadTooLong))?;

		let mut encoded = BytesMut::new();
		encoded.put(&session[..]);
		encoded.put_u16(COOKIE ^ keys.cookie);
		encoded.put_u8(length ^ keys.length);

		encoded.put(ChaCha20Poly1305::new(keys.aead)
			.encrypt(&keys.nonce, aead::Payload { msg: &value, aad: &session })
			.or(Err(AgreementError::EncryptionFailed))?
			.as_ref());

		Ok(encoded.freeze())
	}
}
