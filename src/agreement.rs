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

use std::{task::Poll, convert::{TryInto, TryFrom}};
use color_eyre::Result;
use base64;
use rand::prelude::*;
use thiserror::Error;
use x25519::{StaticSecret, PublicKey, SharedSecret};
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
	pub session: [u8; 4],
	pub data: Bytes,
}

pub const NONCE_LENGTH: usize = 4;
pub const HEADER_LENGTH: usize = 2 + 1;
pub const MAC_LENGTH: usize = 16;

pub const MIN_LENGTH: usize = NONCE_LENGTH + HEADER_LENGTH + MAC_LENGTH;
pub const MAX_LENGTH: usize = NONCE_LENGTH + HEADER_LENGTH + MAC_LENGTH + u8::MAX as usize;

pub const COOKIE: u16 = 0x1337;

impl Agreement {
	pub fn new(me: &str, peer: &str) -> Result<Self> {
		let private_key = base64::decode_config(me, base64::CRYPT)?;
		let public_key = base64::decode_config(peer, base64::CRYPT)?;

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

	fn derive(&self, nonce: Option<&[u8]>) -> (u8, GenericArray<u8, N::U32>, GenericArray<u8, N::U12>) {
		let key = Hkdf::<Sha512>::extract(nonce, self.secret.as_bytes()).0;

		let (length, rest) = key.as_slice().split_at(1);
		let (aead, rest) = rest.split_at(32);
		let (nonce, _rest) = rest.split_at(12);

		(length[0], GenericArray::clone_from_slice(aead), GenericArray::clone_from_slice(nonce))
	}

	pub fn decode(&self, mut buffer: Bytes) -> Result<Poll<(Payload, Bytes)>> {
		if buffer.len() < MIN_LENGTH {
			return Ok(Poll::Pending);
		}

		let session: [u8; 4] = (&buffer[..4]).try_into()?;
		let keys = self.derive(Some(&session[..]));

		// The length is encrypted as well to not have a constant part in the
		// stream that would make it obvious something is happening.
		let length   = buffer[4] ^ keys.0;
		let payload  = length as usize + 2 + <ChaCha20Poly1305 as Aead>::TagSize::to_usize();
		let mut data = buffer.split_off(5);

		if data.len() < payload {
			return Ok(Poll::Pending);
		}

		let rest = data.split_off(payload);

		let mut plaintext = Bytes::from(ChaCha20Poly1305::new(keys.1)
			.decrypt(&keys.2, aead::Payload { msg: data.as_ref(), aad: &session })
			.or(Err(AgreementError::DecryptionFailed))?);

		if plaintext.get_u16() != COOKIE {
			Err(AgreementError::InvalidCookie)?
		}

		Ok(Poll::Ready((Payload { session, data: plaintext }, rest)))
	}

	pub fn encode(&self, value: Bytes) -> Result<Bytes> {
		let mut encoded = BytesMut::new();

		let session: [u8; 4] = rand::thread_rng().gen();
		let keys = self.derive(Some(&session[..]));

		let length = u8::try_from(value.len()).or(Err(AgreementError::PayloadTooLong))?;
		encoded.put(&session[..]);
		encoded.put_u8(length ^ keys.0);

		let mut plaintext = BytesMut::new();
		plaintext.put_u16(0x1337);
		plaintext.put(value.as_ref());

		encoded.put(ChaCha20Poly1305::new(keys.1)
			.encrypt(&keys.2, aead::Payload { msg: &plaintext, aad: &session })
			.or(Err(AgreementError::EncryptionFailed))?
			.as_ref());

		Ok(encoded.freeze())
	}
}
