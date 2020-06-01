use std::{convert::TryFrom, net::IpAddr, time::{UNIX_EPOCH, SystemTime}, mem, ptr};
use color_eyre::Result;
use serde::Serialize;
use packet::{ip::v4 as ip, Builder as _};
use bytes::{Buf, Bytes, BytesMut, BufMut};
use rand::{thread_rng, Rng};
use crate::{agreement::Agreement, command::*};

pub struct Knocker {
	agreement: Agreement,
}

impl Knocker {
	pub fn new(agreement: Agreement) -> Self {
		Knocker { agreement }
	}

	pub fn packets<T>(&self, value: &T, to: IpAddr) -> Result<Packets>
		where T: Serialize
	{
		Ok(Packets {
			to,
			id: thread_rng().gen(),
			seq: 0,
			buffer: self.agreement.encode(Bytes::from(bincode::serialize(value)?))?
		})
	}

	pub fn command(&self, cmd: &Command, to: IpAddr) -> Result<Packets> {
		match cmd {
			Command::Open(cmd) =>
				self.packets(&cmd, to),
		}
	}
}

pub struct Packets {
	to: IpAddr,
	id: u16,
	seq: u16,
	buffer: Bytes,
}

impl Packets {
	pub fn remaining(&self) -> usize {
		self.buffer.len() / 2
	}

	pub fn next(&mut self, at: SystemTime) -> Option<Bytes> {
		if self.buffer.is_empty() {
			return None;
		}

		match self.to {
			IpAddr::V4(dest) => {
				let duration = at.duration_since(UNIX_EPOCH).unwrap();

				let now = libc::timeval {
					tv_sec: i64::try_from(duration.as_secs()).unwrap(),
					tv_usec: i64::from(duration.subsec_micros()),
				};

				let mut payload = BytesMut::new();
				unsafe {
					payload.resize(mem::size_of_val(&now), 0);
					ptr::write_unaligned(payload.as_mut_ptr() as *mut _, now);
				}

				for i in 0x10 ..= 0x37 {
					payload.put_u8(i);
				}

				let packet = ip::Builder::default()
					.id(self.buffer.get_u16()).unwrap()
					.ttl(64).unwrap()
					.source([0, 0, 0, 0].into()).unwrap()
					.destination(dest).unwrap()
					.icmp().unwrap().echo().unwrap().request().unwrap()
						.identifier(self.id).unwrap()
						.sequence(self.seq).unwrap()
						.payload(payload.iter()).unwrap()
						.build().unwrap();

				self.seq += 1;

				Some(Bytes::from(packet))
			}

			IpAddr::V6(_ip) => {
				unimplemented!("IPv6 is currently not supported");
			}
		}
	}
}
