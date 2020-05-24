use std::{collections::VecDeque, net::IpAddr, convert::TryFrom};
use color_eyre::Result;
use thiserror::Error;
use serde::Serialize;
use packet::{ip::v4 as ip, icmp::echo, Packet as _, Builder as _};
use bytes::{Buf, Bytes};
use crate::agreement::Agreement;

pub struct Knocker {
	agreement: Agreement,

	src: IpAddr,
	dest: IpAddr,
}

#[derive(Error, Debug)]
pub enum KnockerError {
	#[error("the source and destination addresses are not the same type")]
	MismatchedAddresses,
}

impl Knocker {
	pub fn new(agreement: Agreement, src: IpAddr, dest: IpAddr) -> Self {
		Knocker { agreement, src, dest }
	}

	pub fn send<T>(&self, value: &T) -> Result<VecDeque<Bytes>>
		where T: Serialize
	{
		let encoded = self.agreement.encode(Bytes::from(bincode::serialize(value)?))?;

		let packets = match self.src {
			IpAddr::V4(src) => {
				let dest = match self.dest {
					IpAddr::V4(dest) => dest,
					IpAddr::V6(_) => Err(KnockerError::MismatchedAddresses)?,
				};

				// TODO(meh): reproduce iputils behavior for maximum stealth

				encoded.as_ref().chunks(2).enumerate().map(|(seq, mut b)| {
					Ok(Bytes::from(ip::Builder::default()
						.id(b.get_u16())?
						.ttl(64)?
						.source(src)?
						.destination(dest)?
						.icmp()?.echo()?.request()?
							.identifier(42)?
							.sequence(u16::try_from(seq)?)?
							.build()?))
				}).collect::<Result<_>>()?
			}

			IpAddr::V6(_ip) => {
				unimplemented!("IPv6 is currently not supported");
			}
		};

		Ok(packets)
	}
}
