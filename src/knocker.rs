use std::{collections::VecDeque, net::IpAddr, convert::TryFrom};
use color_eyre::Result;
use serde::Serialize;
use packet::{ip::v4 as ip, Builder as _};
use bytes::{Buf, Bytes};
use crate::agreement::Agreement;

pub struct Knocker {
	agreement: Agreement,
}

impl Knocker {
	pub fn new(agreement: Agreement) -> Self {
		Knocker { agreement }
	}

	pub fn send<T>(&self, value: &T, dest: IpAddr) -> Result<VecDeque<Bytes>>
		where T: Serialize
	{
		let encoded = self.agreement.encode(Bytes::from(bincode::serialize(value)?))?;

		let packets = match dest {
			IpAddr::V4(dest) => {
				// TODO(meh): reproduce iputils behavior for maximum stealth

				encoded.as_ref().chunks(2).enumerate().map(|(seq, mut b)| {
					Ok(Bytes::from(ip::Builder::default()
						.id(b.get_u16())?
						.ttl(64)?
						.source([0, 0, 0, 0].into())?
						.destination(dest)?
						.icmp()?.echo()?.request()?
							.identifier(42)?
							.sequence(u16::try_from(seq)?)?
							.payload(b"000000000000")?
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
