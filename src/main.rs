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

use std::{time::{Duration, Instant}, net::IpAddr, io, convert::TryInto, thread, task::Poll};
use clap::Clap;
use color_eyre::Result;
use thiserror::Error;
use datalink::Channel::Ethernet;
use serde::{Serialize, Deserialize};
use bytes::BufMut;
use packet::{ip::{Protocol, v4 as ip}, icmp, AsPacket as _, Packet as _};
use tracing;

#[derive(Clap, Debug)]
struct Args {
	#[clap(subcommand)]
	command: Command,
}

#[derive(Clap, Debug)]
enum Command {
	/// Start watching for knocks.
	Observe {
		#[clap(short, long)]
		interface: Option<String>,

		/// The public key of the client.
		#[clap(required = true, short = "P", long)]
		public_key: String,

		/// The observer's private key.
		#[clap(required = true, short = "p", long)]
		private_key: String,
	},

	/// Send a knock.
	Knock {
		#[clap(short, long)]
		interface: Option<String>,

		/// The public key of the observer.
		#[clap(required = true, short = "P", long)]
		public_key: String,

		/// Your private key.
		#[clap(required = true, short = "p", long)]
		private_key: String,

		/// Duration to keep the port open for in minutes.
		#[clap(default_value = "1", short, long)]
		duration: u8,

		/// The host of the observer.
		host: IpAddr,

		/// The port to open.
		port: u16,
	},

	/// Generate a private key.
	GenKey,

	/// Generate a public key from a private key.
	PubKey,
}

#[derive(Error, Debug)]
pub enum MainError {
	#[error("no valid interface could be found")]
	InvalidInterface,

	#[error("no valid channel could be found")]
	InvalidChannel,
}

mod agreement;
use agreement::Agreement;

mod observer;
use observer::{Observer, ObserverError};

mod knocker;
use knocker::Knocker;

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
struct OpenPort {
	port: u16,
	duration: u8,
}

fn main() -> Result<()> {
	tracing_subscriber::fmt::init();
	color_backtrace::install();
	let args = Args::parse();

	match args.command {
		Command::Observe { interface, private_key, public_key } => {
			let (_iff, (mut tx, mut rx)) = channel(interface.as_ref())?;
			let mut observer = Observer::new(Agreement::new(&private_key, &public_key)?);

			loop {
				let buffer = match rx.next() {
					Ok(buffer) => buffer,
					Err(err) => {
						tracing::error!("packet reception failed: {}", err);
						continue;
					}
				};

				let ip: ip::Packet<_> = match buffer.as_packet() {
					Ok(packet) => packet,
					Err(err) => continue
				};

				if ip.protocol() != Protocol::Icmp {
					continue;
				}

				let buffer = ip.payload();
				let icmp: icmp::Packet<_> = match buffer.as_packet() {
					Ok(packet) => packet,
					Err(_) => continue,
				};

				if let Ok(echo) = icmp.echo() {
					if !echo.is_request() {
						continue;
					}

					let mut data = [0u8; 2];
					(&mut data[..]).put_u16(ip.id());

					match observer.receive::<OpenPort>(ip.source().into(), data, Instant::now()) {
						Ok(Poll::Pending) => (),

						Ok(Poll::Ready(request)) => {
							tracing::debug!(?request);
						}

						Err(err) if err.is::<ObserverError>() => {
							match err.downcast_ref::<ObserverError>().unwrap() {
								ObserverError::NonceReused => {
									todo!("send a double reply to mark to retry");
								}
							}
						}
						
						Err(err) => {
							tracing::error!("packet parsing failed: {}", err);
						}
					}
				}
			}
		}

		Command::Knock { interface, private_key, public_key, host, port, duration } => {
			let (iff, (mut tx, _rx)) = channel(interface.as_ref())?;
			let knocker = Knocker::new(Agreement::new(&private_key, &public_key)?,
				iff.ips[0].ip(), host);

			let packets = knocker.send(&OpenPort { port, duration })?;
			for packet in packets {
				thread::sleep(Duration::from_secs(1));
				tx.send_to(packet.as_ref(), None);
			}
		}

		Command::GenKey => {
			let key = x25519::StaticSecret::new(&mut rand::thread_rng());
			println!("{}", base64::encode_config(&key.to_bytes(), base64::CRYPT));
		}

		Command::PubKey => {
			let mut key = String::new();
			io::stdin().read_line(&mut key)?;

			let key = base64::decode_config(key.trim(), base64::CRYPT)?;
			let key: [u8; 32] = key.as_slice().try_into()?;
			let key = x25519::StaticSecret::from(key);
			let key = x25519::PublicKey::from(&key);
			println!("{}", base64::encode_config(key.as_bytes(), base64::CRYPT));
		}
	}

	Ok(())
}

fn channel(name: Option<&String>) -> Result<(datalink::NetworkInterface, (Box<dyn datalink::DataLinkSender>, Box<dyn datalink::DataLinkReceiver>))> {
	let interface = datalink::interfaces().into_iter()
		.filter(|e| e.is_up() && !e.is_loopback() && e.ips.len() > 0 &&
			Some(&e.name) == name)
		.next().ok_or(MainError::InvalidInterface)?;

	if let Ethernet(tx, rx) = datalink::channel(&interface, Default::default())? {
		tracing::debug!("got interface\n{}", interface);

		Ok((interface, (tx, rx)))
	}
	else {
		Err(MainError::InvalidChannel)?
	}
}
