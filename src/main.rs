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

use std::{time::{Duration, Instant}, net::{SocketAddr, IpAddr}, io, convert::TryInto, thread, task::Poll, time::SystemTime};
use indicatif::{ProgressBar, ProgressStyle};
use clap::Clap;
use color_eyre::Result;
use rand::{thread_rng, Rng};
use thiserror::Error;
use tracing;
use socket::Socket;

mod agreement;
mod command;
mod observer;
mod knocker;

use agreement::Agreement;
use observer::{Observer, ObserverError};
use knocker::Knocker;

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
		#[clap(required = true, short = "P", long, env)]
		public_key: String,

		/// The observer's private key.
		#[clap(required = true, short = "p", long, env)]
		private_key: String,
	},

	/// Send a knock.
	Knock {
		#[clap(short, long)]
		interface: Option<String>,

		/// The public key of the observer.
		#[clap(required = true, short = "P", long, env)]
		public_key: String,

		/// Your private key.
		#[clap(required = true, short = "p", long, env)]
		private_key: String,

		/// Whether to add padding packets or not; slows down the transfer but
		/// makes it harder to find.
		#[clap(long, env, parse(from_occurrences))]
		padding: u8,

		/// Number of milliseconds to wait between each packet.
		#[clap(default_value = "1000", long, env)]
		interval: u16,

		/// The host of the observer.
		#[clap(env)]
		host: IpAddr,

		#[clap(subcommand)]
		command: command::Command,
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

	#[error("no valid socket was able to be created")]
	InvalidSocket,
}

fn main() -> Result<()> {
	tracing_subscriber::fmt::init();
	color_backtrace::install();
	let args = Args::parse();

	match args.command {
		Command::Observe { interface, private_key, public_key } => {
			let socket = socket(interface.as_ref().map(AsRef::as_ref), libc::IPPROTO_ICMP.into())?;
			let mut observer = Observer::new(Agreement::new(&private_key, &public_key)?);

			loop {
				let mut buffer = [0u8; 1500];
				let (size, addr) = socket.recv_from(&mut buffer)?;
				let buffer = &buffer[..size];

				match observer.receive::<command::Command>(addr.as_std().unwrap().ip(), buffer, Instant::now()) {
					Ok(Poll::Pending) => (),

					Ok(Poll::Ready(request)) => {
						tracing::debug!(?request);
					}

					Err(err) if err.is::<ObserverError>() => {
						match err.downcast_ref::<ObserverError>().unwrap() {
							ObserverError::NonceReused => {
								tracing::error!("nonce reuse warning not yet implemented");
								continue;
							}

							ObserverError::InvalidPacket |
							ObserverError::StreamClosed =>
								continue
						}
					}

					Err(err) => {
						tracing::error!("packet parsing failed: {}", err);
					}
				}
			}
		}

		Command::Knock {
			interval, padding,
			interface, private_key, public_key,
			host, command
		} => {
			let socket = socket(interface.as_ref().map(AsRef::as_ref), libc::IPPROTO_RAW.into())?;
			let addr: SocketAddr = (host, 0).into();
			let knocker = Knocker::new(Agreement::new(&private_key, &public_key)?);
			let mut packets = knocker.command(&command, host)?;
			let length = packets.remaining();

			// Send payload ICMP packets.
			{
				let progress = ProgressBar::new(length.try_into().unwrap())
					.with_style(ProgressStyle::default_bar()
						.template("[{elapsed_precise}] {bar:40.red/darkgray} {pos:>7}/{len:7}"));

				progress.println(format!("Sending ICMP packets to {}", addr.ip()));

				while let Some(packet) = packets.next(SystemTime::now()) {
					socket.send_to(&packet, &addr.into())?;
					progress.inc(1);
					thread::sleep(Duration::from_millis(interval.into()));
				}

				progress.finish_with_message("Done!");
				length
			};

			// Send padding ICMP packets.
			for _ in 0 .. padding {
				let length = length % thread_rng().gen_range(0,
					1 + ((50.0 * length as f32) / 100.0).ceil() as usize);

				let progress = ProgressBar::new(length.try_into().unwrap())
					.with_style(ProgressStyle::default_bar()
						.template("[{elapsed_precise}] {bar:40.red/darkgray} {pos:>7}/{len:7}"));

				println!();
				progress.println(format!("Sending ICMP random padding to {}", addr.ip()));

				for _ in 0 .. length {
					socket.send_to(&packets.padding(SystemTime::now()), &addr.into())?;
					progress.inc(1);
					thread::sleep(Duration::from_millis(interval.into()));
				}

				progress.finish_with_message("Done!");
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

fn socket(interface: Option<&str>, protocol: socket::Protocol) -> Result<Socket> {
	use std::{ffi::CString, os::unix::io::AsRawFd};

	let interface = if let Some(interface) = interface {
		get_if_addrs::get_if_addrs()?.into_iter()
			.find(|iface| iface.name == interface)
	}
	else {
		get_if_addrs::get_if_addrs()?.into_iter()
			.find(|iface| !iface.is_loopback())
	};

	let socket = Socket::new(socket::Domain::ipv4(), socket::Type::raw(), Some(protocol))?;

	if let Some(interface) = interface {
		unsafe {
			let interface: CString = CString::new(interface.name)?;

			if libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
				interface.as_ptr() as *const _, interface.as_bytes_with_nul().len() as libc::socklen_t) < 0
			{
				Err(MainError::InvalidSocket)?
			}
		}
	}

	Ok(socket)
}
