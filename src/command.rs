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

use std::{process, collections, time::Instant};
use twox_hash::RandomXxHashBuilder32;
use clap::Clap;
use serde::{Serialize, Deserialize};
use color_eyre::{eyre::eyre, Result};
use tracing;
use shellexpand;

type HashMap<K, V> = collections::HashMap<K, V, RandomXxHashBuilder32>;

#[derive(Clone, Serialize, Deserialize, Clap, Debug)]
pub enum Command {
	Open(Open),
	Close(Close),
}

#[derive(Clone, Copy, Serialize, Deserialize, Clap, Debug)]
pub struct Open {
	/// The port to open.
	#[clap(long, env)]
	port: u16,

	/// Duration to keep the port open for in minutes.
	#[clap(default_value = "1", long, env)]
	minutes: u8,
}

#[derive(Clone, Copy, Serialize, Deserialize, Clap, Debug)]
pub struct Close {
	/// The port to open.
	#[clap(long, env)]
	port: u16,
}

pub struct Handler {
	open: String,
	close: String,

	opened: HashMap<u16, Opened>,
}

#[derive(Debug)]
struct Opened {
	port: u16,
	at: Instant,
	minutes: u8,
	handle: String,
}

impl Handler {
	pub fn new(open: String, close: String) -> Self {
		Self {
			open, close,
			opened: Default::default(),
		}
	}

	pub fn handle(&mut self, command: Command) -> Result<()> {
		tracing::info!(?command);

		match command {
			Command::Open(open) => {
				if let Some(opened) = self.opened.get_mut(&open.port) {
					opened.at = Instant::now();
					opened.minutes = open.minutes;

					return Ok(());
				}

				let cmd = shellexpand::env_with_context_no_errors(&self.open, |var| {
					match var {
						"PORT" =>
							Some(format!("{}", open.port)),

						_ =>
							None
					}
				});

				let cmd = process::Command::new("sh")
					.arg("-c")
					.arg(cmd.as_ref())
					.output()?;

				if !cmd.status.success() {
					Err(eyre!("open command failed: {}", String::from_utf8_lossy(&cmd.stderr)))?
				}

				self.opened.insert(open.port, Opened {
					port: open.port,
					at: Instant::now(),
					minutes: open.minutes,
					handle: String::from_utf8_lossy(&cmd.stdout).trim().into(),
				});

				tracing::debug!(?self.opened);
			}

			Command::Close(close) => {
				if let Some(opened) = self.opened.remove(&close.port) {
					tracing::debug!(?self.opened);

					let cmd = shellexpand::env_with_context_no_errors(&self.close, |var| {
						match var {
							"PORT" =>
								Some(opened.port.to_string()),

							"HANDLE" =>
								Some(opened.handle.clone()),

							_ =>
								None
						}
					});

					let cmd = process::Command::new("sh")
						.arg("-c")
						.arg(cmd.as_ref())
						.output()?;

					if !cmd.status.success() {
						Err(eyre!("close command failed: {}", String::from_utf8_lossy(&cmd.stderr)))?
					}
				}
			}
		}

		Ok(())
	}
}
