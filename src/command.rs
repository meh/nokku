use clap::Clap;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Clap, Debug)]
pub enum Command {
	Open(Open)
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
