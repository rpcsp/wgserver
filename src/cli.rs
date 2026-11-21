use crate::custom::DNS_DEFAULT;
use crate::custom::{MTU_DEFAULT, Mtu, PORT_DEFAULT, Port};
use clap::Parser;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    /// Action to be executed
    #[command(subcommand)]
    pub action: Action,

    /// Target configuration file
    #[arg(short, long, default_value = "/etc/wireguard/wg0.conf")]
    pub config: String,
}

#[derive(clap::Subcommand, Debug)]
pub enum Action {
    /// Initialize wireguard configuration file
    Init(Init),

    /// Add client to the server
    Add(Add),

    /// Remove client from the server
    Remove(Remove),

    /// Show the current server configuration
    Print,

    /// Shows the parsed configuration, for testing
    Parsed,

    /// List clients configured on the server
    List,

    /// Restart wireguard service on this server
    Restart,

    /// Shows current status of the wireguard service
    Status,
}

#[derive(clap::Args, Debug)]
pub struct Init {
    /// Public domain or IP address connect to, e.g. vpn.example.com
    pub url: String,

    /// Tunnel ipv4 address/mask for the server
    #[arg(short = '4', long = "ipv4", default_value_t = Ipv4Net::from_str("10.8.0.1/24").unwrap())]
    pub ipv4: Ipv4Net,

    /// Tunnel ipv6 address/mask for the server, e.g. fd42:abcd::1/64
    #[arg(short = '6', long = "ipv6", default_value = None)]
    pub ipv6: Option<Ipv6Net>,

    /// UDP port to listen on (1024-65535)
    #[arg(short, long, default_value_t = PORT_DEFAULT)]
    pub port: Port,

    /// Tunnel MTU (1280-1500)
    #[arg(long, default_value_t = MTU_DEFAULT)]
    pub mtu: Mtu,

    /// Uplink interface to NAT through (default: the one with the default route)
    #[arg(short, long, default_value = None)]
    pub interface: Option<String>,

    /// Replace an existing config file instead of refusing
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(clap::Args, Debug)]
pub struct Add {
    /// Name of the new user
    pub name: String,

    /// DNS servers for this user, comma separated
    #[arg(long, default_value = DNS_DEFAULT)]
    pub dns: String,

    /// Allow local LAN traffic
    #[arg(long)]
    pub split_tunnel: bool,

    /// Replace an existing peer instead of refusing
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(clap::Args, Debug)]
pub struct Remove {
    /// Name of the user (or its index) to remove
    pub name: String,
}
