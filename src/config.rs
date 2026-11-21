mod constants;
mod reader;
mod writer;

use crate::{
    cli,
    custom::{Mtu, Port},
    system,
};
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use std::{
    collections::HashSet,
    fmt, fs, io,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug)]
pub enum ConfigError {
    Io {
        context: String,
        path: String,
        source: io::Error,
    },
    AlreadyExists {
        path: String,
    },
    KeyGeneration(String),
    Parsing(String),
    RunCommand(String),
    IpAddress(String),
    Duplicated(String),
    NotFound(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io {
                context,
                path,
                source,
            } => write!(f, "{context} '{path}': {source}"),
            ConfigError::AlreadyExists { path } => write!(f, "Already exists: {path}"),
            ConfigError::KeyGeneration(msg) => write!(f, "Key generation failed: {msg}"),
            ConfigError::Parsing(msg) => write!(f, "{msg}"),
            ConfigError::RunCommand(msg) => write!(f, "{msg}"),
            ConfigError::IpAddress(msg) => write!(f, "{msg}"),
            ConfigError::Duplicated(s) => write!(f, "Already present: {s}"),
            ConfigError::NotFound(s) => write!(f, "Not found: {s}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::AlreadyExists { path: _ } => None,
            ConfigError::KeyGeneration(_) => None,
            ConfigError::Parsing(_) => None,
            ConfigError::RunCommand(_) => None,
            ConfigError::IpAddress(_) => None,
            ConfigError::Duplicated(_) => None,
            ConfigError::NotFound(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    name: String,
    public_key: String,
    preshared_key: String,
    ipv4: Ipv4Net,
    ipv6: Option<Ipv6Net>,
    extra: Vec<String>,
}

impl Peer {
    fn allow_ips(&self) -> String {
        match self.ipv6 {
            Some(ipv6) => format!("{}, {}", self.ipv4, ipv6),
            None => self.ipv4.to_string(),
        }
    }
}

pub struct PeerConfig<'a> {
    server: &'a ServerConfig,
    peer: &'a Peer,
    private_key: String,
    dns: String,
    split_tunnel: bool,
}

impl<'a> PeerConfig<'a> {
    pub fn file_content(&self) -> Result<String, ConfigError> {
        writer::to_client_config_content(self)
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    path: String,
    ipv4: Ipv4Net,
    ipv6: Option<Ipv6Net>,
    listen_port: Port,
    mtu: Mtu,
    private_key: String,
    url: String,
    pub interface: String,
    post_up: String,
    post_down: String,
    peers: Vec<Peer>,
    extra: Vec<String>,
}

impl ServerConfig {
    /// Check if the config file exists and is not empty
    pub fn non_empty_config_file_exists(path: &str) -> bool {
        if let Ok(metadata) = fs::metadata(path) {
            metadata.is_file() && metadata.len() > 0
        } else {
            false
        }
    }

    /// Return instance of ServerConfig based on CliInit and path provided
    fn from_cli(cli: cli::Init, path: String) -> Result<Self, ConfigError> {
        let interface = match cli.interface {
            Some(interface) => interface,
            None => system::get_default_interface()?,
        };
        let post_up = post_up(&interface, &cli.ipv4, &cli.ipv6, &cli.port);
        let post_down = post_down(&interface, &cli.ipv4, &cli.ipv6, &cli.port);
        Ok(Self {
            path,
            ipv4: cli.ipv4,
            ipv6: cli.ipv6,
            listen_port: cli.port,
            mtu: cli.mtu,
            private_key: system::generate_private_key()?,
            url: cli.url,
            interface,
            post_up,
            post_down,
            peers: vec![],
            extra: vec![],
        })
    }

    /// Attempt to create a brand new config file. Aborts if the file exists
    pub fn init(cli: cli::Init, path: &str) -> Result<ServerConfig, ConfigError> {
        let path = path.to_string();
        if !cli.overwrite && ServerConfig::non_empty_config_file_exists(&path) {
            return Err(ConfigError::AlreadyExists { path });
        };
        let config = ServerConfig::from_cli(cli, path)?;
        Ok(config)
    }

    /// Write settings to standard config file
    pub fn save(&self) -> Result<(), ConfigError> {
        writer::to_server_config_file(self)
    }

    /// Read the config file and return instance of ServerConfig
    pub fn load(path: &str) -> Result<ServerConfig, ConfigError> {
        reader::from_server_config_file(path)
    }

    pub fn file_content(&self) -> String {
        writer::to_server_config_content(self)
    }

    /// Add one new peer to server config
    pub fn add_peer(&mut self, cli: cli::Add) -> Result<String, ConfigError> {
        let names = self.peer_names();
        if names.contains(cli.name.as_str()) {
            if cli.overwrite {
                self.peers.retain(|p| p.name != cli.name);
            } else {
                return Err(ConfigError::Duplicated(cli.name));
            }
        }

        // New peer keys
        let private_key = system::generate_private_key()?;
        let public_key = system::generate_public_key(&private_key)?;
        let preshared_key = system::generate_preshared_key()?;

        // New IPs
        let ipv4 = self.next_ipv4()?;
        let ipv6 = self.next_ipv6()?;

        let peer = Peer {
            name: cli.name,
            public_key,
            preshared_key,
            ipv4,
            ipv6,
            extra: vec![],
        };
        self.peers.push(peer);

        let peer_config = PeerConfig {
            server: self,
            peer: self.peers.last().expect("New peer must be present"),
            private_key,
            dns: cli.dns,
            split_tunnel: cli.split_tunnel,
        };

        peer_config.file_content()
    }

    pub fn remove_peer(mut self, name: &str) -> Result<Self, ConfigError> {
        let original_count = self.peers.len();
        self.peers.retain(|p| p.name != name);

        // Find by name
        if self.peers.len() < original_count {
            return Ok(self);
        }
        // Find by index
        let index: usize = name
            .parse()
            .map_err(|_| ConfigError::NotFound(name.to_string()))?;
        if index > 0 && index <= self.peers.len() {
            self.peers.remove(index - 1);
            return Ok(self);
        };
        Err(ConfigError::NotFound(name.to_string()))
    }

    fn next_ipv4(&self) -> Result<Ipv4Net, ConfigError> {
        // Get list of know hosts
        let mut known_ips: HashSet<Ipv4Addr> = self.peers.iter().map(|p| p.ipv4.addr()).collect();
        known_ips.insert(self.ipv4.addr());

        // Identify the next available
        for ip in self.ipv4.hosts() {
            if !known_ips.contains(&ip) && ip > self.ipv4.addr() {
                return Ipv4Net::new(ip, self.ipv4.prefix_len())
                    .map_err(|e| ConfigError::IpAddress(format!("IP error: {e} exhausted")));
            }
        }
        Err(ConfigError::IpAddress(format!(
            "IP pool {} exhausted",
            self.ipv4.trunc()
        )))
    }

    fn next_ipv6(&self) -> Result<Option<Ipv6Net>, ConfigError> {
        match self.ipv6 {
            Some(ipv6) => {
                let mut known_ips: HashSet<Ipv6Addr> = self
                    .peers
                    .iter()
                    .filter_map(|p| p.ipv6)
                    .map(|ip| ip.addr())
                    .collect();
                known_ips.insert(ipv6.addr());

                // Get list of know hosts
                for ip in ipv6.hosts() {
                    if !known_ips.contains(&ip) && ip > ipv6.addr() {
                        let ip = Ipv6Net::new(ip, ipv6.prefix_len()).map_err(|e| {
                            ConfigError::IpAddress(format!("IP error: {e} exhausted"))
                        })?;
                        return Ok(Some(ip));
                    }
                }
                Err(ConfigError::IpAddress(format!(
                    "IP pool {} exhausted",
                    self.ipv4.trunc()
                )))
            }
            None => Ok(None),
        }
    }

    // Return list of peer names present in the config
    fn peer_names(&self) -> HashSet<&str> {
        self.peers.iter().map(|p| p.name.as_str()).collect()
    }

    /// Print all peers with index, name and allowed IPs
    pub fn print_peers(&self) {
        println!("List of peers - {} item(s):", self.peers.len());
        for (index, peer) in self.peers.iter().enumerate() {
            if peer.name.is_empty() {
                println!("\n## Index: {}", index + 1);
            } else {
                println!("\n## Index: {} - Name: {} ", index + 1, peer.name);
            }
            println!("   allowed IPs: {}", peer.allow_ips());
        }
    }
}

/// Firewall rules applied when the interface comes up
/// The post_up rules are inserted at position 1 to take effect before any existing rule
/// Includes extra spaces to align with PostDown
fn post_up(
    interface: &str,
    ipv4_network: &Ipv4Net,
    ipv6_network: &Option<Ipv6Net>,
    port: &Port,
) -> String {
    let ipv4_network = ipv4_network.trunc();
    let mut rules = format!(
        "iptables -I FORWARD 1 -i %i -o {interface} -j ACCEPT; \
         iptables -I FORWARD 1 -i {interface} -o %i -j ACCEPT; \
         iptables -t nat -I POSTROUTING 1 -s {ipv4_network} -o {interface} -j MASQUERADE; \
         iptables -I INPUT 1 -i %i -j ACCEPT; \
         iptables -I INPUT 1 -p udp -m udp --dport {port} -j ACCEPT"
    );

    if let Some(ipv6_network) = ipv6_network {
        let ipv6_network = ipv6_network.trunc();
        rules.push_str(&format!(
            "; ip6tables -I FORWARD 1 -i %i -o {interface} -j ACCEPT; \
             ip6tables -I FORWARD 1 -i {interface} -o %i -j ACCEPT; \
             ip6tables -t nat -I POSTROUTING 1 -s {ipv6_network} -o {interface} -j MASQUERADE; \
             ip6tables -I INPUT 1 -i %i -j ACCEPT; \
             ip6tables -I INPUT 1 -p udp -m udp --dport {port} -j ACCEPT"
        ));
    }

    rules
}

/// Must mirror post_up, removing what was added.
/// Includes extra spaces to align with PostUp
fn post_down(
    interface: &str,
    ipv4_network: &Ipv4Net,
    ipv6_network: &Option<Ipv6Net>,
    port: &Port,
) -> String {
    let ipv4_network = ipv4_network.trunc();
    let mut rules = format!(
        "iptables -D FORWARD   -i %i -o {interface} -j ACCEPT; \
         iptables -D FORWARD   -i {interface} -o %i -j ACCEPT; \
         iptables -t nat -D POSTROUTING   -s {ipv4_network} -o {interface} -j MASQUERADE; \
         iptables -D INPUT   -i %i -j ACCEPT; \
         iptables -D INPUT   -p udp -m udp --dport {port} -j ACCEPT"
    );

    if let Some(ipv6_network) = ipv6_network {
        let ipv6_network = ipv6_network.trunc();
        rules.push_str(&format!(
            "; ip6tables -D FORWARD   -i %i -o {interface} -j ACCEPT; \
             ip6tables -D FORWARD   -i {interface} -o %i -j ACCEPT; \
             ip6tables -t nat -D POSTROUTING   -s {ipv6_network} -o {interface} -j MASQUERADE; \
             ip6tables -D INPUT   -i %i -j ACCEPT; \
             ip6tables -D INPUT   -p udp -m udp --dport {port} -j ACCEPT"
        ));
    }

    rules
}
