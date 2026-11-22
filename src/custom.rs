use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

pub const PORT_DEFAULT: Port = Port(51820);
pub const MTU_DEFAULT: Mtu = Mtu(1420);
pub const DNS_DEFAULT: &str = "8.8.8.8,1.1.1.1";

#[derive(Debug, Clone)]
pub struct Port(u16);

impl Port {
    pub fn new(port: i32) -> Result<Self, String> {
        if !(1024..=65535).contains(&port) {
            return Err("Port values must be within range 1024-65535".into());
        }
        Ok(Self(port as u16))
    }
}

impl FromStr for Port {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port: i32 = s.parse().map_err(|_| format!("Invalid port number: {s}"))?;

        Self::new(port)
    }
}

impl Display for Port {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct Mtu(u16);

impl Mtu {
    pub fn new(mtu: i32) -> Result<Self, String> {
        if !(1280..=1500).contains(&mtu) {
            return Err("MTU must be within range 1280-1500".into());
        }
        Ok(Self(mtu as u16))
    }
}

impl FromStr for Mtu {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mtu: i32 = s.parse().map_err(|_| format!("Invalid MTU value: {s}"))?;
        Self::new(mtu)
    }
}

impl Display for Mtu {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// Build an interface name after checking it is a safe single shell token.
    ///
    /// Accepts 1-15 characters from A-Z, a-z, 0-9, '.', '_', or '-' (Linux IFNAMSIZ).
    /// The allowlist excludes spaces and shell metacharacters, so the value cannot
    /// break out of its argument when wg-quick runs the firewall rules.
    pub fn new(name: &str) -> Result<Self, String> {
        let valid = !name.is_empty()
            && name.len() <= 15
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if valid {
            Ok(Self(name.to_string()))
        } else {
            Err(format!(
                "Invalid interface name {name:?}: use 1-15 characters \
                from A-Z, a-z, 0-9, '.', '_', or '-'"
            ))
        }
    }
}

impl FromStr for InterfaceName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Display for InterfaceName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerName(String);

impl PeerName {
    /// Build a peer name, rejecting control characters and pure numbers.
    ///
    /// Control characters could break a config line. A pure-number name is
    /// rejected because it collides with the one-based index that remove uses.
    pub fn new(name: &str) -> Result<Self, String> {
        if name.chars().any(|c| c.is_control()) {
            return Err("Peer name must not contain control characters".to_string());
        }
        if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            return Err("Peer name must not be a number".to_string());
        }
        Ok(Self(name.to_string()))
    }

    /// The name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PeerName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Display for PeerName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct DnsServers(String);

impl DnsServers {
    /// Build a DNS server list, validating each comma-separated entry is an IP address.
    pub fn new(dns: &str) -> Result<Self, String> {
        for entry in dns.split(',') {
            if entry.trim().parse::<std::net::IpAddr>().is_err() {
                return Err(format!(
                    "Invalid DNS server {entry:?}: expected an IP address"
                ));
            }
        }
        Ok(Self(dns.to_string()))
    }
}

impl FromStr for DnsServers {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Display for DnsServers {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
