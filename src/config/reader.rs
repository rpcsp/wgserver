use crate::config::Peer;
use crate::config::constants::{GROUP_INTERFACE, GROUP_PEER, KNOWN_GROUPS, LAST_PEER_MSG};
use crate::custom::{Mtu, Port};
use crate::{
    config::{ConfigError, ServerConfig},
    system,
};
use ipnet::IpNet;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use std::fs;

#[derive(Debug, Default)]
pub struct PartialServerConfig {
    path: String,
    ipv4: Option<Ipv4Net>,
    ipv6: Option<Ipv6Net>,
    listen_port: Option<Port>,
    mtu: Option<Mtu>,
    private_key: Option<String>,
    url: Option<String>,
    interface: Option<String>,
    post_up: Option<String>,
    post_down: Option<String>,
    peers: Vec<PartialPeer>,
    extra: Vec<String>,
    unrecognized_keys_and_groups: Vec<String>,
}

#[derive(Debug, Default)]
pub struct PartialPeer {
    name: Option<String>,
    public_key: Option<String>,
    preshared_key: Option<String>,
    ipv4: Option<Ipv4Net>,
    ipv6: Option<Ipv6Net>,
    extra: Vec<String>,
}

pub fn from_server_config_file(path: &str) -> Result<ServerConfig, ConfigError> {
    let content = fs::read_to_string(path).map_err(|e| ConfigError::Io {
        context: "Error reading config file".to_string(),
        path: path.to_string(),
        source: e,
    })?;
    from_server_config_content(&content, path)
}

pub fn from_server_config_content(content: &str, path: &str) -> Result<ServerConfig, ConfigError> {
    let mut group = String::new();
    let mut parsed = PartialServerConfig {
        path: path.to_string(),
        ..Default::default()
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse group names
        if let Some(s) = line.strip_prefix("[").and_then(|s| s.strip_suffix("]")) {
            group = s.trim().to_string();
            match group.as_str() {
                GROUP_INTERFACE => (),
                GROUP_PEER => parsed.peers.push(PartialPeer::default()),
                _ => {
                    parsed.extra.push(line.to_string());
                    parsed.unrecognized_keys_and_groups.push(group.to_string());
                }
            }
            continue;
        }

        // Store any attribute from unknown groups
        if !KNOWN_GROUPS.contains(&group.as_str()) {
            parsed.extra.push(line.to_string());
            continue;
        }

        // Store attributes that are not key/value pairs
        let Some((key, value)) = line.split_once('=') else {
            match group.as_str() {
                GROUP_INTERFACE => parsed.extra.push(line.to_string()),
                GROUP_PEER => {
                    let peer = parsed.peers.last_mut().expect(LAST_PEER_MSG);
                    peer.extra.push(line.to_string())
                }
                _ => (),
            };
            continue;
        };
        let (key, value) = (key.trim(), value.trim().to_string());
        match group.as_str() {
            GROUP_INTERFACE => parse_interface_attribute(&mut parsed, key, value)?,
            GROUP_PEER => parse_peer_attribute(&mut parsed, key, value)?,
            _ => (),
        };
    }
    if !parsed.unrecognized_keys_and_groups.is_empty() {
        let mut items = parsed.unrecognized_keys_and_groups.clone();
        items.sort();
        items.dedup();
        eprintln!(
            "Note: kept {} unrecognized group(s)/key(s) found: '{}'",
            items.len(),
            items.join("', '")
        );
    }
    partial_to_server_config(parsed)
}

/// Parser for attributes in the `[Interface]` group
fn parse_interface_attribute(
    parsed: &mut PartialServerConfig,
    key: &str,
    value: String,
) -> Result<(), ConfigError> {
    match key {
        "Address" => {
            let ips = value.split(",").map(|s| s.trim().parse::<IpNet>());
            for ip in ips {
                match ip {
                    Ok(IpNet::V4(ipv4)) => parsed.ipv4 = Some(ipv4),
                    Ok(IpNet::V6(ipv6)) => parsed.ipv6 = Some(ipv6),
                    Err(e) => {
                        return Err(ConfigError::Parsing(format!(
                            "Failed parsing IP address: {e}"
                        )));
                    }
                };
            }
        }
        "ListenPort" => {
            parsed.listen_port = Some(
                value
                    .parse()
                    .map_err(|e| ConfigError::Parsing(format!("Failed parsing port: {e}")))?,
            )
        }
        "MTU" => {
            parsed.mtu = Some(
                value
                    .parse()
                    .map_err(|e| ConfigError::Parsing(format!("Failed parsing MTU: {e}")))?,
            )
        }
        "PrivateKey" => parsed.private_key = Some(value),
        "PostUp" => parsed.post_up = Some(value),
        "PostDown" => parsed.post_down = Some(value),
        "# Endpoint" => parsed.url = Some(value),
        "# Url" => parsed.url = Some(value),
        _ => {
            parsed.extra.push(format!("{key} = {value}"));
            parsed.unrecognized_keys_and_groups.push(key.to_string());
        }
    };
    Ok(())
}

/// Parser for attributes in the `[Peer]` group
fn parse_peer_attribute(
    parsed: &mut PartialServerConfig,
    key: &str,
    value: String,
) -> Result<(), ConfigError> {
    let peer: &mut PartialPeer = parsed.peers.last_mut().expect(LAST_PEER_MSG);
    match key {
        "PublicKey" => peer.public_key = Some(value),
        "PresharedKey" => peer.preshared_key = Some(value),
        "AllowedIPs" => {
            for ip_str in value.split(",") {
                let ip: IpNet = ip_str.trim().parse().map_err(|e| {
                    ConfigError::Parsing(format!("Failed to parse IP address: {e}"))
                })?;
                match ip {
                    IpNet::V4(ip) => peer.ipv4 = Some(ip),
                    IpNet::V6(ip) => peer.ipv6 = Some(ip),
                }
            }
        }
        "# Name" => peer.name = Some(value),
        _ => {
            peer.extra.push(format!("{key} = {value}"));
            parsed.unrecognized_keys_and_groups.push(key.to_string());
        }
    };
    Ok(())
}

/// Return error if opt is None, or the actual value
fn required<T>(opt: Option<T>, msg: &str) -> Result<T, ConfigError> {
    opt.ok_or_else(|| ConfigError::Parsing(msg.to_string()))
}

/// Convert instance of PartialServerConfig into ServerConfig
fn partial_to_server_config(p: PartialServerConfig) -> Result<ServerConfig, ConfigError> {
    Ok(ServerConfig {
        path: p.path,
        ipv4: required(p.ipv4, "Config should contain an IPv4 address")?,
        ipv6: p.ipv6,
        listen_port: required(p.listen_port, "Config should contain 'ListenPort'")?,
        mtu: required(p.mtu, "Config should contain 'MTU'")?,
        private_key: required(p.private_key, "Config should contain 'PrivateKey'")?,
        url: required(p.url, "Config should contain 'Url'")?,
        interface: match p.interface {
            Some(i) => i,
            None => system::get_default_interface()?,
        },
        post_up: required(p.post_up, "Config should contain 'PostUp'")?,
        post_down: required(p.post_down, "Config should contain 'PostDown'")?,
        extra: p.extra,
        peers: p
            .peers
            .into_iter()
            .map(partial_to_peer)
            .collect::<Result<Vec<Peer>, ConfigError>>()?,
    })
}

/// Convert instance of PartialPeer into Peer
fn partial_to_peer(p: PartialPeer) -> Result<Peer, ConfigError> {
    Ok(Peer {
        name: p.name.unwrap_or_default(),
        public_key: required(p.public_key, "Peer must have a public key")?,
        preshared_key: required(p.preshared_key, "Peer must have a preshared key")?,
        ipv4: required(p.ipv4, "Peer must declare allowed IPv4 network")?,
        ipv6: p.ipv6,
        extra: p.extra,
    })
}
