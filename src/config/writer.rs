use crate::config::PeerConfig;
use crate::config::constants::{GROUP_INTERFACE, GROUP_PEER};
use crate::{
    config::{ConfigError, ServerConfig},
    system,
};

pub fn to_server_config_file(config: &ServerConfig) -> Result<(), ConfigError> {
    let content = to_server_config_content(config);
    system::write_config_file(&config.path, &content)
}

pub fn to_server_config_content(config: &ServerConfig) -> String {
    let mut content = String::new();

    let address = match config.ipv6 {
        Some(ipv6) => format!("{}, {}", config.ipv4, ipv6),
        None => format!("{}", config.ipv4),
    };

    // Interface
    content.push_str(&format!("[{}]\n", GROUP_INTERFACE));
    content.push_str(&format!("Address = {}\n", address));
    content.push_str(&format!("ListenPort = {}\n", config.listen_port));
    content.push_str(&format!("MTU = {}\n", config.mtu));
    content.push_str(&format!("PrivateKey = {}\n", config.private_key));
    content.push_str(&format!("PostUp   = {}\n", config.post_up));
    content.push_str(&format!("PostDown = {}\n", config.post_down));

    // Comments
    content.push_str(&format!("# Url = {}\n", config.url));

    // Others
    for extra in &config.extra {
        if extra.starts_with('[') {
            content.push('\n');
        }
        content.push_str(&format!("{}\n", extra));
    }

    // Peers
    for peer in &config.peers {
        content.push_str(&format!("\n[{}]\n", GROUP_PEER));
        content.push_str(&format!("# Name = {}\n", peer.name));
        content.push_str(&format!("PublicKey = {}\n", peer.public_key));
        content.push_str(&format!("PresharedKey = {}\n", peer.preshared_key));
        content.push_str(&format!("AllowedIPs = {}\n", peer.allow_ips()));

        // Others
        for extra in &peer.extra {
            content.push_str(&format!("{}\n", extra));
        }
    }
    content
}

pub fn to_client_config_content<'a>(peer_config: &'a PeerConfig) -> Result<String, ConfigError> {
    let mut content = String::new();

    let address = match peer_config.peer.ipv6 {
        Some(ipv6) => format!("{}, {}", peer_config.peer.ipv4, ipv6),
        None => format!("{}", peer_config.peer.ipv4),
    };
    let allowed_ips = match (peer_config.peer.ipv6, peer_config.split_tunnel) {
        (Some(_), false) => "0.0.0.0/0, ::/0",
        (Some(_), true) => "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1",
        (None, false) => "0.0.0.0/0",
        (None, true) => "0.0.0.0/1, 128.0.0.0/1",
    };

    let server_config = peer_config.server;
    let server_public_key = system::generate_public_key(&server_config.private_key)?;
    let server_endpoint = format!("{}:{}", server_config.url, server_config.listen_port);
    let preshared_key = &peer_config.peer.preshared_key;

    // Client side config
    content.push_str(&format!("[{}]\n", GROUP_INTERFACE));
    content.push_str(&format!("Address = {}\n", address));
    content.push_str(&format!("DNS = {}\n", peer_config.dns));
    content.push_str(&format!("PrivateKey = {}\n", peer_config.private_key));

    content.push_str(&format!("\n[{}]\n", GROUP_PEER));
    content.push_str(&format!("Endpoint = {}\n", server_endpoint));
    content.push_str(&format!("AllowedIPs = {}\n", allowed_ips));
    content.push_str(&format!("PresharedKey = {}\n", preshared_key));
    content.push_str(&format!("PublicKey = {}\n", server_public_key));

    Ok(content)
}
