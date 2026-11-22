use crate::config::constants::{GROUP_INTERFACE, GROUP_PEER};
use crate::config::{Peer, PeerConfig, address_list};
use crate::{
    config::{ConfigError, ServerConfig},
    system,
};
use ipnet::{Ipv4Net, Ipv6Net};

pub fn to_server_config_file(config: &ServerConfig) -> Result<(), ConfigError> {
    let content = to_server_config_content(config);
    system::write_config_file(&config.path, &content)
}

pub fn to_server_config_content(config: &ServerConfig) -> String {
    let mut content = String::new();

    let address = address_list(config.ipv4, config.ipv6);

    // Interface
    content.push_str(&format!("[{}]\n", GROUP_INTERFACE));
    content.push_str(&format!("Address = {}\n", address));
    content.push_str(&format!("ListenPort = {}\n", config.listen_port));
    content.push_str(&format!("MTU = {}\n", config.mtu));
    content.push_str(&format!("PrivateKey = {}\n", config.private_key));
    content.push_str(&format!("PostUp   = {}\n", config.post_up));
    content.push_str(&format!("PostDown = {}\n", config.post_down));

    // Comments
    if let Some(url) = &config.url {
        content.push_str(&format!("# Url = {}\n", url));
    }

    // Others
    for extra in &config.extra {
        if extra.starts_with('[') {
            content.push('\n');
        }
        content.push_str(&format!("{}\n", extra));
    }

    // Peers
    for peer in &config.peers {
        let (ipv4, ipv6) = peer.host_routes();

        content.push_str(&format!("\n[{}]\n", GROUP_PEER));
        content.push_str(&format!("# Name = {}\n", peer.name));
        content.push_str(&format!("PublicKey = {}\n", peer.public_key));
        content.push_str(&format!("PresharedKey = {}\n", peer.preshared_key));
        content.push_str(&format!("AllowedIPs = {}\n", address_list(ipv4, ipv6)));

        // Others
        for extra in &peer.extra {
            content.push_str(&format!("{}\n", extra));
        }
    }
    content
}

/// The peer's own addresses with the tunnel's prefix, as a client needs them.
fn client_addresses(
    peer: &Peer,
    server: &ServerConfig,
) -> Result<(Ipv4Net, Option<Ipv6Net>), ConfigError> {
    let ipv4 = Ipv4Net::new(peer.ipv4.addr(), server.ipv4.prefix_len())
        .map_err(|e| ConfigError::IpAddress(format!("IPv4 error: {e}")))?;
    let ipv6 = match (peer.ipv6, server.ipv6) {
        (Some(peer_ipv6), Some(server_ipv6)) => Some(
            Ipv6Net::new(peer_ipv6.addr(), server_ipv6.prefix_len())
                .map_err(|e| ConfigError::IpAddress(format!("IPv6 error: {e}")))?,
        ),
        (_, _) => None,
    };
    Ok((ipv4, ipv6))
}

pub fn to_client_config_content(peer_config: &PeerConfig) -> Result<String, ConfigError> {
    let mut content = String::new();
    let server = peer_config.server;
    let peer = peer_config.peer;

    let (ipv4, ipv6) = client_addresses(peer, server)?;
    let address = address_list(ipv4, ipv6);
    let allowed_ips = match (ipv6, peer_config.split_tunnel) {
        (Some(_), false) => "0.0.0.0/0, ::/0",
        (Some(_), true) => "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1",
        (None, false) => "0.0.0.0/0",
        (None, true) => "0.0.0.0/1, 128.0.0.0/1",
    };

    let url = server.url.as_deref().ok_or_else(|| {
        ConfigError::Parsing(
            "Server config has no 'Url'; cannot build the client 'Endpoint'".to_string(),
        )
    })?;
    let server_public_key = system::generate_key::public(&server.private_key)?;
    let server_endpoint = format!("{}:{}", url, server.listen_port);
    let preshared_key = &peer.preshared_key;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{test_peer, test_server};

    fn client_config<'a>(
        server: &'a ServerConfig,
        peer: &'a Peer,
        split_tunnel: bool,
    ) -> PeerConfig<'a> {
        PeerConfig {
            server,
            peer,
            private_key: "YFa6yVubpzmLEmvFREoGCSGe6y21Wz/dKbMLFTG5+Xk=".to_string(),
            dns: "8.8.8.8,1.1.1.1".parse().unwrap(),
            split_tunnel,
        }
    }

    #[test]
    fn client_addresses_take_the_tunnel_prefix() {
        let server = test_server();
        let (ipv4, ipv6) = client_addresses(&test_peer("a"), &server).unwrap();
        assert_eq!(address_list(ipv4, ipv6), "10.8.0.2/24, fd42::2/64");
    }

    #[test]
    fn client_addresses_drop_ipv6_without_an_ipv6_tunnel() {
        let mut server = test_server();
        server.ipv6 = None;
        let (ipv4, ipv6) = client_addresses(&test_peer("a"), &server).unwrap();
        assert_eq!(ipv4.to_string(), "10.8.0.2/24");
        assert_eq!(ipv6, None);
    }

    #[test]
    fn client_address_uses_the_tunnel_prefix_not_a_host_route() {
        let server = test_server();
        let peer = test_peer("alice");
        let content = to_client_config_content(&client_config(&server, &peer, false)).unwrap();
        assert!(
            content.contains("Address = 10.8.0.2/24, fd42::2/64"),
            "{content}"
        );
        assert!(
            content.contains("Endpoint = vpn.example.com:51820"),
            "{content}"
        );
        assert!(
            content.contains("AllowedIPs = 0.0.0.0/0, ::/0"),
            "{content}"
        );
    }

    #[test]
    fn split_tunnel_splits_the_default_route_in_half() {
        let server = test_server();
        let peer = test_peer("alice");
        let content = to_client_config_content(&client_config(&server, &peer, true)).unwrap();
        assert!(
            content.contains("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1"),
            "{content}"
        );
    }

    #[test]
    fn a_server_without_url_cannot_build_a_client() {
        let mut server = test_server();
        server.url = None;
        let peer = test_peer("alice");
        let error = to_client_config_content(&client_config(&server, &peer, false)).unwrap_err();
        assert!(error.to_string().contains("Url"), "{error}");
    }

    #[test]
    fn server_config_omits_the_url_comment_when_unknown() {
        let mut server = test_server();
        server.url = None;
        assert!(!to_server_config_content(&server).contains("# Url"));
    }
}
