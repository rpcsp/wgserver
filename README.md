# wgserver

`wgserver` is a command-line tool for setting up and managing a WireGuard VPN server on Linux.

It handles the configuration tasks that would otherwise require manually editing WireGuard configuration files, generating keys, assigning peer addresses, and configuring network forwarding. It can initialize a server, add and remove clients, manage the WireGuard systemd service, and generate client configurations ready to import into the official WireGuard applications.

The tool is written in Rust and produces a single executable.

## Features

- Initialize a WireGuard server configuration with sensible defaults.
- Generate server and peer keys using `wg`.
- Add and remove peers without manually editing the server configuration.
- Automatically assign available IPv4 and, optionally, IPv6 addresses to new peers.
- Generate complete client configuration files, including DNS and routing settings.
- Print client configurations as QR codes for convenient import into mobile devices.
- Generate `PostUp` and `PostDown` rules for firewall configuration, NAT, and packet forwarding.
- Enable and persist IPv4 and IPv6 forwarding through `sysctl`.
- Enable and manage the WireGuard `wg-quick` systemd service.
- Support IPv4-only and dual-stack configurations.

## Requirements

`wgserver` is intended for Linux systems using WireGuard, systemd, and the standard Linux networking tools.

The following software must be installed:

- `wireguard-tools` (`wg` and `wg-quick`)
- `systemd`
- `iproute2` (`ip`)
- `iptables` and `ip6tables`
- `sysctl`

Root privileges are required for operations that modify system configuration, firewall rules, or network interfaces.

To build from source, you will also need Rust stable (edition 2024).

## Installation

### Build from source

```bash
git clone https://github.com/rpcsp/wgserver.git
cd wgserver
cargo build --release
```

Install the executable:

```bash
sudo install -m 755 target/release/wgserver /usr/local/bin/wgserver
```

### Install using Cargo

Alternatively:

```bash
cargo install --git https://github.com/rpcsp/wgserver.git
```

### Prebuilt binaries

Prebuilt Linux binaries are published with each [GitHub Release](https://github.com/rpcsp/wgserver/releases).

| Binary | Platform | Notes |
|---|---|---|
| `wgserver-linux-x64` | Linux x86_64 | 64-bit Linux |
| `wgserver-linux-armv7` | Linux ARMv7 (32-bit, hard-float) | Standard build |
| `wgserver-linux-armv7-glibc228` | Linux ARMv7 (32-bit, hard-float) | Compatible with glibc 2.28 and newer |

The ARMv7 glibc 2.28 build is intended for older distributions, including Raspberry Pi OS Buster.

Download the appropriate binary from the [latest release](https://github.com/rpcsp/wgserver/releases/latest). SHA-256 checksums are provided in `SHA256SUMS`.

## Usage

All commands accept the `-c` or `--config` option to specify the WireGuard configuration file.

By default, the configuration file is `/etc/wireguard/wg0.conf`. The tunnel name is derived from the filename, so `wg0.conf` corresponds to the `wg0` interface and the `wg-quick@wg0.service` systemd unit.

Most commands that modify the server configuration or system settings must be run as root.

### Initialize a server

Create a new WireGuard server configuration:

```bash
sudo wgserver init vpn.example.com
```

By default, this creates a configuration with:

| Setting | Default |
|---|---|
| Server IPv4 address | `10.8.0.1/24` |
| Listen port | `51820` |
| MTU | `1420` |
| DNS servers | `8.8.8.8,1.1.1.1` |
| Uplink interface | Automatically detected from the default route |

The command generates the server's private and public keys and writes the initial configuration.

An existing non-empty configuration file is not overwritten unless `--overwrite` is specified.

Additional options can be supplied when initializing the server:

```bash
sudo wgserver init vpn.example.com \
    --ipv4 10.8.0.1/24 \
    --ipv6 fd42:abcd::1/64 \
    --port 51820 \
    --mtu 1420 \
    --interface eth0
```

IPv6 is optional. When configured, the server and clients are assigned IPv6 addresses as well.

The generated configuration includes `PostUp` and `PostDown` rules for configuring firewall access, packet forwarding, and NAT. These rules are executed by `wg-quick` when the tunnel starts and stops.

### Add a client

Add a new peer:

```bash
sudo wgserver add alice
```

The command generates a key pair and preshared key, assigns the next available tunnel addresses, and adds the peer to the server configuration.

A complete client configuration is printed to standard output. A QR code representing the same configuration is printed to standard error.

This makes it possible to save the configuration directly to a file without including the QR code:

```bash
sudo wgserver add alice > alice.conf
```

The resulting file can be imported directly into the WireGuard application.

Additional options are available.

**Specify DNS servers:**

```bash
sudo wgserver add alice --dns 9.9.9.9,1.1.1.1
```

**Enable split tunnelling:**

```bash
sudo wgserver add alice --split-tunnel
```

With split tunnelling enabled, more-specific local network routes remain available through the client's normal network connection, while other traffic is routed through the VPN.

**Replace an existing peer:**

```bash
sudo wgserver add alice --overwrite
```

This regenerates the peer's keys and configuration. The previous client configuration will no longer be valid.

### List clients

Display the configured peers:

```bash
sudo wgserver list
```

The output includes peer information such as the peer index and allowed IP addresses.

### Remove a client

A peer can be removed by name:

```bash
sudo wgserver remove alice
```

It can also be removed using the index displayed by `list`:

```bash
sudo wgserver remove 2
```

Removing a peer deletes its entry from the server configuration. It does not delete previously generated client configuration files.

### Manage the WireGuard service

Apply the configuration and restart the tunnel:

```bash
sudo wgserver restart
```

This command:

1. Enables IPv4 and IPv6 packet forwarding.
2. Persists forwarding settings in `/etc/sysctl.d/99-wireguard.conf`.
3. Enables the corresponding `wg-quick` systemd service at boot.
4. Reloads the systemd configuration.
5. Restarts the WireGuard service.

Firewall and NAT rules defined in the configuration are applied by `wg-quick` as part of the service startup.

Check the service and forwarding status:

```bash
sudo wgserver status
```

### Inspect the configuration

Print the configuration file:

```bash
sudo wgserver print
```

The latter is mainly useful for troubleshooting and inspecting how the configuration is interpreted.

## Typical setup

A basic server setup involves four steps.

**1. Initialize the server**

```bash
sudo wgserver init vpn.example.com
```

Replace `vpn.example.com` with the public hostname or IP address clients will use to connect.

**2. Add a client**

```bash
sudo wgserver add alice > alice.conf
```

Keep the generated client configuration private. It contains the client's private key.

**3. Start the WireGuard tunnel**

```bash
sudo wgserver restart
```

**4. Check the status**

```bash
sudo wgserver status
```

Import `alice.conf` into the WireGuard application on the client device. Alternatively, scan the QR code printed by the `add` command to import the configuration on a mobile device.

## Networking notes

- The server must be reachable by clients on the configured WireGuard UDP port.
- The appropriate UDP port must be allowed through any external firewall or router.
- IP forwarding and NAT are required if clients should access networks or the Internet through the VPN.
- The generated firewall rules configure the local Linux system. They do not configure external routers or cloud-provider firewalls.
- Client configuration files contain private keys and should be kept private.
- Removing a peer from the server configuration does not automatically remove its configuration from client devices.

## License

This project is licensed under the GNU General Public License version 3.0 (GPL-3.0). See [LICENSE](LICENSE) for the full license text.