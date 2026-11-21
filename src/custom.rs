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

impl std::str::FromStr for Port {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port: i32 = s.parse().map_err(|_| format!("Invalid port number: {s}"))?;

        Self::new(port)
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::str::FromStr for Mtu {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mtu: i32 = s.parse().map_err(|_| format!("Invalid MTU value: {s}"))?;
        Self::new(mtu)
    }
}

impl std::fmt::Display for Mtu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
