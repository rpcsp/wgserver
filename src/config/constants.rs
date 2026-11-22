pub(crate) const GROUP_INTERFACE: &str = "Interface";
pub(crate) const GROUP_PEER: &str = "Peer";
pub(crate) const KNOWN_GROUPS: [&str; 2] = [GROUP_INTERFACE, GROUP_PEER];

/// When a new `[Peer]` is found, a PartialPeer group is always added to the list
/// So, the last element always exists
pub(crate) const LAST_PEER_MSG: &str = "[Peer] group always pushes a PartialPeer";
