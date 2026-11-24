//! Host route advertising.
//!
//! Explicit advertising uses only concrete listener binds and developer-listed hints. Auto
//! advertising additionally enumerates the LAN and overlay addresses a pairing-capable TCP
//! listener bound to an unspecified address actually accepts on. It never selects a public,
//! loopback, link-local or blocked address, and never an address on a network whose only
//! transport is cellular.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::error::RuntimeError;
use crate::providers::is_metadata_or_link_local_ip;
use crate::redact::redact_json_error;

/// Interface name prefixes that count as overlay evidence and mark a tunnel interface.
const TUNNEL_IFACE_PREFIXES: [&str; 5] = ["tailscale", "wg", "zt", "utun", "tun"];

/// Which advertising rule a host applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvertiseMode {
    /// Explicit sources plus enumerated LAN and overlay addresses (SDK and FFI default).
    #[default]
    Auto,
    /// Concrete listener binds and developer-listed hints only (CLI rule).
    Explicit,
}

/// A transport a network runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Wifi,
    Ethernet,
    Cellular,
    Vpn,
    Other,
}

/// One local interface address with the transports of its network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddr {
    pub addr: IpAddr,
    pub iface: String,
    pub if_index: u32,
    pub transports: Vec<Transport>,
}

/// A source of local interface addresses.
pub trait LocalAddrSource {
    /// Current addresses of interfaces that are up.
    fn local_addrs(&self) -> Vec<LocalAddr>;

    /// Whether an address on a network whose transports are only `Other` (on a non-tunnel
    /// interface) is eligible. Desktop native enumeration only.
    fn other_is_eligible(&self) -> bool {
        false
    }
}

/// A fixed address list (Android snapshots and tests).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListAddrSource {
    addrs: Vec<LocalAddr>,
}

impl ListAddrSource {
    #[must_use]
    pub const fn new(addrs: Vec<LocalAddr>) -> Self {
        Self { addrs }
    }

    /// Flattens a network snapshot into its addresses; unparseable address strings are skipped.
    #[must_use]
    pub fn from_snapshot(snapshot: &NetworkSnapshot) -> Self {
        let addrs = snapshot
            .networks
            .iter()
            .flat_map(|net| {
                net.addrs.iter().filter_map(|raw| {
                    Some(LocalAddr {
                        addr: parse_snapshot_addr(raw)?,
                        iface: net.iface.clone(),
                        if_index: net.if_index,
                        transports: net.transports.clone(),
                    })
                })
            })
            .collect();
        Self { addrs }
    }
}

impl LocalAddrSource for ListAddrSource {
    fn local_addrs(&self) -> Vec<LocalAddr> {
        self.addrs.clone()
    }
}

/// Accepts `ip`, `ip/prefix` and `ipv6%scope` forms.
fn parse_snapshot_addr(raw: &str) -> Option<IpAddr> {
    let no_prefix = raw.split_once('/').map_or(raw, |(ip, _)| ip);
    let no_scope = no_prefix.split_once('%').map_or(no_prefix, |(ip, _)| ip);
    no_scope.trim().parse().ok()
}

/// The complete current network snapshot a list-source platform (Android) passes to
/// `tendril_endpoint_refresh_routes`, never a delta.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub networks: Vec<SnapshotNetwork>,
}

/// One network of a [`NetworkSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotNetwork {
    #[serde(default)]
    pub id: String,
    pub iface: String,
    #[serde(default)]
    pub if_index: u32,
    pub transports: Vec<Transport>,
    pub addrs: Vec<String>,
}

impl NetworkSnapshot {
    /// Parses the snapshot JSON `{"networks": [...]}`. The error names the JSON error's
    /// category and position, never the input.
    pub fn from_json(json: &str) -> Result<Self, RuntimeError> {
        serde_json::from_str(json).map_err(|err| {
            RuntimeError::Protocol(format!(
                "invalid network snapshot: {}",
                redact_json_error(&err)
            ))
        })
    }
}

/// Native interface enumeration through `netdev` (feature `auto-advertise`). Without the
/// feature, and on Android and WASM, it reports no addresses.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeAddrSource;

impl LocalAddrSource for NativeAddrSource {
    fn local_addrs(&self) -> Vec<LocalAddr> {
        native::local_addrs()
    }

    fn other_is_eligible(&self) -> bool {
        cfg!(not(any(target_os = "ios", target_os = "android")))
    }
}

#[cfg(all(
    feature = "auto-advertise",
    not(any(target_os = "android", target_arch = "wasm32"))
))]
mod native {
    use netdev::interface::types::InterfaceType;

    use super::{LocalAddr, Transport, is_tunnel_iface};

    const CELLULAR_IFACE_PREFIXES: [&str; 4] = ["pdp_ip", "rmnet", "ccmni", "wwan"];

    fn transport(iface: &netdev::Interface) -> Transport {
        let name = iface.name.to_ascii_lowercase();
        let friendly = iface
            .friendly_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let cellular_type = matches!(
            iface.if_type,
            InterfaceType::Wwan
                | InterfaceType::Wwanpp
                | InterfaceType::Wwanpp2
                | InterfaceType::Wman
                | InterfaceType::GenericModem
                | InterfaceType::Ppp
                | InterfaceType::Slip
        );
        if cellular_type || CELLULAR_IFACE_PREFIXES.iter().any(|p| name.starts_with(p)) {
            return Transport::Cellular;
        }
        if iface.if_type == InterfaceType::Tunnel
            || iface.is_tun()
            || is_tunnel_iface(&name)
            || is_tunnel_iface(&friendly)
        {
            return Transport::Vpn;
        }
        match iface.if_type {
            InterfaceType::Wireless80211 | InterfaceType::PeerToPeerWireless => Transport::Wifi,
            InterfaceType::Ethernet
            | InterfaceType::Ethernet3Megabit
            | InterfaceType::FastEthernetT
            | InterfaceType::FastEthernetFx
            | InterfaceType::GigabitEthernet
            | InterfaceType::Bridge => Transport::Ethernet,
            _ => Transport::Other,
        }
    }

    pub(super) fn local_addrs() -> Vec<LocalAddr> {
        netdev::get_interfaces()
            .into_iter()
            .filter(|i| {
                i.is_up()
                    && i.is_running()
                    && !i.is_loopback()
                    && i.if_type != InterfaceType::Loopback
            })
            .flat_map(|i| {
                let transports = vec![transport(&i)];
                i.ip_addrs().into_iter().map(move |addr| LocalAddr {
                    addr,
                    iface: i.name.clone(),
                    if_index: i.index,
                    transports: transports.clone(),
                })
            })
            .collect()
    }
}

#[cfg(not(all(
    feature = "auto-advertise",
    not(any(target_os = "android", target_arch = "wasm32"))
)))]
mod native {
    pub(super) const fn local_addrs() -> Vec<super::LocalAddr> {
        Vec::new()
    }
}

/// A pairing-capable TCP listener and the address families it accepts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServedListener {
    addr: SocketAddr,
    v6only: Option<bool>,
}

impl ServedListener {
    /// `v6only` is the socket's `IPV6_V6ONLY` value read back after bind; it matters only for
    /// a `[::]` bind, where `None` is treated as `true`.
    #[must_use]
    pub const fn new(addr: SocketAddr, v6only: Option<bool>) -> Self {
        Self { addr, v6only }
    }

    /// Records a bound listener, reading `IPV6_V6ONLY` back for an IPv6 bind.
    pub fn from_listener(listener: &tokio::net::TcpListener) -> std::io::Result<Self> {
        let addr = listener.local_addr()?;
        let v6only = if addr.is_ipv6() {
            Some(socket2::SockRef::from(listener).only_v6()?)
        } else {
            None
        };
        Ok(Self { addr, v6only })
    }

    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[must_use]
    pub const fn v6only(&self) -> Option<bool> {
        self.v6only
    }

    /// `true` for an unspecified bind, the only kind auto enumeration expands.
    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        self.addr.ip().is_unspecified()
    }

    /// Whether this listener accepts connections to `ip`.
    fn covers(&self, ip: IpAddr) -> bool {
        match (self.addr.ip(), ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => true,
            (IpAddr::V6(_), IpAddr::V4(_)) => self.v6only == Some(false),
            (IpAddr::V4(_), IpAddr::V6(_)) => false,
        }
    }
}

fn is_tunnel_iface(name: &str) -> bool {
    TUNNEL_IFACE_PREFIXES.iter().any(|p| name.starts_with(p))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AutoClass {
    Lan,
    Overlay,
}

enum AddrRange {
    Private4,
    SharedCgnat,
    Ula,
    Never,
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_link_local()
        || o[0] == 0
        || o[0] >= 240
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn addr_range(ip: IpAddr) -> AddrRange {
    if is_metadata_or_link_local_ip(ip) {
        return AddrRange::Never;
    }
    match ip {
        IpAddr::V4(v4) if is_blocked_v4(v4) => AddrRange::Never,
        IpAddr::V4(v4) if v4.is_private() => AddrRange::Private4,
        IpAddr::V4(v4) if v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64 => {
            AddrRange::SharedCgnat
        }
        IpAddr::V6(v6) if is_blocked_v6(v6) => AddrRange::Never,
        IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00 => AddrRange::Ula,
        _ => AddrRange::Never,
    }
}

/// Rules for one address; `None` means never auto-advertised.
fn auto_class(local: &LocalAddr, ip: IpAddr, other_eligible: bool) -> Option<AutoClass> {
    let has = |t| local.transports.contains(&t);
    let tunnel_name = is_tunnel_iface(&local.iface.to_ascii_lowercase());
    let eligible = has(Transport::Wifi)
        || has(Transport::Ethernet)
        || has(Transport::Vpn)
        || (other_eligible && has(Transport::Other) && !tunnel_name);
    if !eligible {
        return None;
    }
    // Overlay evidence also rules out LAN: a private address on a VPN or tunnel interface is
    // never a `direct:` LAN hint.
    let overlay_evidence = has(Transport::Vpn) || tunnel_name;
    match addr_range(ip) {
        AddrRange::SharedCgnat | AddrRange::Ula if overlay_evidence => Some(AutoClass::Overlay),
        AddrRange::Private4 | AddrRange::Ula if !overlay_evidence => Some(AutoClass::Lan),
        _ => None,
    }
}

/// Enumerates the LAN and overlay hints every unspecified-bind listener accepts on
/// `direct:<ip>:<port>` for LAN, `overlay://<ip>:<port>` for
/// overlay. Hints from all listeners are ordered together: IPv4 before IPv6 within a provider,
/// then interface index, then listener and address order, so a listener listed first never
/// pushes another listener's IPv4 hint behind its IPv6 ones.
#[must_use]
pub fn auto_endpoints(listeners: &[ServedListener], source: &dyn LocalAddrSource) -> Vec<String> {
    let other_eligible = source.other_is_eligible();
    let addrs = source.local_addrs();
    let mut found: Vec<(AutoClass, bool, u32, usize, usize, SocketAddr)> = Vec::new();
    for (l, listener) in listeners.iter().enumerate() {
        if !listener.is_unspecified() {
            continue;
        }
        let port = listener.addr.port();
        found.extend(addrs.iter().enumerate().filter_map(|(i, local)| {
            let ip = unmap(local.addr);
            if !listener.covers(ip) {
                return None;
            }
            let class = auto_class(local, ip, other_eligible)?;
            Some((
                class,
                ip.is_ipv6(),
                local.if_index,
                l,
                i,
                SocketAddr::new(ip, port),
            ))
        }));
    }
    found.sort_unstable();
    let mut out = Vec::new();
    for (class, _, _, _, _, sock) in found {
        let hint = match class {
            AutoClass::Lan => format!("direct:{sock}"),
            AutoClass::Overlay => format!("overlay://{sock}"),
        };
        if !out.contains(&hint) {
            out.push(hint);
        }
    }
    out
}

/// What a host advertises from: listener endpoints, the TCP listeners auto enumeration expands
/// and developer-listed hints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvertiseInputs {
    pub mode: AdvertiseMode,
    /// Endpoint strings of every serving listener (`served_endpoints`), including
    /// unspecified binds.
    pub served_endpoints: Vec<String>,
    /// Pairing-capable TCP listeners (`serve_direct`) for auto enumeration.
    pub listeners: Vec<ServedListener>,
    /// Developer-listed hints (`advertised_endpoints`).
    pub advertised_endpoints: Vec<String>,
}

fn is_unspecified_bind(endpoint: &str) -> bool {
    endpoint
        .strip_prefix("direct:")
        .unwrap_or(endpoint)
        .parse::<SocketAddr>()
        .is_ok_and(|s| s.ip().is_unspecified())
}

impl AdvertiseInputs {
    /// The raw endpoint list for the announced set: served endpoints, then developer-listed
    /// hints, then (auto mode) enumerated addresses. In auto mode unspecified binds are
    /// replaced by their enumeration; in explicit mode they stay and the announced set drops
    /// them with `unspecified_bind`.
    #[must_use]
    pub fn endpoints(&self, source: &dyn LocalAddrSource) -> Vec<String> {
        let auto = self.mode == AdvertiseMode::Auto;
        let mut out: Vec<String> = self
            .served_endpoints
            .iter()
            .filter(|e| !(auto && is_unspecified_bind(e)))
            .cloned()
            .collect();
        out.extend(self.advertised_endpoints.iter().cloned());
        if auto {
            out.extend(auto_endpoints(&self.listeners, source));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str, iface: &str, idx: u32, t: &[Transport]) -> LocalAddr {
        LocalAddr {
            addr: ip.parse().unwrap(),
            iface: iface.into(),
            if_index: idx,
            transports: t.to_vec(),
        }
    }

    #[test]
    fn other_needs_desktop_and_a_non_tunnel_interface() {
        struct Desktop(Vec<LocalAddr>);
        impl LocalAddrSource for Desktop {
            fn local_addrs(&self) -> Vec<LocalAddr> {
                self.0.clone()
            }
            fn other_is_eligible(&self) -> bool {
                true
            }
        }
        let addrs = vec![
            addr("192.168.5.2", "eth9", 2, &[Transport::Other]),
            addr("10.9.0.2", "tun3", 3, &[Transport::Other]),
        ];
        let listener = [ServedListener::new("0.0.0.0:7000".parse().unwrap(), None)];
        assert_eq!(
            auto_endpoints(&listener, &Desktop(addrs.clone())),
            vec!["direct:192.168.5.2:7000"]
        );
        assert!(auto_endpoints(&listener, &ListAddrSource::new(addrs)).is_empty());
    }

    #[test]
    fn mapped_and_metadata_addresses() {
        let src = ListAddrSource::new(vec![
            addr("::ffff:192.168.1.9", "en0", 1, &[Transport::Wifi]),
            addr("fd00:ec2::254", "en0", 1, &[Transport::Wifi]),
            addr("10.0.0.4", "tailscale0", 4, &[Transport::Vpn]),
        ]);
        let dual = [ServedListener::new(
            "[::]:7100".parse().unwrap(),
            Some(false),
        )];
        assert_eq!(auto_endpoints(&dual, &src), vec!["direct:192.168.1.9:7100"]);
        let unknown = [ServedListener::new("[::]:7100".parse().unwrap(), None)];
        assert!(auto_endpoints(&unknown, &src).is_empty());
    }

    #[test]
    fn snapshot_addresses_accept_prefix_and_scope() {
        let snap = NetworkSnapshot::from_json(
            r#"{"networks":[{"id":"100","iface":"wlan0","if_index":30,"transports":["wifi"],
                "addrs":["192.168.1.20/24","fe80::1%wlan0","fd34::9/64","bogus"]}]}"#,
        )
        .unwrap();
        let ips: Vec<IpAddr> = ListAddrSource::from_snapshot(&snap)
            .local_addrs()
            .into_iter()
            .map(|a| a.addr)
            .collect();
        assert_eq!(
            ips,
            vec![
                "192.168.1.20".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap(),
                "fd34::9".parse().unwrap()
            ]
        );
    }

    #[test]
    fn explicit_mode_keeps_unspecified_binds_for_reporting() {
        let inputs = AdvertiseInputs {
            mode: AdvertiseMode::Explicit,
            served_endpoints: vec!["0.0.0.0:9100".into(), "127.0.0.1:9300".into()],
            listeners: vec![ServedListener::new("0.0.0.0:9100".parse().unwrap(), None)],
            advertised_endpoints: vec!["overlay://100.101.1.2:9100".into()],
        };
        let src = ListAddrSource::new(vec![addr("192.168.1.20", "en0", 1, &[Transport::Wifi])]);
        assert_eq!(
            inputs.endpoints(&src),
            vec![
                "0.0.0.0:9100",
                "127.0.0.1:9300",
                "overlay://100.101.1.2:9100"
            ]
        );
        let auto = AdvertiseInputs {
            mode: AdvertiseMode::Auto,
            ..inputs
        };
        assert_eq!(
            auto.endpoints(&src),
            vec![
                "127.0.0.1:9300",
                "overlay://100.101.1.2:9100",
                "direct:192.168.1.20:9100"
            ]
        );
    }
}
