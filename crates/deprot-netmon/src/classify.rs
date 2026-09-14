//! Pure endpoint parsing + classification — no I/O, so it's fully unit-testable.
//!
//! `/proc/net/tcp` stores addresses as hex: an IPv4 address is 8 hex chars in host byte order
//! (little-endian on x86), and a port is 4 hex chars big-endian. IPv6 is 32 hex chars, stored as
//! four little-endian 32-bit words.

use deprot_core::Severity;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What kind of endpoint a connection reached, worst-first in `severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Cloud instance metadata service (169.254.169.254 / fd00:ec2::254) — credential-theft target.
    CloudMetadata,
    /// A public, routable address — an install/build phoning out to the internet.
    External,
    /// A private / LAN address (RFC1918, CGNAT, ULA).
    Private,
    /// Loopback — never interesting.
    Loopback,
}

impl Category {
    pub fn severity(self) -> Severity {
        match self {
            Category::CloudMetadata => Severity::Critical,
            Category::External => Severity::Medium,
            Category::Private => Severity::Low,
            Category::Loopback => Severity::Low,
        }
    }

    pub fn rule(self) -> &'static str {
        match self {
            Category::CloudMetadata => "cloud-metadata-connection",
            Category::External => "external-connection",
            Category::Private => "private-connection",
            Category::Loopback => "loopback-connection",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Category::CloudMetadata => {
                "Connection to the cloud metadata service (credential theft)"
            }
            Category::External => "Outbound connection to a public host",
            Category::Private => "Connection to a private/LAN address",
            Category::Loopback => "Loopback connection",
        }
    }
}

/// The AWS/GCP/Azure link-local metadata address.
const IMDS_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Classify a remote IP into a [`Category`].
pub fn classify(ip: IpAddr) -> Category {
    match ip {
        IpAddr::V4(v4) => {
            if v4 == IMDS_V4 {
                Category::CloudMetadata
            } else if v4.is_loopback() {
                Category::Loopback
            } else if v4.is_private() || v4.is_link_local() || is_cgnat(v4) {
                Category::Private
            } else {
                Category::External
            }
        }
        IpAddr::V6(v6) => {
            // GCP/AWS also expose IMDS over IPv6 at fd00:ec2::254.
            if is_imds_v6(v6) {
                Category::CloudMetadata
            } else if v6.is_loopback() {
                Category::Loopback
            } else if is_private_v6(v6) {
                Category::Private
            } else {
                Category::External
            }
        }
    }
}

/// 100.64.0.0/10 — carrier-grade NAT, treated as private.
fn is_cgnat(v4: Ipv4Addr) -> bool {
    v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1])
}

fn is_imds_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    s == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254]
}

/// ULA (fc00::/7) or link-local (fe80::/10) — the IPv6 "private" ranges.
fn is_private_v6(v6: Ipv6Addr) -> bool {
    let first = v6.segments()[0];
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

/// Parse an IPv4 `/proc/net/tcp` address field (`"0100007F:0035"`) into `(ip, port)`.
pub fn parse_v4(field: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = field.split_once(':')?;
    let raw = u32::from_str_radix(addr, 16).ok()?;
    // Stored in host byte order (little-endian): the low byte is the first octet.
    let ip = Ipv4Addr::new(
        (raw & 0xff) as u8,
        ((raw >> 8) & 0xff) as u8,
        ((raw >> 16) & 0xff) as u8,
        ((raw >> 24) & 0xff) as u8,
    );
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((IpAddr::V4(ip), port))
}

/// Parse an IPv6 `/proc/net/tcp6` address field (32 hex chars + `:port`) into `(ip, port)`.
pub fn parse_v6(field: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = field.split_once(':')?;
    if addr.len() != 32 {
        return None;
    }
    // Four little-endian 32-bit words. Read each word, swap to big-endian bytes.
    let mut octets = [0u8; 16];
    for w in 0..4 {
        let word = u32::from_str_radix(&addr[w * 8..w * 8 + 8], 16).ok()?;
        let be = word.to_le_bytes(); // reinterpret host-order word as bytes in address order
        octets[w * 4..w * 4 + 4].copy_from_slice(&be);
    }
    let ip = Ipv6Addr::from(octets);
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((IpAddr::V6(ip), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v4_little_endian() {
        // 127.0.0.1:53
        assert_eq!(
            parse_v4("0100007F:0035"),
            Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53))
        );
        // 169.254.169.254:80  -> FEA9FEA9 in host order (LE): 254,169,254,169 reversed
        let (ip, port) = parse_v4("FEA9FEA9:0050").unwrap();
        assert_eq!(ip, IpAddr::V4(IMDS_V4));
        assert_eq!(port, 80);
    }

    #[test]
    fn classifies_categories() {
        assert_eq!(classify(IpAddr::V4(IMDS_V4)), Category::CloudMetadata);
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            Category::Loopback
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Category::Private
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(100, 100, 0, 1))),
            Category::Private,
            "CGNAT"
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Category::External
        );
    }

    #[test]
    fn severity_ordering() {
        assert!(Category::CloudMetadata.severity() > Category::External.severity());
        assert!(Category::External.severity() > Category::Private.severity());
        assert_eq!(Category::Private.severity(), Category::Loopback.severity());
    }

    #[test]
    fn parses_v6_loopback() {
        // ::1 in /proc form: 00000000000000000000000001000000
        let (ip, port) = parse_v6("00000000000000000000000001000000:1F90").unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(port, 8080);
        assert_eq!(classify(ip), Category::Loopback);
    }
}
