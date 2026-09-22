//! Conservative public-address policy for OAuth discovery and token endpoints.
//! IANA special-purpose registries reviewed 2026-09-11. This deliberately also
//! excludes protocol-specific anycast/transitional allocations. Local MCP uses
//! the separately contained stdio carrier; OAuth never grants private-network access.
use std::net::{IpAddr, SocketAddr};

pub(super) fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Only ordinary global unicast. This excludes mapped IPv4, NAT64,
            // loopback/unspecified, local/link-local/site-local and multicast.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0)
        }
    }
}

/// Admit the complete resolved address set for a credential-bearing MCP endpoint.
///
/// # Errors
/// Mixed private/public answers, special-use addresses and wrong ports refuse.
pub fn pin_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    port: u16,
) -> Result<Vec<SocketAddr>, String> {
    if port == 0 {
        return Err("OAuth endpoint has no usable port.".into());
    }
    let mut pinned = Vec::new();
    for (index, address) in addresses.into_iter().take(65).enumerate() {
        if index == 64 || address.port() != port || !public_address(address.ip()) {
            return Err(
                "OAuth DNS includes a private, special-purpose or excessive address set.".into(),
            );
        }
        if !pinned.contains(&address) {
            pinned.push(address);
        }
    }
    if pinned.is_empty() {
        return Err("OAuth endpoint resolved no public addresses.".into());
    }
    Ok(pinned)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_special_mapped_and_transition_addresses_refuse() {
        for value in [
            "0.1.2.3",
            "10.0.0.1",
            "127.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::0808:0808",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2001:20::1",
            "2002:0808:0808::1",
            "3fff:fff::1",
        ] {
            assert!(!public_address(value.parse().unwrap()), "{value}");
        }
        for value in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_address(value.parse().unwrap()), "{value}");
        }
    }
    #[test]
    fn mixed_dns_answers_cannot_fall_back_to_an_unapproved_address() {
        let public = "8.8.8.8:443".parse().unwrap();
        assert!(pin_addresses([public, "127.0.0.1:443".parse().unwrap()], 443).is_err());
        assert!(pin_addresses([public], 8443).is_err());
        assert!(pin_addresses([], 443).is_err());
        assert_eq!(pin_addresses([public, public], 443).unwrap(), [public]);
        assert!(pin_addresses([public; 65], 443).is_err());
    }
}
