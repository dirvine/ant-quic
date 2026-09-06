//! Disposable Linux acceptance harness: run only through the admitted private namespace.
// Integration-test assertions follow the repository test-only lint exemption.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{BootstrapCacheConfig, Node, NodeConfig};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::Duration;

fn require_private_runtime() {
    let status = std::fs::read_to_string("/proc/self/status").expect("process status");
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))
            .expect("capability field");
        assert_eq!(u64::from_str_radix(value.trim(), 16).unwrap(), 0);
    }
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    assert_eq!(std::env::var("HOME").unwrap(), "/tmp/x0x-runtime-home");
    let output = std::process::Command::new("/usr/sbin/ip")
        .args(["-j", "link"])
        .output()
        .expect("interface census");
    assert!(output.status.success());
    let links: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let links = links.as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["ifname"], "lo");
}

fn config(requested: SocketAddr, cache: &Path) -> NodeConfig {
    let config = NodeConfig::builder()
        .bind_addr(requested)
        .mdns_enabled(false)
        .port_mapping_enabled(false)
        .bootstrap_cache(BootstrapCacheConfig {
            cache_dir: cache.to_owned(),
            persist: false,
            ..Default::default()
        })
        .build();
    assert!(config.known_peers.is_empty());
    config
}

// Linux procfs reports each address as native-endian 32-bit words. Match
// entries against this process's socket inodes, including cloned descriptors.
fn own_udp_bindings() -> BTreeSet<SocketAddr> {
    let inodes: BTreeSet<String> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|path| {
            path.to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')
                .map(str::to_owned)
        })
        .collect();
    let mut result = BTreeSet::new();
    for (path, ipv6) in [("/proc/self/net/udp", false), ("/proc/self/net/udp6", true)] {
        for line in std::fs::read_to_string(path).unwrap().lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert!(fields.len() > 9, "unexpected UDP census row");
            if !inodes.contains(fields[9]) {
                continue;
            }
            let (ip, port) = fields[1].split_once(':').unwrap();
            let ip = if ipv6 {
                assert_eq!(ip.len(), 32);
                let mut bytes = [0_u8; 16];
                for i in 0..4 {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(
                        &u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16)
                            .unwrap()
                            .to_ne_bytes(),
                    );
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            } else {
                IpAddr::V4(Ipv4Addr::from(
                    u32::from_str_radix(ip, 16).unwrap().to_ne_bytes(),
                ))
            };
            result.insert(SocketAddr::new(ip, u16::from_str_radix(port, 16).unwrap()));
        }
    }
    result
}

// Shutdown cancels background tasks; allow them one bounded drain window.
// This is cleanup observation, separate from the bind predicate, not a retry.
async fn drained_udp_bindings(expected: &BTreeSet<SocketAddr>) -> BTreeSet<SocketAddr> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let sockets = own_udp_bindings();
        if &sockets == expected || tokio::time::Instant::now() >= deadline {
            return sockets;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn assert_bind(requested: SocketAddr) {
    require_private_runtime();
    assert!(
        own_udp_bindings().is_empty(),
        "fixture process already owns UDP sockets"
    );
    let root = tempfile::tempdir().unwrap();
    let node = tokio::time::timeout(
        Duration::from_secs(15),
        Node::with_config(config(requested, root.path())),
    )
    .await
    .expect("creation deadline")
    .expect("node bind");
    let actual = node.local_addr().expect("bound address");
    let status = node.status().await;
    let sockets = own_udp_bindings();
    let conflict = UdpSocket::bind(actual).err().map(|error| error.kind());
    node.shutdown().await;
    let remaining = drained_udp_bindings(&BTreeSet::new()).await;
    println!(
        "\nBIND_OBSERVATION {}",
        serde_json::json!({
            "case": "explicit", "requested": requested, "actual": actual,
            "status": status.local_addr, "kernel_sockets": sockets,
            "cleanup_sockets": remaining,
            "reported_port_busy": conflict == Some(std::io::ErrorKind::AddrInUse)
        })
    );
    assert_eq!(actual.ip(), requested.ip(), "EXPLICIT_BIND_IP_MISMATCH");
    assert_ne!(actual.port(), 0, "port-zero allocation not surfaced");
    assert_eq!(
        status.local_addr, actual,
        "status differs from endpoint socket address"
    );
    assert_eq!(
        sockets,
        BTreeSet::from([actual]),
        "kernel sockets differ from returned address"
    );
    assert_eq!(
        conflict,
        Some(std::io::ErrorKind::AddrInUse),
        "reported socket is not exclusively bound"
    );
    assert!(
        remaining.is_empty(),
        "shutdown retained UDP socket: {remaining:?}"
    );
    println!(
        "BIND_ACCEPTANCE {{\"case\":\"explicit\",\"requested\":\"{requested}\",\"actual\":\"{actual}\",\"kernel_socket_count\":1,\"status_matches\":true,\"shutdown_empty\":true}}"
    );
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires the reviewed Linux namespace"
)]
async fn explicit_ipv4_port_zero_matches_kernel_and_status() {
    assert_bind("127.0.0.1:0".parse().unwrap()).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires the reviewed Linux namespace"
)]
async fn explicit_ipv6_port_zero_matches_kernel_and_status() {
    assert_bind("[::1]:0".parse().unwrap()).await;
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires the reviewed Linux namespace"
)]
async fn occupied_explicit_address_fails_without_widening() {
    require_private_runtime();
    assert!(own_udp_bindings().is_empty());
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let held = UdpSocket::bind(address).expect("exclusive sentinel bind");
        let requested = held.local_addr().unwrap();
        let root = tempfile::tempdir().unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            Node::with_config(config(requested, root.path())),
        )
        .await
        .expect("failure deadline");
        let rejected = match result {
            Ok(node) => {
                node.shutdown().await;
                false
            }
            Err(ant_quic::NodeError::Endpoint(ant_quic::EndpointError::Config(message))) => {
                message.starts_with("Failed to bind UDP socket:")
            }
            Err(_) => false,
        };
        let sockets = drained_udp_bindings(&BTreeSet::from([requested])).await;
        println!(
            "\nBIND_OBSERVATION {}",
            serde_json::json!({
                "case": "occupied", "requested": requested, "bind_rejected": rejected,
                "remaining_sockets": sockets
            })
        );
        assert!(
            rejected,
            "occupied explicit address unexpectedly bound another socket"
        );
        assert_eq!(
            sockets,
            BTreeSet::from([requested]),
            "failed construction opened an unrelated socket"
        );
        drop(held);
        let remaining = drained_udp_bindings(&BTreeSet::new()).await;
        assert!(
            remaining.is_empty(),
            "sentinel cleanup retained sockets: {remaining:?}"
        );
        println!(
            "BIND_ACCEPTANCE {{\"case\":\"occupied\",\"requested\":\"{requested}\",\"rejected\":true,\"remaining_socket_count\":1,\"cleanup_empty\":true}}"
        );
    }
}
