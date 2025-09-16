//! Basic connection test without certificates

use ant_quic::Endpoint;
use std::net::{Ipv4Addr, SocketAddr};

#[tokio::test]
async fn test_client_creation() {
    // Just test that we can create a client endpoint
    let client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    assert!(
        client.is_ok(),
        "Failed to create client: {:?}",
        client.err()
    );
}
