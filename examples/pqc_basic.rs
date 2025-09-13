//! Basic Post-Quantum Cryptography example
//!
//! This example demonstrates the simplest way to enable PQC in ant-quic
//! using the QuicP2PNode high-level API.

use ant_quic::{
    auth::AuthConfig,
    crypto::pqc::PqcConfig,
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ml_dsa_keypair,
    },
    nat_traversal_api::EndpointRole,
    quic_node::{QuicNodeConfig, QuicP2PNode},
};

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    // PQC is now always enabled
    
    // Parse command line arguments
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            println!("Usage: {} <server|client> [server_addr]", args[0]);
            println!("\nExamples:");
            println!(
                "  {} server              # Start a PQC-enabled server",
                args[0]
            );
            println!(
                "  {} client 127.0.0.1:5000  # Connect to a PQC server",
                args[0]
            );
            return Ok(());
        }

        let mode = &args[1];

        match mode.as_str() {
            "server" => run_server().await,
            "client" => {
                if args.len() < 3 {
                    eprintln!("Error: Client mode requires server address");
                    return Ok(());
                }
                let server_addr: SocketAddr = args[2].parse()?;
                run_client(server_addr).await
            }
            _ => {
                eprintln!("Error: Unknown mode '{mode}'. Use 'server' or 'client'");
                Ok(())
            }
        }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 Starting PQC-enabled QUIC server...");

    // Generate identity with ML-DSA
    let keypair = generate_ml_dsa_keypair();
    let public_key = keypair.public_key();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    println!("📋 Server PeerID: {peer_id:?}");

    // Create PQC configuration (always enabled)
    let _pqc_config = PqcConfig::default();
    println!("🔐 PQC Mode: Full post-quantum (ML-DSA-65 + ML-KEM-768)");

    // Create server configuration
    let config = QuicNodeConfig {
        role: EndpointRole::Server {
            can_coordinate: true,
        },
        bootstrap_nodes: vec![],
        enable_coordinator: true,
        max_connections: 50,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(), // PQC is configured here internally
        bind_addr: Some("0.0.0.0:5000".parse()?),
    };

    let node = Arc::new(QuicP2PNode::new(config).await?);
    println!("🎧 Listening on 0.0.0.0:5000");
    println!("🔐 PQC protection enabled!");

    // Handle incoming messages
    loop {
        match node.receive().await {
            Ok((peer_id, data)) => {
                let message = String::from_utf8_lossy(&data);
                println!("📩 Message from {peer_id:?}: {message}");

                // Echo the message back
                let response = format!("Server received: {message}");
                if let Err(e) = node.send_to_peer(&peer_id, response.as_bytes()).await {
                    warn!("Failed to send response: {}", e);
                }
            }
            Err(_) => {
                // No messages available
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn run_client(
    server_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 Starting PQC-enabled QUIC client...");

    // Generate identity with ML-DSA
    let keypair = generate_ml_dsa_keypair();
    let public_key = keypair.public_key();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    println!("📋 Client PeerID: {peer_id:?}");

    // Create PQC configuration (always enabled)
    let _pqc_config = PqcConfig::default();
    println!("🔐 PQC Mode: Full post-quantum (ML-DSA-65 + ML-KEM-768)");

    // Create client configuration
    let config = QuicNodeConfig {
        role: EndpointRole::Client,
        bootstrap_nodes: vec![server_addr],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(), // PQC is configured here internally
        bind_addr: None,
    };

    let node = Arc::new(QuicP2PNode::new(config).await?);
    println!("🔗 Connecting to {server_addr} with PQC...");

    // Connect to server (bootstrap node)
    let server_peer_id = node.connect_to_bootstrap(server_addr).await?;
    println!("✅ Connected to server with PQC protection!");
    println!("   Server PeerID: {server_peer_id:?}");

    // Send a test message
    let message = "Hello from PQC-protected client!";
    info!("Sending message: {}", message);
    node.send_to_peer(&server_peer_id, message.as_bytes())
        .await?;

    // Wait for response
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match node.receive().await {
                Ok((peer_id, data)) => {
                    if peer_id == server_peer_id {
                        let response = String::from_utf8_lossy(&data);
                        println!("📨 Response: {response}");
                        return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
    .await;

    match timeout {
        Ok(Ok(())) => println!("✅ Communication successful with PQC protection!"),
        Ok(Err(_)) => warn!("Failed to receive response"),
        Err(_) => warn!("Timeout waiting for response"),
    }

    // Graceful shutdown
    drop(node);
    println!("👋 Client shutdown complete");

    Ok(())
}
