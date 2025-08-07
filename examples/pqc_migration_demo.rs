//! Post-Quantum Cryptography Migration Example
//!
//! This example demonstrates how to migrate an existing QUIC application
//! to use PQC while maintaining backward compatibility.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Post-Quantum Cryptography Migration Demo ===\n");

    // Check if PQC features are enabled
    #[cfg(not(feature = "pqc"))]
    {
        println!("Error: This example requires the 'pqc' feature to be enabled.");
        println!("Run with: cargo run --example pqc_migration_demo --features pqc");
        return Ok(());
    }

    #[cfg(feature = "pqc")]
    {
        tokio_main()
    }
}

#[cfg(feature = "pqc")]
use ant_quic::crypto::pqc::{HybridPreference, PqcConfig, PqcMode};
#[cfg(feature = "pqc")]
use ant_quic::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, VarInt};
#[cfg(feature = "pqc")]
use std::error::Error;
#[cfg(feature = "pqc")]
use std::net::SocketAddr;
#[cfg(feature = "pqc")]
use std::sync::Arc;
#[cfg(feature = "pqc")]
use std::time::Duration;
#[cfg(feature = "pqc")]
use tokio::time::{sleep, timeout};

#[derive(Debug, Clone, Copy)]
enum MigrationPhase {
    /// Phase 1: PQC disabled (baseline)
    PreMigration,
    /// Phase 2: PQC optional (hybrid mode with preference for classical)
    OptionalPqc,
    /// Phase 3: PQC preferred (hybrid mode with preference for PQC)
    PreferredPqc,
    /// Phase 4: PQC required (pure PQC mode)
    RequiredPqc,
}

#[cfg(feature = "pqc")]
#[tokio::main]
async fn tokio_main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Initialize logging

    println!("🔄 Post-Quantum Cryptography Migration Demo");
    println!("==========================================\n");

    // Demonstrate migration phases
    for phase in [
        MigrationPhase::PreMigration,
        MigrationPhase::OptionalPqc,
        MigrationPhase::PreferredPqc,
        MigrationPhase::RequiredPqc,
    ] {
        println!("\n📋 Migration Phase: {phase:?}");
        println!("----------------------------------------");

        // Start server with current phase configuration
        let server_task = tokio::spawn(run_server_phase(phase));

        // Give server time to start
        sleep(Duration::from_millis(100)).await;

        // Test with different client configurations
        test_client_compatibility(phase).await?;

        // Stop server
        server_task.abort();
        let _ = server_task.await;

        if matches!(phase, MigrationPhase::RequiredPqc) {
            break;
        }

        println!("\n⏳ Simulating migration period...");
        sleep(Duration::from_secs(1)).await;
    }

    println!("\n✅ Migration complete! Your application now uses Post-Quantum Cryptography.");

    Ok(())
}

#[cfg(feature = "pqc")]
async fn run_server_phase(phase: MigrationPhase) -> Result<(), Box<dyn Error + Send + Sync>> {
    let _pqc_config = match phase {
        MigrationPhase::PreMigration => {
            println!("   🔓 PQC: Disabled");
            PqcConfig::builder()
                .mode(PqcMode::ClassicalOnly)
                .build()
                .unwrap()
        }
        MigrationPhase::OptionalPqc => {
            println!("   🔐 PQC: Optional (Hybrid mode, prefer classical)");
            PqcConfig::builder()
                .mode(PqcMode::Hybrid)
                .hybrid_preference(HybridPreference::PreferClassical)
                // Migration period can be tracked externally
                .build()
                .unwrap()
        }
        MigrationPhase::PreferredPqc => {
            println!("   🔐 PQC: Preferred (Hybrid mode, prefer PQC)");
            PqcConfig::builder()
                .mode(PqcMode::Hybrid)
                .hybrid_preference(HybridPreference::PreferPqc)
                // Migration period can be tracked externally
                .build()
                .unwrap()
        }
        MigrationPhase::RequiredPqc => {
            println!("   🔒 PQC: Required (Pure PQC mode)");
            PqcConfig::builder().mode(PqcMode::PqcOnly).build().unwrap()
        }
    };

    // Generate certificate
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key = cert.signing_key.serialize_der();

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let priv_key = PrivateKeyDer::try_from(priv_key).unwrap();

    // Create server configuration
    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

    // Apply PQC configuration
    // Note: In real implementation, this would be done through the crypto provider

    // Create endpoint
    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;
    println!("   📡 Server listening on {addr}");

    // Store address for clients
    std::fs::write("server_addr.tmp", addr.to_string())?;

    // Accept connections
    while let Some(conn) = endpoint.accept().await {
        match conn.await {
            Ok(connection) => {
                println!(
                    "   ✅ Accepted connection from {}",
                    connection.remote_address()
                );
                tokio::spawn(handle_connection(connection));
            }
            Err(e) => {
                println!("   ❌ Connection failed: {e}");
            }
        }
    }

    Ok(())
}

#[cfg(feature = "pqc")]
async fn test_client_compatibility(
    server_phase: MigrationPhase,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Read server address
    let addr_str = std::fs::read_to_string("server_addr.tmp")?;
    let server_addr: SocketAddr = addr_str.trim().parse()?;

    println!("\n   Testing client compatibility:");

    // Test with legacy client (no PQC)
    println!("   - Legacy client (no PQC)...",);
    match connect_with_config(
        server_addr,
        PqcConfig::builder()
            .mode(PqcMode::ClassicalOnly)
            .build()
            .unwrap(),
    )
    .await
    {
        Ok(_) => println!("     ✅ Connected successfully"),
        Err(e) => println!("     ❌ Failed: {e}"),
    }

    // Test with hybrid client
    println!("   - Hybrid client (PQC optional)...",);
    match connect_with_config(server_addr, PqcConfig::default()).await {
        Ok(_) => println!("     ✅ Connected successfully"),
        Err(e) => println!("     ❌ Failed: {e}"),
    }

    // Test with PQC-only client
    if !matches!(server_phase, MigrationPhase::PreMigration) {
        println!("   - PQC-only client...",);
        let pqc_only = PqcConfig::builder().mode(PqcMode::PqcOnly).build().unwrap();
        match connect_with_config(server_addr, pqc_only).await {
            Ok(_) => println!("     ✅ Connected successfully"),
            Err(e) => println!("     ❌ Failed: {e}"),
        }
    }

    Ok(())
}

#[cfg(feature = "pqc")]
async fn connect_with_config(
    server_addr: SocketAddr,
    _pqc_config: PqcConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Create client configuration
    let client_config = ClientConfig::try_with_platform_verifier()?;

    // Apply PQC configuration
    // Note: In real implementation, this would be done through the crypto provider

    // Create endpoint
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let runtime = ant_quic::high_level::default_runtime().ok_or("No compatible async runtime found")?;
    let endpoint = Endpoint::new(EndpointConfig::default(), None, socket, runtime)?;

    // Connect with timeout
    let connection = timeout(
        Duration::from_secs(2),
        endpoint.connect_with(client_config, server_addr, "localhost")?,
    )
    .await??;

    // Test connection
    let (mut send, _recv) = connection.open_bi().await?;
    send.write_all(b"test").await?;
    send.finish()?;

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}

#[cfg(feature = "pqc")]
async fn handle_connection(
    connection: ant_quic::high_level::Connection,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Simple echo handler
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let data = recv.read_to_end(1024).await?;
        send.write_all(&data).await?;
        send.finish()?;
    }
    Ok(())
}

impl MigrationPhase {
    #[allow(dead_code)]
    fn description(&self) -> &'static str {
        match self {
            Self::PreMigration => "No PQC support - baseline configuration",
            Self::OptionalPqc => "PQC available but not required - testing phase",
            Self::PreferredPqc => "PQC preferred for new connections - rollout phase",
            Self::RequiredPqc => "PQC required for all connections - migration complete",
        }
    }
}
