//! Minimal test to debug connection issue
use ant_quic::{
    ClientConfig, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

#[tokio::test]
async fn test_minimal_connection() {
    // Install crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Generate certificate using rcgen
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der: rustls::pki_types::CertificateDer = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());

    println!("Certificate generated");

    // Create server
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    println!("Server crypto config created");

    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    let server =
        Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_addr = server.local_addr().unwrap();

    println!("Server listening on {}", server_addr);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        println!("Server: Waiting for connections...");
        match tokio::time::timeout(std::time::Duration::from_secs(10), server.accept()).await {
            Ok(Some(incoming)) => {
                println!("Server: Got incoming connection");
                match incoming.await {
                    Ok(conn) => {
                        println!(
                            "Server: Connection established from {}",
                            conn.remote_address()
                        );
                        conn
                    }
                    Err(e) => {
                        println!("Server: Connection error: {}", e);
                        panic!("Server failed: {}", e);
                    }
                }
            }
            Ok(None) => {
                panic!("Server: accept() returned None");
            }
            Err(_) => {
                panic!("Server: Timeout waiting for connection");
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Create client
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    println!("Client endpoint created");

    // Configure client with dangerous verifier
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    println!("Client crypto config created");

    let client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client.set_default_client_config(client_config);

    println!("Client connecting to {}", server_addr);

    // Try to connect with explicit timeout
    let connecting = client.connect(server_addr, "localhost").unwrap();

    match tokio::time::timeout(std::time::Duration::from_secs(5), connecting).await {
        Ok(Ok(conn)) => {
            println!("Client: Connected to {}", conn.remote_address());
            // Connection successful
        }
        Ok(Err(e)) => {
            println!("Client: Connection error: {}", e);
            // Print more details
            panic!("Connection failed: {:?}", e);
        }
        Err(_) => {
            println!("Client: Connection timed out after 5 seconds");
            panic!("Connection timed out");
        }
    }

    // Wait for server to finish
    let _ = server_handle.await;
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        println!("SkipServerVerification: verify_server_cert called");
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        println!("SkipServerVerification: verify_tls12_signature called");
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        println!("SkipServerVerification: verify_tls13_signature called");
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        println!("SkipServerVerification: supported_verify_schemes called");
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::Unknown(0xFE3C), // ML-DSA-65
        ]
    }
}
