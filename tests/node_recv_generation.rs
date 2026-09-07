//! Receive provenance must survive queueing and reconnects through the public Node API.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{Node, NodeConfig, bootstrap_cache::BootstrapCacheConfig};
use std::{net::SocketAddr, time::Duration};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);

async fn node() -> Node {
    Node::with_config(
        NodeConfig::builder()
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().expect("loopback"))
            .mdns_enabled(false)
            .bootstrap_cache(BootstrapCacheConfig::builder().persist(false).build())
            .build(),
    )
    .await
    .expect("node")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recv_generation_survives_queued_reconnect_and_recv_stays_compatible() {
    let sender = node().await;
    let receiver = node().await;
    let sender_id = sender.peer_id();
    let receiver_id = receiver.peer_id();
    // Dual-stack sockets can report [::] even when configured with IPv4 loopback.
    let bound = receiver.local_addr().expect("receiver address");
    let addr = SocketAddr::from(([127, 0, 0, 1], bound.port()));
    let accept = {
        let receiver = receiver.clone();
        tokio::spawn(async move { while receiver.accept().await.is_some() {} })
    };
    assert_eq!(receiver.current_connection_generation(&sender_id), None);
    timeout(DEADLINE, sender.connect_addr(addr))
        .await
        .expect("connect timeout")
        .expect("connect");
    sender
        .send(&receiver_id, b"old uni")
        .await
        .expect("uni send");
    timeout(DEADLINE, async {
        while receiver.data_channel_diagnostics().data_tx_depth != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("old frame queued before reconnect");
    let old = receiver
        .current_connection_generation(&sender_id)
        .expect("old generation");
    assert_ne!(old, u64::MAX);
    // Endpoint instances allocate from the same process-wide namespace.
    assert_ne!(
        sender.current_connection_generation(&receiver_id),
        Some(old)
    );

    let mut previous = old;
    for cycle in 0..3 {
        sender
            .disconnect(&receiver_id)
            .await
            .expect("disconnect sender");
        // The sender's close may have already removed the remote peer.
        assert!(matches!(
            receiver.disconnect(&sender_id).await,
            Ok(())
                | Err(ant_quic::NodeError::Endpoint(
                    ant_quic::EndpointError::PeerNotFound(_)
                ))
        ));
        assert_eq!(receiver.current_connection_generation(&sender_id), None);
        timeout(DEADLINE, sender.connect_addr(addr))
            .await
            .expect("reconnect timeout")
            .expect("reconnect");
        sender
            .send_with_receive_ack(&receiver_id, b"new ack", DEADLINE)
            .await
            .expect("ACK admission");
        let current = receiver
            .current_connection_generation(&sender_id)
            .expect("current generation");
        assert!(current > previous);
        previous = current;
        if cycle == 0 {
            assert_eq!(
                timeout(DEADLINE, receiver.recv_with_generation())
                    .await
                    .expect("old recv timeout")
                    .expect("old recv"),
                (sender_id, old, b"old uni".to_vec()),
                "dequeue must not relabel the old reader's bytes"
            );
        }
        assert_eq!(
            timeout(DEADLINE, receiver.recv_with_generation())
                .await
                .expect("ack recv timeout")
                .expect("ack recv"),
            (sender_id, current, b"new ack".to_vec())
        );
    }
    sender
        .send(&receiver_id, b"compatible")
        .await
        .expect("send");
    assert_eq!(
        timeout(DEADLINE, receiver.recv())
            .await
            .expect("recv timeout")
            .expect("recv"),
        (sender_id, b"compatible".to_vec())
    );
    receiver.clone().shutdown().await;
    assert_eq!(receiver.current_connection_generation(&sender_id), None);
    assert!(receiver.recv_with_generation().await.is_err());
    sender.shutdown().await;
    accept.abort();
}
