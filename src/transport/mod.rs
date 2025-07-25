//! Core QUIC transport layer
//!
//! This module contains the essential QUIC protocol functionality needed for NAT traversal.
//! It is streamlined to include only the necessary components for the ant-quic implementation.

// Re-export essential types from the core QUIC implementation
pub use crate::connection::{
    Connection as QuicConnection, ConnectionError, ConnectionStats, Event as ConnectionEvent,
    PathStats, ShouldTransmit,
};

pub use crate::endpoint::{
    AcceptError, ConnectError, ConnectionHandle, Endpoint as QuicEndpoint, Incoming,
};

pub use crate::shared::{ConnectionId, EcnCodepoint};
pub use crate::transport_error::{Code as TransportErrorCode, Error as TransportError};
pub use crate::transport_parameters;

// Stream-related types
pub use crate::connection::{
    FinishError, ReadError, RecvStream, SendStream, StreamEvent, Streams, WriteError,
};

// Module-private imports
