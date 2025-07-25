//! Lock-free ring buffer for event storage

use super::event::{Event, TraceId};
use std::ptr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[cfg(feature = "trace-index")]
use dashmap::DashMap;

/// Configuration for the event log
pub struct TraceConfig;

impl TraceConfig {
    /// Ring buffer size (must be power of 2)
    #[cfg(not(feature = "trace-minimal"))]
    pub const BUFFER_SIZE: usize = 65536; // ~8MB

    #[cfg(feature = "trace-minimal")]
    pub const BUFFER_SIZE: usize = 4096; // ~512KB

    pub const BUFFER_MASK: usize = Self::BUFFER_SIZE - 1;
}

/// Lock-free ring buffer for event storage
pub struct EventLog {
    /// Fixed-size ring buffer
    events: Box<[std::cell::UnsafeCell<Event>; TraceConfig::BUFFER_SIZE]>,
    /// Write index (always increments)
    write_index: AtomicU64,
    /// Sequence counter for events
    sequence_counter: AtomicU32,

    /// Optional indices for fast queries
    #[cfg(feature = "trace-index")]
    indices: EventIndices,
}

#[cfg(feature = "trace-index")]
struct EventIndices {
    /// Index by trace ID
    by_trace: DashMap<TraceId, Vec<u32>>,
    /// Index by peer
    by_peer: DashMap<[u8; 32], Vec<u32>>,
}

// Ensure BUFFER_SIZE is a power of 2
const _: () = assert!(TraceConfig::BUFFER_SIZE.count_ones() == 1);

impl EventLog {
    /// Create a new event log
    pub fn new() -> Self {
        let events: Vec<std::cell::UnsafeCell<Event>> = (0..TraceConfig::BUFFER_SIZE)
            .map(|_| std::cell::UnsafeCell::new(Event::default()))
            .collect();
        let events = events.into_boxed_slice();
        let events = unsafe {
            Box::from_raw(Box::into_raw(events)
                as *mut [std::cell::UnsafeCell<Event>; TraceConfig::BUFFER_SIZE])
        };

        EventLog {
            events,
            write_index: AtomicU64::new(0),
            sequence_counter: AtomicU32::new(0),
            #[cfg(feature = "trace-index")]
            indices: EventIndices {
                by_trace: DashMap::new(),
                by_peer: DashMap::new(),
            },
        }
    }

    /// Log an event (lock-free)
    pub fn log(&self, mut event: Event) {
        // Set sequence number
        event.sequence = self.sequence_counter.fetch_add(1, Ordering::Relaxed);

        // Get write position
        let idx = self.write_index.fetch_add(1, Ordering::Relaxed);
        let slot = (idx & TraceConfig::BUFFER_MASK as u64) as usize;

        // Write to ring buffer (atomic write)
        unsafe {
            let ptr = self.events[slot].get();
            ptr::write_volatile(ptr, event.clone());
        }

        // Update indices if enabled
        #[cfg(feature = "trace-index")]
        self.update_indices(slot, &event);
    }

    #[cfg(feature = "trace-index")]
    fn update_indices(&self, slot: usize, event: &Event) {
        // Index by trace ID
        self.indices
            .by_trace
            .entry(event.trace_id)
            .or_insert_with(Vec::new)
            .push(slot as u32);

        // Index by peer if present in event data
        use super::event::EventData;
        match &event.event_data {
            EventData::HolePunchingStarted { peer, .. }
            | EventData::HolePunchingSucceeded { peer, .. }
            | EventData::ObservedAddressReceived {
                from_peer: peer, ..
            } => {
                self.indices
                    .by_peer
                    .entry(*peer)
                    .or_insert_with(Vec::new)
                    .push(slot as u32);
            }
            _ => {}
        }
    }

    /// Get recent events (newest first)
    pub fn recent_events(&self, count: usize) -> Vec<Event> {
        let current_idx = self.write_index.load(Ordering::Relaxed);
        let mut events = Vec::with_capacity(count.min(TraceConfig::BUFFER_SIZE));

        // Don't scan more than we've written
        let scan_count = count
            .min(current_idx as usize)
            .min(TraceConfig::BUFFER_SIZE);

        for i in 0..scan_count {
            let idx = current_idx.saturating_sub(i as u64 + 1);
            if idx >= current_idx {
                break; // Underflow protection
            }

            let slot = (idx & TraceConfig::BUFFER_MASK as u64) as usize;

            let event = unsafe {
                let ptr = self.events[slot].get();
                ptr::read_volatile(ptr)
            };

            // Skip uninitialized slots
            if event.timestamp == 0 {
                break;
            }

            events.push(event);
        }

        events
    }

    /// Query events by trace ID
    #[cfg(feature = "trace-index")]
    pub fn query_trace(&self, trace_id: TraceId) -> Vec<Event> {
        if let Some(indices) = self.indices.by_trace.get(&trace_id) {
            indices
                .iter()
                .map(|&slot| unsafe {
                    let ptr = self.events[slot as usize].get();
                    ptr::read_volatile(ptr)
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Query events by trace ID (without index)
    #[cfg(not(feature = "trace-index"))]
    pub fn query_trace(&self, trace_id: TraceId) -> Vec<Event> {
        let current_idx = self.write_index.load(Ordering::Relaxed);
        let mut events = Vec::new();

        // Only scan up to current write position or buffer size
        let scan_count = current_idx.min(TraceConfig::BUFFER_SIZE as u64);

        // Linear scan through buffer
        for i in 0..scan_count {
            let idx = current_idx.saturating_sub(i + 1);
            let slot = (idx & TraceConfig::BUFFER_MASK as u64) as usize;

            let event = unsafe {
                let ptr = self.events[slot].get();
                ptr::read_volatile(ptr)
            };

            if event.timestamp == 0 {
                break;
            }

            if event.trace_id == trace_id {
                events.push(event);
            }
        }

        events
    }

    /// Query events by time range
    pub fn query_time_range(&self, start: u64, end: u64) -> Vec<Event> {
        let current_idx = self.write_index.load(Ordering::Relaxed);
        let mut events = Vec::new();

        for i in 0..TraceConfig::BUFFER_SIZE {
            let idx = current_idx.saturating_sub(i as u64 + 1);
            let slot = (idx & TraceConfig::BUFFER_MASK as u64) as usize;

            let event = unsafe {
                let ptr = self.events[slot].get();
                ptr::read_volatile(ptr)
            };

            if event.timestamp == 0 || event.timestamp < start {
                break;
            }

            if event.timestamp <= end {
                events.push(event);
            }
        }

        events.reverse(); // Return in chronological order
        events
    }

    /// Get total number of events logged
    pub fn event_count(&self) -> u64 {
        self.write_index.load(Ordering::Relaxed)
    }

    // Alias methods for TraceQuery compatibility

    /// Get events by trace ID (alias for query_trace)
    pub fn get_events_by_trace(&self, trace_id: TraceId) -> Vec<Event> {
        self.query_trace(trace_id)
    }

    /// Get recent events (alias for recent_events)
    pub fn get_recent_events(&self, count: usize) -> Vec<Event> {
        self.recent_events(count)
    }

    /// Get events in time range (alias for query_time_range)
    pub fn get_events_in_range(&self, start: u64, end: u64) -> Vec<Event> {
        self.query_time_range(start, end)
    }
}

// Safe to send across threads
unsafe impl Send for EventLog {}
unsafe impl Sync for EventLog {}

#[cfg(all(test, feature = "trace"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_ring_buffer_basic() {
        let log = EventLog::new();
        let trace_id = TraceId::new();

        // Log some events
        for i in 0..10 {
            let event = Event::packet_sent(100 + i, i as u64, trace_id);
            log.log(event);
        }

        // Check recent events
        let recent = log.recent_events(5);
        assert_eq!(recent.len(), 5);

        // Most recent should have highest packet number
        match &recent[0].event_data {
            crate::tracing::event::EventData::PacketSent { packet_num, .. } => {
                assert_eq!(*packet_num, 9);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_concurrent_logging() {
        let log = Arc::new(EventLog::new());
        let mut handles = vec![];

        // Spawn multiple threads logging concurrently
        for thread_id in 0..4 {
            let log_clone = log.clone();
            let handle = thread::spawn(move || {
                let trace_id = TraceId::new();
                for i in 0..100 {
                    let event = Event::packet_sent(thread_id * 1000 + i, i as u64, trace_id);
                    log_clone.log(event);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Should have logged 400 events
        assert_eq!(log.event_count(), 400);
    }

    #[test]
    fn test_ring_buffer_wraparound() {
        let log = EventLog::new();
        let trace_id = TraceId::new();

        // Log more events than buffer size
        for i in 0..(TraceConfig::BUFFER_SIZE + 100) {
            let event = Event::packet_sent(i as u32, i as u64, trace_id);
            log.log(event);
        }

        // Recent events should still work
        let recent = log.recent_events(10);
        assert_eq!(recent.len(), 10);
    }
}
