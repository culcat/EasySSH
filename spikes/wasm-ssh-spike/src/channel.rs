//! Bounded channel and window-based flow control backpressure implementation.
//!
//! Under heavy stdout bursts (such as `cat hugefile`), an unbounded channel would
//! quickly accumulate hundreds of megabytes in the WebWorker heap, causing browser tab
//! termination due to OOM.
//!
//! This module provides:
//! 1. `BoundedRelayQueue`: Ring/deque buffer with strict byte-level capacity limit.
//! 2. `SshWindowFlowControl`: SSH-2.0 RFC 4254 channel sliding window flow controller.

use crate::frame::SshRelayFrame;
use std::collections::VecDeque;
use std::fmt;

/// Default byte capacity limit for the inbound relay queue (64 KiB).
pub const DEFAULT_QUEUE_BYTE_LIMIT: usize = 64 * 1024;

/// Default SSH channel window size (256 KiB).
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 256 * 1024;

/// Errors arising from backpressure conditions.
#[derive(Debug, PartialEq, Eq)]
pub enum BackpressureError {
    /// The inbound byte capacity has been reached. Sender must wait.
    QueueFull {
        current_bytes: usize,
        limit_bytes: usize,
        attempted_bytes: usize,
    },
    /// The remote peer's SSH sliding window has been exhausted.
    WindowExhausted { available_window: u32 },
}

impl fmt::Display for BackpressureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull {
                current_bytes,
                limit_bytes,
                attempted_bytes,
            } => {
                write!(
                    f,
                    "queue limit reached: {}/{} bytes (attempted +{})",
                    current_bytes, limit_bytes, attempted_bytes
                )
            }
            Self::WindowExhausted { available_window } => {
                write!(
                    f,
                    "sliding window exhausted: {} available credits",
                    available_window
                )
            }
        }
    }
}

impl std::error::Error for BackpressureError {}

/// A bounded byte-tracking queue for relay frames.
#[derive(Debug)]
pub struct BoundedRelayQueue {
    queue: VecDeque<SshRelayFrame>,
    max_bytes: usize,
    current_bytes: usize,
    peak_bytes: usize,
    total_bytes_enqueued: u64,
    total_bytes_dequeued: u64,
    backpressure_events: u64,
}

impl BoundedRelayQueue {
    /// Create a new queue with a maximum byte limit.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_bytes,
            current_bytes: 0,
            peak_bytes: 0,
            total_bytes_enqueued: 0,
            total_bytes_dequeued: 0,
            backpressure_events: 0,
        }
    }

    /// Try to push a frame into the queue.
    /// Returns `Err(BackpressureError::QueueFull)` if pushing would exceed `max_bytes`.
    pub fn try_push(&mut self, frame: SshRelayFrame) -> Result<(), BackpressureError> {
        let frame_bytes = frame.payload.len();
        if self.current_bytes + frame_bytes > self.max_bytes {
            self.backpressure_events += 1;
            return Err(BackpressureError::QueueFull {
                current_bytes: self.current_bytes,
                limit_bytes: self.max_bytes,
                attempted_bytes: frame_bytes,
            });
        }

        self.current_bytes += frame_bytes;
        if self.current_bytes > self.peak_bytes {
            self.peak_bytes = self.current_bytes;
        }
        self.total_bytes_enqueued += frame_bytes as u64;
        self.queue.push_back(frame);

        Ok(())
    }

    /// Pop the next available frame from the queue.
    pub fn pop(&mut self) -> Option<SshRelayFrame> {
        let frame = self.queue.pop_front()?;
        self.current_bytes -= frame.payload.len();
        self.total_bytes_dequeued += frame.payload.len() as u64;
        Some(frame)
    }

    /// Current buffered byte count.
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Maximum byte capacity limit.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Highest memory footprint reached in bytes during execution.
    pub fn peak_bytes(&self) -> usize {
        self.peak_bytes
    }

    /// Total bytes that traversed through the queue.
    pub fn total_bytes_enqueued(&self) -> u64 {
        self.total_bytes_enqueued
    }

    /// Number of frames currently in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Total number of times backpressure was triggered.
    pub fn backpressure_events(&self) -> u64 {
        self.backpressure_events
    }
}

/// Sliding window flow controller modeled after RFC 4254 (SSH Channel Flow Control).
#[derive(Debug, Clone)]
pub struct SshWindowFlowControl {
    /// Remote peer's remaining receive window (how many bytes we can send).
    remote_window: u32,
    /// Our local remaining receive window (how many bytes remote can send us).
    local_window: u32,
    /// Maximum allowable local window (threshold for sending window adjustments).
    local_window_max: u32,
}

impl SshWindowFlowControl {
    pub fn new(initial_window: u32) -> Self {
        Self {
            remote_window: initial_window,
            local_window: initial_window,
            local_window_max: initial_window,
        }
    }

    /// Available window for sending outbound data.
    pub fn remote_window(&self) -> u32 {
        self.remote_window
    }

    /// Current local window credit.
    pub fn local_window(&self) -> u32 {
        self.local_window
    }

    /// Check if we can send `bytes` and deduct from remote window.
    pub fn consume_remote_window(&mut self, bytes: u32) -> Result<(), BackpressureError> {
        if bytes > self.remote_window {
            return Err(BackpressureError::WindowExhausted {
                available_window: self.remote_window,
            });
        }
        self.remote_window -= bytes;
        Ok(())
    }

    /// Record receipt of `bytes` by local consumer and return optional adjustment credit to send to peer.
    /// Replenishes the window when it drops below half of `local_window_max`.
    pub fn on_bytes_consumed(&mut self, bytes: u32) -> Option<u32> {
        self.local_window = self.local_window.saturating_sub(bytes);
        let threshold = self.local_window_max / 2;
        if self.local_window <= threshold {
            let credit = self.local_window_max - self.local_window;
            self.local_window += credit;
            Some(credit)
        } else {
            None
        }
    }

    /// Receive remote peer's window adjustment frame.
    pub fn replenish_remote_window(&mut self, credit: u32) {
        self.remote_window = self.remote_window.saturating_add(credit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_enforces_byte_limit() {
        let mut queue = BoundedRelayQueue::new(100);

        let frame1 = SshRelayFrame::data(1, vec![0u8; 60]);
        let frame2 = SshRelayFrame::data(1, vec![0u8; 30]);
        let frame3 = SshRelayFrame::data(1, vec![0u8; 20]); // 60 + 30 + 20 = 110 > 100

        assert!(queue.try_push(frame1).is_ok());
        assert_eq!(queue.current_bytes(), 60);

        assert!(queue.try_push(frame2).is_ok());
        assert_eq!(queue.current_bytes(), 90);

        // Third frame must fail with QueueFull
        let err = queue.try_push(frame3).unwrap_err();
        assert!(matches!(err, BackpressureError::QueueFull { .. }));
        assert_eq!(queue.current_bytes(), 90);
        assert_eq!(queue.backpressure_events(), 1);

        // Pop one frame, freeing 60 bytes
        let popped = queue.pop().unwrap();
        assert_eq!(popped.payload.len(), 60);
        assert_eq!(queue.current_bytes(), 30);

        // Now frame3 can be pushed
        let frame3_retry = SshRelayFrame::data(1, vec![0u8; 20]);
        assert!(queue.try_push(frame3_retry).is_ok());
        assert_eq!(queue.current_bytes(), 50);
        assert_eq!(queue.peak_bytes(), 90);
    }

    #[test]
    fn test_sliding_window_flow_control() {
        let mut flow = SshWindowFlowControl::new(1000);

        // Consume 600 bytes outbound
        assert!(flow.consume_remote_window(600).is_ok());
        assert_eq!(flow.remote_window(), 400);

        // Try to consume 500 bytes (exceeds 400)
        assert!(matches!(
            flow.consume_remote_window(500),
            Err(BackpressureError::WindowExhausted { .. })
        ));

        // Replenish window with 1000 credits
        flow.replenish_remote_window(1000);
        assert_eq!(flow.remote_window(), 1400);
        assert!(flow.consume_remote_window(500).is_ok());
        assert_eq!(flow.remote_window(), 900);
    }
}
