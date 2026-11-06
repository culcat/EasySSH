//! Binary packet framing for the WebSocket SSH relay bridge.
//!
//! In the browser environment, WebSockets can only transmit text or binary frames.
//! `SshRelayFrame` defines the binary protocol wrapping raw SSH ciphertext and control
//! signals between the browser WebWorker (WASM `core`) and the TCP relay server.

use std::fmt;

/// Magic header bytes identifying an EasySSH relay protocol frame.
pub const RELAY_MAGIC: [u8; 4] = *b"ESSH";

/// Current relay protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum allowable payload size in a single relay frame (256 KiB) to prevent OOM.
pub const MAX_PAYLOAD_SIZE: usize = 256 * 1024;

/// Header size: Magic (4) + Version (1) + FrameType (1) + ChannelId (4) + PayloadLen (4) = 14 bytes.
pub const HEADER_SIZE: usize = 14;

/// Frame types supported by the relay bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Client -> Relay: Request TCP connection to target host:port.
    Connect = 0x01,
    /// Relay -> Client: TCP connection to target successfully established.
    Connected = 0x02,
    /// Bidirectional: Encrypted SSH payload bytes.
    Data = 0x03,
    /// Bidirectional: Flow control window adjustment credit (in bytes).
    WindowAdjust = 0x04,
    /// Bidirectional: Clean disconnection request / acknowledgement.
    Disconnect = 0x05,
    /// Relay -> Client: Error notification (e.g., DNS failure, TCP connection refused).
    Error = 0x06,
}

impl FrameType {
    pub fn from_u8(value: u8) -> Result<Self, FrameError> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Connected),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::WindowAdjust),
            0x05 => Ok(Self::Disconnect),
            0x06 => Ok(Self::Error),
            other => Err(FrameError::UnknownFrameType(other)),
        }
    }
}

/// A parsed binary frame sent over the WebSocket bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRelayFrame {
    pub version: u8,
    pub frame_type: FrameType,
    pub channel_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u8),
    UnknownFrameType(u8),
    PayloadTooLarge { length: usize, max: usize },
    BufferTooSmall,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(magic) => write!(f, "invalid magic header: {:?}", magic),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {}", v),
            Self::UnknownFrameType(t) => write!(f, "unknown frame type: {:#04x}", t),
            Self::PayloadTooLarge { length, max } => {
                write!(f, "payload size {} exceeds maximum allowed {}", length, max)
            }
            Self::BufferTooSmall => write!(f, "buffer is too small for header"),
        }
    }
}

impl std::error::Error for FrameError {}

impl SshRelayFrame {
    /// Create a new relay frame.
    pub fn new(frame_type: FrameType, channel_id: u32, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            frame_type,
            channel_id,
            payload,
        }
    }

    /// Convenience constructor for raw SSH ciphertext data frame.
    pub fn data(channel_id: u32, payload: Vec<u8>) -> Self {
        Self::new(FrameType::Data, channel_id, payload)
    }

    /// Convenience constructor for a flow-control window adjustment frame.
    pub fn window_adjust(channel_id: u32, bytes_credit: u32) -> Self {
        Self::new(
            FrameType::WindowAdjust,
            channel_id,
            bytes_credit.to_be_bytes().to_vec(),
        )
    }

    /// Convenience constructor for a connect request frame.
    pub fn connect(channel_id: u32, target_host: &str, target_port: u16) -> Self {
        let mut payload = Vec::with_capacity(2 + target_host.len());
        payload.extend_from_slice(&target_port.to_be_bytes());
        payload.extend_from_slice(target_host.as_bytes());
        Self::new(FrameType::Connect, channel_id, payload)
    }

    /// Serialize the frame to binary bytes for WebSocket transmission.
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len();
        let mut bytes = Vec::with_capacity(HEADER_SIZE + payload_len);

        bytes.extend_from_slice(&RELAY_MAGIC);
        bytes.push(self.version);
        bytes.push(self.frame_type as u8);
        bytes.extend_from_slice(&self.channel_id.to_be_bytes());
        bytes.extend_from_slice(&(payload_len as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    /// Attempt to parse a single frame from the input byte slice.
    ///
    /// Returns:
    /// - `Ok(Some((frame, bytes_consumed)))` if a complete frame was decoded.
    /// - `Ok(None)` if more bytes are needed to complete the header or payload.
    /// - `Err(FrameError)` if the data violates protocol framing invariants.
    pub fn decode(src: &[u8]) -> Result<Option<(Self, usize)>, FrameError> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        let magic = [src[0], src[1], src[2], src[3]];
        if magic != RELAY_MAGIC {
            return Err(FrameError::InvalidMagic(magic));
        }

        let version = src[4];
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }

        let frame_type = FrameType::from_u8(src[5])?;
        let channel_id = u32::from_be_bytes([src[6], src[7], src[8], src[9]]);
        let payload_len = u32::from_be_bytes([src[10], src[11], src[12], src[13]]) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge {
                length: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let total_frame_len = HEADER_SIZE + payload_len;
        if src.len() < total_frame_len {
            return Ok(None); // Need more bytes for the full payload
        }

        let payload = src[HEADER_SIZE..total_frame_len].to_vec();
        let frame = Self {
            version,
            frame_type,
            channel_id,
            payload,
        };

        Ok(Some((frame, total_frame_len)))
    }
}

/// Accumulating stream decoder for reassembling fragmented WebSocket chunks.
#[derive(Debug, Default)]
pub struct RelayFrameDecoder {
    buffer: Vec<u8>,
}

impl RelayFrameDecoder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Push new chunk of incoming network bytes.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Read next complete frame if available.
    pub fn poll_frame(&mut self) -> Result<Option<SshRelayFrame>, FrameError> {
        match SshRelayFrame::decode(&self.buffer)? {
            Some((frame, consumed)) => {
                self.buffer.drain(..consumed);
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    /// Return count of unparsed bytes currently in buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let frame = SshRelayFrame::data(42, b"SSH-2.0-TestCiphertext".to_vec());
        let encoded = frame.encode();

        assert_eq!(encoded.len(), HEADER_SIZE + frame.payload.len());

        let (decoded, consumed) = SshRelayFrame::decode(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_partial_frame_decoding() {
        let frame = SshRelayFrame::data(1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let encoded = frame.encode();

        // Feed only partial header
        assert_eq!(SshRelayFrame::decode(&encoded[..8]).unwrap(), None);

        // Feed header but only half payload
        assert_eq!(
            SshRelayFrame::decode(&encoded[..HEADER_SIZE + 4]).unwrap(),
            None
        );

        // Feed entire buffer
        let (decoded, consumed) = SshRelayFrame::decode(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut encoded = SshRelayFrame::data(1, vec![1, 2, 3]).encode();
        encoded[0] = b'X';
        assert!(matches!(
            SshRelayFrame::decode(&encoded),
            Err(FrameError::InvalidMagic(_))
        ));
    }

    #[test]
    fn test_decoder_stream_reassembly() {
        let mut decoder = RelayFrameDecoder::new();
        let frame1 = SshRelayFrame::data(10, b"frame1".to_vec());
        let frame2 = SshRelayFrame::data(20, b"frame2-longer-payload".to_vec());

        let mut stream = frame1.encode();
        stream.extend_from_slice(&frame2.encode());

        // Feed in 5-byte chunks
        let mut extracted = Vec::new();
        for chunk in stream.chunks(5) {
            decoder.push_bytes(chunk);
            while let Some(frame) = decoder.poll_frame().unwrap() {
                extracted.push(frame);
            }
        }

        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0], frame1);
        assert_eq!(extracted[1], frame2);
        assert_eq!(decoder.buffered_bytes(), 0);
    }
}
