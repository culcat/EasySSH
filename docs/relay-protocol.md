# EasySSH WebSocket Ciphertext Relay Protocol Specification

> **Version:** 1.0  
> **Status:** Draft / Active  
> **Target Implementation:** `crates/relay` and `crates/wasm`

---

## 1. Overview & Threat Model

Web browsers cannot open arbitrary raw TCP sockets directly due to browser security sandboxing. To allow the web-based **React-UI** to connect to standard SSH servers on port 22, EasySSH uses a lightweight **WebSocket-to-TCP Relay** (`crates/relay`).

### Core Security Invariants

1. **Untrusted Intermediate (Zero-Knowledge Relay)**:
   The relay is treated as an untrusted third party.
   - All cryptographic handshakes, key exchanges (`Diffie-Hellman` / `Curve25519`), user authentications, and payload encryptions happen **inside the client browser's WebAssembly engine** using `russh`.
   - The relay **never** receives private keys, passwords, or decrypted terminal streams.
   - Even if the relay server is completely compromised or controlled by an adversary, the adversary only sees encrypted SSH packets and cannot decrypt the session or forge commands without failing client-side host key and signature checks.
2. **End-to-End Host Key Verification**:
   The client WASM engine performs full SSH host key verification directly against the server's public key. The relay cannot perform a Man-in-the-Middle (MITM) attack without causing a fatal `HostKeyStatus::Mismatch` alarm in the client UI.
3. **Stateless Forwarding**:
   The relay maintains no persistent logs of session data or keystrokes. It merely bridges bytes between a WebSocket connection and a TCP socket.

---

## 2. Transport & Handshake

### 2.1 Connection Establishment

- **Transport**: Secure WebSocket (`wss://`) in production; `ws://` permitted only for `localhost` development.
- **WebSocket Subprotocol**: `easyssh-relay-v1`
- **Path**: `/connect` (e.g. `wss://relay.example.com/connect`)

Upon opening the WebSocket connection, the client and relay perform a brief JSON-based control handshake before switching to raw binary forwarding.

### 2.2 Handshake Message Exchange

#### Step 1: Client Connect Request

Immediately after the WebSocket connection opens, the client MUST send a text frame containing a JSON `ConnectRequest`:

```json
{
  "type": "connect",
  "target_host": "bastion.internal.net",
  "target_port": 22,
  "auth_token": "optional-relay-access-token",
  "timeout_seconds": 15
}
```

##### Field Specifications:
- `type` (string, required): Must be `"connect"`.
- `target_host` (string, required): Fully qualified domain name (FQDN) or IPv4/IPv6 address of the destination SSH server.
- `target_port` (integer, optional): Target TCP port. Defaults to `22` if omitted. Must be in range `1..=65535`.
- `auth_token` (string, optional): Bearer token for relay access control and rate-limiting (if relay authentication is enabled).
- `timeout_seconds` (integer, optional): Maximum time the relay should wait for the remote TCP socket connection to complete. Defaults to `10`, maximum `30`.

#### Step 2: Relay Connect Response

The relay attempts to resolve `target_host` and open a TCP socket. It replies with a text frame containing a JSON `ConnectResponse`:

##### Success Response:
```json
{
  "status": "connected",
  "remote_addr": "198.51.100.24:22"
}
```

Once `status: "connected"` is transmitted, the connection transitions immediately to **Binary Stream Mode**.

##### Error Response:
```json
{
  "status": "error",
  "code": "CONNECTION_REFUSED",
  "message": "Connection refused by remote host 198.51.100.24:22"
}
```

If an error response is sent, the relay MUST immediately close the WebSocket with code `4400` or higher (see Section 5).

---

## 3. Binary Stream Mode (Data Transfer)

Once the handshake succeeds, **all subsequent WebSocket messages are binary frames**:

```
[ Browser WASM ] <=== WebSocket Binary Frames ===> [ Relay ] <=== Raw TCP Sockets ===> [ SSH Server ]
```

### 3.1 Downstream (Relay → Client)
- When the relay reads bytes from the TCP socket connected to the remote SSH server:
  - It packages the bytes into binary WebSocket frames.
  - The frame payload is verbatim the raw TCP stream (SSH banner, key exchange, encrypted packets).
  - Maximum single frame size: 64 KB (65,536 bytes).

### 3.2 Upstream (Client → Relay)
- When the client WASM `russh` engine produces outbound SSH packets:
  - It transmits them as binary WebSocket frames.
  - The relay reads each binary frame and writes its entire payload directly to the TCP socket.

### 3.3 Text Frames in Stream Mode Prohibited
Any text frame received by either peer after the handshake has succeeded constitutes a protocol violation and MUST cause the connection to terminate immediately with WebSocket close code `1002` (Protocol Error).

---

## 4. Flow Control, Backpressure, and Buffering

SSH sessions can generate significant bursts of data (e.g. streaming log files or running `cat`). Without backpressure, intermediate buffers in the relay or browser could consume unbounded RAM.

### Invariants:
1. **TCP to WebSocket Backpressure**:
   - The relay monitors the WebSocket send buffer (via Tokio tungstenite / axum / actix bounded channels).
   - If the WebSocket send buffer reaches high watermark (default 256 KB), the relay **stops reading from the TCP socket**.
   - This causes the kernel TCP window on the remote SSH server to fill, pausing transmission at the source SSH server.
   - Once the client consumes buffered WebSocket frames and the relay buffer drops below the low watermark (default 64 KB), the relay resumes reading from the TCP socket.
2. **WebSocket to TCP Backpressure**:
   - If the remote TCP socket is slow to accept writes, the relay pauses pulling incoming frames from the WebSocket connection.

---

## 5. Teardown & Closure Semantics

Either end may initiate teardown at any time:

### 5.1 Clean Termination
- **SSH Disconnect**: When the SSH session terminates cleanly (e.g. user runs `exit` or server sends `SSH_MSG_DISCONNECT`), the client or server terminates the TCP connection.
- **Relay Action on TCP EOF**: Upon detecting EOF on the TCP socket, the relay closes the WebSocket connection with code `1000` (Normal Closure).
- **Relay Action on WebSocket Close**: If the client closes the WebSocket (code `1000`), the relay sends a TCP `FIN` to the SSH server and drops the socket.

### 5.2 Error Codes & Close Codes

| Close Code | Identifier | Meaning |
|---|---|---|
| `1000` | Normal Closure | Clean disconnect by user or SSH exit. |
| `1002` | Protocol Error | Client sent malformed framing or unexpected text frame. |
| `1008` | Policy Violation | Target host forbidden by relay egress policy or token invalid. |
| `4001` | DNS Resolution Failed | Hostname could not be resolved by relay. |
| `4002` | Connection Timeout | Remote SSH server did not respond within timeout window. |
| `4003` | Connection Refused | Target server rejected TCP SYN packet. |
| `4004` | Host Forbidden | Target IP resolves to forbidden subnet (e.g. loopback/RFC 1918 if restricted). |

---

## 6. Relay Security & Egress Filtering

Production relay instances MUST implement sensible security hardening:

1. **SSRF (Server-Side Request Forgery) Protection**:
   Unless explicitly configured for private network access, public relays MUST reject connections targeting private or cloud metadata IP ranges:
   - `127.0.0.0/8` (Loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private IPv4)
   - `169.254.169.254` (Cloud Instance Metadata Service)
   - `::1` (IPv6 Loopback)
2. **Rate Limiting**:
   Relays should enforce maximum concurrent connections per IP address or auth token (default: 10 connections per token).
3. **Session Inactivity Timeout**:
   If zero bytes are exchanged across both TCP and WebSocket channels for longer than 300 seconds, the relay may close the connection with code `4000` (Idle Timeout).
