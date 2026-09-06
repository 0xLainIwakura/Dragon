#!/bin/bash
set -e

echo "[*] Setting up MinGW cross-compilation dependencies"
mkdir -p deps/mingw64/{include,lib}

# -- libsodium for MinGW --
echo "[*] Downloading libsodium"
wget -q https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-mingw.tar.gz
tar xzf libsodium-1.0.20-mingw.tar.gz
cp -r libsodium-win64/include/* deps/mingw64/include/
cp -r libsodium-win64/lib/*     deps/mingw64/lib/
rm -rf libsodium-win64 libsodium-1.0.20-mingw.tar.gz
echo "[+] libsodium ready"

# -- OpenSSL for MinGW --
echo "[*] Building OpenSSL for mingw64 (this can take a few minutes)"
OPENSSL_VER="3.3.1"
wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz"
tar xzf "openssl-${OPENSSL_VER}.tar.gz"
cd "openssl-${OPENSSL_VER}"
./Configure mingw64 \
    --cross-compile-prefix=x86_64-w64-mingw32- \
    --prefix="$(pwd)/../deps/mingw64" \
    no-shared no-tests
make -j"$(nproc)"
make install_sw
cd ..
rm -rf "openssl-${OPENSSL_VER}" "openssl-${OPENSSL_VER}.tar.gz"

echo ""
echo "[+] All dependencies installed in deps/mingw64/"
echo "[+] You can now use 'generate' from the server console."