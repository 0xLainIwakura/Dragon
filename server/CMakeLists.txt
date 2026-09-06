cmake_minimum_required(VERSION 3.20)
project(dragon_server C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(_GNU_SOURCE)

add_executable(server
    dragon_server.c
    crypto_dragon.c
    transport.c
    transport_tcp.c
    transport_http.c
    transport_https.c
)

add_executable(keygen keygen.c)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(SODIUM   REQUIRED libsodium)
pkg_check_modules(MONGOC mongoc2)
if(NOT MONGOC_FOUND)
    pkg_check_modules(MONGOC REQUIRED libmongoc-1.0)
endif()

pkg_check_modules(BSON bson2)
if(NOT BSON_FOUND)
    pkg_check_modules(BSON REQUIRED libbson-1.0)
endif()
pkg_check_modules(READLINE REQUIRED readline)

target_include_directories(server PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${MONGOC_INCLUDE_DIRS}
    ${BSON_INCLUDE_DIRS}
    ${READLINE_INCLUDE_DIRS}
)

target_link_directories(server PRIVATE
    ${SODIUM_LIBRARY_DIRS}
    ${MONGOC_LIBRARY_DIRS}
    ${BSON_LIBRARY_DIRS}
    ${READLINE_LIBRARY_DIRS}
)

target_link_libraries(server PRIVATE
    ${SODIUM_LIBRARIES}
    ${MONGOC_LIBRARIES}
    ${BSON_LIBRARIES}
    ${READLINE_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

target_include_directories(keygen PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_directories(keygen PRIVATE ${SODIUM_LIBRARY_DIRS})
target_link_libraries(keygen PRIVATE
    ${SODIUM_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)