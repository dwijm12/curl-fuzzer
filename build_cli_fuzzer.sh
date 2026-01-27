#!/bin/bash
#
# Script to build the curl CLI fuzzer after curl sources have been downloaded
#
# This script should be run after the main build completes, as it requires
# the curl tool sources to be available in the build directory.
#

set -e

BUILD_DIR="${BUILD_DIR:-$(pwd)/build}"
CURL_FUZZER_SRC="$(dirname "$0")/fuzz_curl_cli.c"

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory $BUILD_DIR does not exist"
    echo "Please run ./mainline.sh first to build dependencies"
    exit 1
fi

# Find curl source directory
CURL_SRC_DIR=""
if [ -d "$BUILD_DIR/curl/src/curl_external/src" ]; then
    CURL_SRC_DIR="$BUILD_DIR/curl/src/curl_external/src"
elif [ -n "$CURL_SOURCE_DIR" ] && [ -d "$CURL_SOURCE_DIR/src" ]; then
    CURL_SRC_DIR="$CURL_SOURCE_DIR/src"
fi

if [ -z "$CURL_SRC_DIR" ] || [ ! -d "$CURL_SRC_DIR" ]; then
    echo "Error: Could not find curl source directory"
    echo "Tried:"
    echo "  - $BUILD_DIR/curl/src/curl_external/src"
    echo "  - \$CURL_SOURCE_DIR/src"
    exit 1
fi

echo "Found curl source directory: $CURL_SRC_DIR"

# Check if tool_operate.c exists
if [ ! -f "$CURL_SRC_DIR/tool_operate.c" ]; then
    echo "Error: tool_operate.c not found in $CURL_SRC_DIR"
    exit 1
fi

# Find curl install directory
CURL_INSTALL_DIR=""
for dir in "$BUILD_DIR/curl-install" "$BUILD_DIR/install"; do
    if [ -d "$dir/include/curl" ]; then
        CURL_INSTALL_DIR="$dir"
        break
    fi
done

if [ -z "$CURL_INSTALL_DIR" ]; then
    echo "Error: Could not find curl install directory"
    exit 1
fi

echo "Found curl install directory: $CURL_INSTALL_DIR"

# Collect all tool_*.c files except tool_main.c
TOOL_SOURCES=$(find "$CURL_SRC_DIR" -name "tool_*.c" ! -name "tool_main.c" | tr '\n' ' ')

if [ -z "$TOOL_SOURCES" ]; then
    echo "Error: No tool sources found in $CURL_SRC_DIR"
    exit 1
fi

echo "Found $(echo $TOOL_SOURCES | wc -w) tool source files"

# Set up compiler and flags
CC="${CC:-clang}"
CFLAGS="${CFLAGS:--fsanitize=address,fuzzer-no-link}"
FUZZ_FLAGS="-fsanitize=fuzzer"
OPT_FLAGS="-g -O1"

# Collect library paths
ZLIB_LIB="$BUILD_DIR/zlib-install/lib/libz.a"
ZSTD_LIB="$BUILD_DIR/zstd-install/lib/libzstd.a"
NGHTTP2_LIB="$BUILD_DIR/nghttp2-install/lib/libnghttp2.a"
LIBIDN2_LIB="$BUILD_DIR/libidn2-install/lib/libidn2.a"
LDAP_LIB="$BUILD_DIR/openldap-install/lib/libldap.a"
LBER_LIB="$BUILD_DIR/openldap-install/lib/liblber.a"
CURL_LIB="$CURL_INSTALL_DIR/lib/libcurl.a"

# Check for OpenSSL (might not be present in memory sanitizer builds)
OPENSSL_LIBS=""
if [ -f "$BUILD_DIR/openssl-install/lib/libssl.a" ]; then
    OPENSSL_LIBS="$BUILD_DIR/openssl-install/lib/libssl.a $BUILD_DIR/openssl-install/lib/libcrypto.a"
fi

# Check for brotli (system library)
BROTLI_LIBS=""
if pkg-config --exists libbrotlidec 2>/dev/null; then
    BROTLI_LIBS="$(pkg-config --libs libbrotlidec libbrotlienc libbrotlicommon)"
elif [ -f "/usr/lib/x86_64-linux-gnu/libbrotlidec.a" ]; then
    BROTLI_LIBS="-lbrotlidec -lbrotlienc -lbrotlicommon"
fi

# Build the fuzzer
echo "Building curl CLI fuzzer..."
set -x

$CC $OPT_FLAGS $CFLAGS $FUZZ_FLAGS \
    -DCURL_DISABLE_DEPRECATION \
    -DCURL_STRICTER \
    -I"$CURL_INSTALL_DIR/include" \
    -I"$CURL_SRC_DIR" \
    -I"$(dirname "$CURL_SRC_DIR")/lib" \
    "$CURL_FUZZER_SRC" \
    $TOOL_SOURCES \
    $CURL_LIB \
    $NGHTTP2_LIB \
    $OPENSSL_LIBS \
    $ZLIB_LIB \
    $ZSTD_LIB \
    $LIBIDN2_LIB \
    $LDAP_LIB \
    $LBER_LIB \
    $BROTLI_LIBS \
    -lpthread \
    -lm \
    -o "$BUILD_DIR/curl_fuzzer_cli"

set +x

if [ -f "$BUILD_DIR/curl_fuzzer_cli" ]; then
    echo "Successfully built curl_fuzzer_cli"
    echo "Output: $BUILD_DIR/curl_fuzzer_cli"
    exit 0
else
    echo "Error: Failed to build curl_fuzzer_cli"
    exit 1
fi
