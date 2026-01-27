#!/bin/bash
#
# Script to build the curl CLI fuzzer after curl sources have been downloaded
# This version compiles tool sources individually with proper flags
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

# Find curl source and build directories
CURL_SRC_DIR="$BUILD_DIR/curl/src/curl_external"
CURL_BUILD_DIR="$BUILD_DIR/curl/src/curl_external-build"
CURL_INSTALL_DIR="$BUILD_DIR/curl-install"

if [ ! -d "$CURL_SRC_DIR/src" ]; then
    echo "Error: Could not find curl source directory at $CURL_SRC_DIR/src"
    exit 1
fi

if [ ! -d "$CURL_BUILD_DIR" ]; then
    echo "Error: Could not find curl build directory at $CURL_BUILD_DIR"
    exit 1
fi

echo "Found curl source directory: $CURL_SRC_DIR"
echo "Found curl build directory: $CURL_BUILD_DIR"
echo "Found curl install directory: $CURL_INSTALL_DIR"

# Create output directory for tool objects
OBJ_DIR="$BUILD_DIR/cli_fuzzer_objs"
mkdir -p "$OBJ_DIR"

# Set up compiler and flags
CC="${CC:-clang}"
CFLAGS="${CFLAGS:--fsanitize=address,fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping}"
OPT_FLAGS="-g -O1"

# Include paths (same as curl uses)
INCLUDES=(
    "-I$CURL_SRC_DIR/include"
    "-I$CURL_BUILD_DIR/lib"
    "-I$CURL_BUILD_DIR/include"
    "-I$CURL_SRC_DIR/lib"
    "-I$CURL_SRC_DIR/src"
    "-I$CURL_INSTALL_DIR/include"
)

# Defines (MUST match curl library build flags to avoid ABI mismatch)
DEFINES=(
    "-DHAVE_CONFIG_H"
    "-DBUILDING_LIBCURL"
    "-DCURL_STATICLIB"
    "-DDEBUGBUILD"
    "-DCURL_DISABLE_DEPRECATION"
)

# Compile each tool source file and helper sources
echo "Compiling tool sources..."
for src in "$CURL_SRC_DIR"/src/tool_*.c \
           "$CURL_SRC_DIR"/src/toolx/*.c \
           "$CURL_SRC_DIR"/src/config2setopts.c \
           "$CURL_SRC_DIR"/src/slist_wc.c \
           "$CURL_SRC_DIR"/src/terminal.c \
           "$CURL_SRC_DIR"/src/var.c; do
    [ ! -f "$src" ] && continue
    [ "$(basename "$src")" = "tool_main.c" ] && continue

    obj="$OBJ_DIR/$(basename "$src" .c).o"
    echo "  Compiling $(basename "$src")..."
    $CC $OPT_FLAGS $CFLAGS "${INCLUDES[@]}" "${DEFINES[@]}" -c "$src" -o "$obj" || {
        echo "Error compiling $src"
        exit 1
    }
done

# Compile fuzzer source
echo "Compiling fuzzer source..."
$CC $OPT_FLAGS $CFLAGS "${INCLUDES[@]}" "${DEFINES[@]}" -c "$CURL_FUZZER_SRC" -o "$OBJ_DIR/fuzz_curl_cli.o" || {
    echo "Error compiling fuzzer"
    exit 1
}

# Collect all object files
OBJ_FILES=$(find "$OBJ_DIR" -name "*.o" | tr '\n' ' ')

# Collect library paths
ZLIB_LIB="$BUILD_DIR/zlib-install/lib/libz.a"
ZSTD_LIB="$BUILD_DIR/zstd-install/lib/libzstd.a"
NGHTTP2_LIB="$BUILD_DIR/nghttp2-install/lib/libnghttp2.a"
LIBIDN2_LIB="$BUILD_DIR/libidn2-install/lib/libidn2.a"
LDAP_LIB="$BUILD_DIR/openldap-install/lib/libldap.a"
LBER_LIB="$BUILD_DIR/openldap-install/lib/liblber.a"
CURL_LIB="$CURL_INSTALL_DIR/lib/libcurl.a"

# Check for OpenSSL
OPENSSL_LIBS=""
if [ -f "$BUILD_DIR/openssl-install/lib/libssl.a" ]; then
    OPENSSL_LIBS="$BUILD_DIR/openssl-install/lib/libssl.a $BUILD_DIR/openssl-install/lib/libcrypto.a"
fi

# Check for brotli
BROTLI_LIBS=""
if pkg-config --exists libbrotlidec 2>/dev/null; then
    BROTLI_LIBS="$(pkg-config --libs libbrotlidec libbrotlienc libbrotlicommon)"
elif [ -f "/usr/lib/x86_64-linux-gnu/libbrotlidec.a" ]; then
    BROTLI_LIBS="-lbrotlidec -lbrotlienc -lbrotlicommon"
fi

# Link the fuzzer
echo "Linking curl CLI fuzzer..."
set -x

$CC $OPT_FLAGS $CFLAGS -fsanitize=fuzzer \
    $OBJ_FILES \
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
    ls -lh "$BUILD_DIR/curl_fuzzer_cli"
    exit 0
else
    echo "Error: Failed to build curl_fuzzer_cli"
    exit 1
fi
