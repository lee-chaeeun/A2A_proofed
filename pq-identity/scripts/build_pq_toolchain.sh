#!/usr/bin/env bash
# Task-local build of wolfSSL (ML-DSA/ML-KEM) and the wolfTPM firmware TPM + client library
# with CMake/Ninja, into .toolchain/. No system library is replaced. Pinned commits below.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD; TC=$ROOT/.toolchain; SRC=${PQ_SRC_DIR:-$TC/src}
WOLFSSL_COMMIT=0ac786e0405978697f2ebfb079a47b27bca7fce9
WOLFTPM_COMMIT=1362e1e53ad3282973eefd6234be34fb774d06d3
mkdir -p "$SRC" "$TC/wolftpm/include" "$TC/wolftpm/bin"
if [ ! -d "$SRC/wolfssl" ]; then git clone -q https://github.com/wolfSSL/wolfssl "$SRC/wolfssl"; fi
(cd "$SRC/wolfssl" && git fetch -q --depth 1 origin "$WOLFSSL_COMMIT" 2>/dev/null || true; git checkout -q "$WOLFSSL_COMMIT")
cmake -S "$SRC/wolfssl" -B "$SRC/wolfssl/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$TC/wolfssl" \
  -DWOLFSSL_MLDSA=yes -DWOLFSSL_MLKEM=yes -DWOLFSSL_KEYGEN=yes -DWOLFSSL_TPM=yes -DWOLFSSL_PKCALLBACKS=yes \
  -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=yes -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="-DWC_RSA_NO_PADDING" >/dev/null
ninja -C "$SRC/wolfssl/build" >/dev/null && ninja -C "$SRC/wolfssl/build" install >/dev/null
if [ ! -d "$SRC/wolfTPM" ]; then git clone -q https://github.com/wolfSSL/wolfTPM "$SRC/wolfTPM"; fi
(cd "$SRC/wolfTPM" && git fetch -q --depth 1 origin "$WOLFTPM_COMMIT" 2>/dev/null || true; git checkout -q "$WOLFTPM_COMMIT")
cmake -S "$SRC/wolfTPM" -B "$SRC/wolfTPM/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$TC/wolfssl" \
  -DWOLFTPM_FWTPM=yes -DWOLFTPM_INTERFACE=SWTPM -DWOLFTPM_V185=yes -DBUILD_SHARED_LIBS=OFF -DWOLFTPM_EXAMPLES=yes \
  -DCMAKE_EXE_LINKER_FLAGS="" -DCMAKE_C_STANDARD_LIBRARIES="-lm" >/dev/null
ninja -C "$SRC/wolfTPM/build" fwtpm_server mldsa_sign caps >/dev/null
cp "$SRC/wolfTPM/build/bin/fwtpm_server" "$SRC/wolfTPM/build/bin/mldsa_sign" "$SRC/wolfTPM/build/bin/caps" "$TC/wolftpm/bin/"
cp "$SRC/wolfTPM/build/libwolftpm.a" "$TC/wolftpm/"
rm -rf "$TC/wolftpm/include/wolftpm"; cp -r "$SRC/wolfTPM/wolftpm" "$TC/wolftpm/include/"
# CMake writes the generated options.h either into the build tree or into the source
# tree (this wolfTPM commit uses the source tree); take whichever exists.
OPT=""; for f in "$SRC/wolfTPM/build/wolftpm/options.h" "$SRC/wolfTPM/wolftpm/options.h"; do [ -f "$f" ] && OPT=$f && break; done
[ -n "$OPT" ] || { echo "wolfTPM options.h not found after the CMake build" >&2; exit 1; }
cp "$OPT" "$TC/wolftpm/include/wolftpm/options.h"; cp "$SRC/wolfTPM/hal/tpm_io.h" "$TC/wolftpm/include/"
make -s -C tools/pqtpm
echo "built: $TC/wolftpm/bin/fwtpm_server, tools/pqtpm/pqtpm"
