# pqtpm — bounded bridge to a TPM 2.0 v1.85 emulator for ML-DSA identity keys

`pqtpm` is a small C command-line tool that drives an ML-DSA key inside a TPM 2.0 v1.85
emulator through the wolfTPM client library: `create` (TPM2_CreatePrimary under the owner
hierarchy with `fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|noDA|sign`, then
TPM2_EvictControl to a persistent handle), `pub` (TPM2_ReadPublic), `sign`
(TPM2_SignSequenceStart with a FIPS 204 context string, TPM2_SignSequenceComplete),
`verify` (in-emulator VerifySequence; diagnostic only) and `evict`. Each run prints one
JSON object including the TPM command codes, response codes and per-command times it
observed. There is no software signing fallback in this program. The private key never
leaves the emulator; the only secret handled is the key's authValue (read from a file,
never printed).

The Go code (`internal/pqdev`) executes this tool as a subprocess and sees only public
keys, handles and signatures. The requester never uses it: it verifies with CIRCL.

## Emulator and build (task-local, no system packages replaced)
* Emulator: wolfTPM firmware TPM (`fwtpm_server`, socket transport, TPM 2.0 v1.85 ML-DSA
  via `WOLFTPM_V185`), upstream `wolfSSL/wolfTPM` commit `1362e1e53ad3282973eefd6234be34fb774d06d3`
  (2026-11-07), built with CMake: `WOLFTPM_FWTPM=yes WOLFTPM_INTERFACE=SWTPM WOLFTPM_V185=yes`.
* Crypto: wolfSSL commit `0ac786e0405978697f2ebfb079a47b27bca7fce9` (2026-11-06), CMake
  options `WOLFSSL_MLDSA WOLFSSL_MLKEM WOLFSSL_KEYGEN WOLFSSL_TPM WOLFSSL_PKCALLBACKS`,
  `-DWC_RSA_NO_PADDING`, static library.
* Not used: Stefan Berger's swtpm/libtpms (no ML-DSA in libtpms master `165c303c`, no
  v0.11 release at the time); the classical identity component keeps using swtpm 0.10.2.

```sh
# from the repository root; produces .toolchain/wolfssl, .toolchain/wolftpm/{bin,lib}
scripts/build_pq_toolchain.sh
make -C tools/pqtpm              # links libwolftpm.a + libwolfssl.a
tools/pqtpm/pqtpm --port 2321 pub --handle 0x81010001
```

Environment overrides read by the Go code: `A2AID_FWTPM` (path of `fwtpm_server`),
`A2AID_PQTPM` (path of `pqtpm`). The wolfTPM client reads `TPM2_SWTPM_HOST` /
`TPM2_SWTPM_PORT`; `pqtpm --host/--port` sets them per invocation.

## Licence
wolfTPM and wolfSSL are GPLv3 (with commercial alternatives from wolfSSL Inc.). This tool
links them and is therefore licensed under GPLv3 (`LICENSE` in this directory). The rest
of the repository is Apache-2.0 and only executes `pqtpm` as a separate process.

## What this is and is not
Emulated device-resident PQ signing: measured API/protocol viability under an assumed
host/state protection boundary. The emulator's NV file is an ordinary file; copying it is
a separate, measured capability (control X2). It is not a physical device, not hardware
extraction resistance, and not FIPS validation.
