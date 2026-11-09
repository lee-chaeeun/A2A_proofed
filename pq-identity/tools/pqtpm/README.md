# pqtpm: bridge to the firmware TPM emulator

A small C program that manages an ML-DSA key inside the wolfTPM firmware TPM (TPM 2.0 v1.85) through the wolfTPM client library:

| Command | TPM operations |
|---|---|
| `create` | CreatePrimary under the owner hierarchy with an ML-DSA-65 key restricted to signing and fixed to this TPM, then EvictControl to a persistent handle |
| `pub` | ReadPublic |
| `sign` | SignSequenceStart with the FIPS 204 context string, SignSequenceComplete |
| `verify` | Verification inside the emulator (diagnostic only; the requester verifies with CIRCL) |
| `evict` | Remove the persistent key |

Each call prints one JSON object with the TPM command codes, response codes and timings it observed. There is no software signing fallback. The private key never leaves the emulator; the only secret the program reads is the key's authorization value, from a file, and it is never printed. `internal/pqdev` runs the program as a subprocess and sees only public keys, handles and signatures.

## Build

```sh
scripts/build_pq_toolchain.sh   # from pq-identity/: pinned wolfSSL and wolfTPM, then this program
make -C tools/pqtpm             # rebuild only this program
tools/pqtpm/pqtpm --port 2321 pub --handle 0x81010001
```

`A2AID_FWTPM` and `A2AID_PQTPM` override the paths of the emulator and of this program. The emulator is software: its state, including the key protecting its storage, is a host file.

## Licence

wolfTPM and wolfSSL are GPLv3; this program links them and is GPLv3 ([LICENSE](LICENSE)). The rest of the repository is Apache-2.0 and only runs this program as a separate process.
