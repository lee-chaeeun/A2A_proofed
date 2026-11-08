# Emulator check: native ML-DSA in the wolfTPM firmware TPM

wolfTPM (TPM 2.0 v1.85, socket transport) and wolfSSL were built from pinned upstream versions (`upstream-commits.txt`, `*-cmake-options.txt`, `binary-sha256.txt`). The swtpm/libtpms emulator had no ML-DSA support at the time.

| File | Observation |
|---|---|
| `create.json` | CreatePrimary and EvictControl succeed; ML-DSA-65 key restricted to signing and fixed to this TPM (attributes 0x00040472); 1952-byte public key and object name |
| `sign.json` | SignSequenceStart/Complete produce a 3309-byte signature with the FIPS 204 context string |
| `sign-wrong-auth.json` | A wrong authorization value is refused and no signature is produced |
| `verify-tampered-message.json` | An altered message fails verification inside the emulator |
| `pub-after-restart.json`, `sign-after-restart.json` | The persistent key, public key and name survive an emulator restart |
| `circl-cross-verification.txt` | CIRCL verifies the emulator's signature; a wrong context or message is rejected |
| `circl-mldsa65-acvp-test.log` | CIRCL's NIST test vectors |
| `caps-example-output.txt`, `mldsa_sign-example-output.txt`, `fwtpm-server-first-start.log` | Upstream example programs and emulator start-up |

No private key, seed or authorization value is recorded; the private key exists only in the emulator's state file.
