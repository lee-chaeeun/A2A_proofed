package verifier

import "crypto/sha256"

func x509Sha256(b []byte) [32]byte { return sha256.Sum256(b) }
