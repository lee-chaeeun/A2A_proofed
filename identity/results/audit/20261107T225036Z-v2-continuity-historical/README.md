# Historical P0-B reproduction on the archived v2 source (20261107T225036Z)

Question: before the v3 fix, did the requester write the job to a replacement
connection after a valid proof? No retained pre-fix execution existed, so a minimal
close-then-swap test (zz_historical_continuity_test.go.txt, stored with a .txt suffix so `go test ./...` does not compile it; sha256 in inputs-sha256.txt)
was added to an ISOLATED extraction of the archived v2 source
(source-v2.tar.gz, sha256 in inputs-sha256.txt). The archive and the production tree
were not modified. extracted-tree-sha256.txt lists the extracted files;
archive-vs-extracted.diff compares them with the archive's own hash list.

Attacker capabilities: B holds A's TLS certificate and private key and is placed at
A's name after the proof; B has NO proof key and NO signer access (it answered 0
challenges). Policy: S-env+cb (v2 BoundNonce derivation, honest A signs with its
enrolled isolated key).

Outcome (go-test-output.txt): the v2 requester accepted A's proof, then delivered
the job to B over a NEW connection; B acknowledged as dep-B; A received nothing.
This is the pre-fix continuity weakness, reproduced on the archived code with the
principal threat-model capabilities. The current code refuses this before any byte
is written (internal/verifier/continuity_final_test.go, case 2).
