# proof-cache

Layout since the 2026-11-08 correction (`internal/zk/bridge.go`, `CacheVersion = "v2"`):

    v2/<guest image id embedded in the local zkprove build>/<sha256 of the proof inputs JSON>.json

The worker resolves the image id from `zkprove --image-id` BEFORE any lookup and
serves a cached entry only if it carries that id, a receipt matching its recorded
hash and a journal for the requested challenge. If the build identity cannot be
resolved, proving with a cache configured fails closed.

The 20 flat `<hash>.json` files directly in this directory are the pre-correction v1
layout: keyed by an EMPTY image prefix plus the inputs (the worker never set the
image field). They are retained unchanged as evidence of the earlier runs and are
never read by the current code.
