# proof-cache

Optional cache of generated proofs, used when a matrix is re-run with unchanged inputs:

    v2/<guest image id of the local zkprove build>/<sha256 of the proof inputs>.json

The worker resolves the image id from `zkprove --image-id` before any lookup and serves a cached entry only if it carries that id, a receipt matching its recorded hash and a journal for the requested challenge. If the build identity cannot be resolved, proving with a cache configured fails closed. Cache entries are generated locally and not published.
