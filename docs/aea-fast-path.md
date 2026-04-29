# AEA OTA fast path

iOS 18+ kernelcaches ship inside encrypted [AEA](https://developer.apple.com/documentation/applearchive) OTA assets, often exceeding 7 GiB. The fast path extracts only the kernelcache chunk over HTTP Range without persisting the full asset. A typical run transfers ~24 MiB in ~12 requests to materialize the ~62 MiB kernelcache.

## Architecture

All code lives under [`src/aea/`](../src/aea); the entry point is `aea_fast_extract_kernelcache` in [`include/aea_fast.h`](../include/aea_fast.h). `grab_kernelcache_*` dispatches AEA links to it automatically; non-AEA assets continue to use `libpartial`.

| Module | Responsibility |
| --- | --- |
| `aea_crypto.m` | HKDF-SHA256, AES-256 CTR, and the AEA HMAC variant `HMAC(key, salt \|\| data \|\| u64_le(salt_len))` via `CommonCrypto`. |
| `aea_range.m` | `AEAFRangeOpener` — `NSURLSession`-backed Range fetcher with retry and byte/request counters. |
| `aea_index.m` | `AEAFClusterIndex` — parses the AEA prefix, walks cluster headers on demand, and decrypts arbitrary plaintext slices a segment band at a time. |
| `aea_yop.m` | YAA frame decoder + `YOP_MANIFEST` parser to find chunk plaintext offsets. |
| `aea_im4p.m` | IM4P ASN.1 walker and `Compression`-framework segment decompression (LZFSE / LZBITMAP / LZ4 / LZMA / zlib). |
| `aea_fast.m` | Top-level orchestration: prefix → manifest → outer YAA → rolling-window inner-YAA scan → kernelcache slice fetch → IM4P → LZFSE → write. |

AppleDB integration surfaces the per-link AEA `decryptionKey` (base64 AES-256 AMK) via the library-private [`src/appledb_internal.h`](../src/appledb_internal.h); the public `appledb.h` ABI is unchanged.

## Testing

[`tests/aea/`](../tests/aea) contains three harnesses that hit real Apple CDN Full OTAs:

- `one.m` — single-build smoke test. `./aea_one <build> <url> <key>`.
- `test_18x.m` — 9-build iOS 18.x matrix (18.0 → 18.7).
- `test_26x.m` — 20-build iOS 26.x matrix (26.0 → 26.4.2, two devices each).

```sh
make TARGET=macos
./output/macos/tests/aea_18x   # iOS 18.x
./output/macos/tests/aea_26x   # iOS 26.x
```

## Measured cost

Numbers below are from the full matrices, request counts include the AEA prefix prepare, BuildManifest discovery, in-chunk linear scan, and the final kernelcache fetch.

### iOS 18.x — `iPhone14,7` & `iPhone17,1`, 9 builds

| Build | Model | KC chunk | Requests | Bytes (MiB) |
| --- | --- | --- | --- | --- |
| 22A3351 | iPhone17,1 | 4 | 29 | 54.7 |
| 22B82  | iPhone14,7 | 2 | 20 | 43.3 |
| 22C150 | iPhone14,7 | 2 | 20 | 41.3 |
| 22D82  | iPhone14,7 | 2 | 20 | 41.3 |
| 22E252 | iPhone14,7 | 2 | 20 | 42.4 |
| 22F76  | iPhone14,7 | 2 | 20 | 42.3 |
| 22G100 | iPhone14,7 | 2 | 20 | 42.3 |
| 22H124 | iPhone14,7 | 2 | 20 | 42.3 |
| 22H352 | iPhone14,7 | 2 | 20 | 42.3 |

In iOS 18 OTAs `BuildManifest.plist` lives in chunk 1 within the first ~3 frames; the kernelcache itself is in chunk 2 (A15) or chunk 4 (A18 Pro).

### iOS 26.x — 10 versions × 2 devices, 20 builds

| Version | Build | iPhone14,7 reqs / MiB | iPhone17,1 reqs / MiB |
| --- | --- | --- | --- |
| 26.0   | 23A341  | 20 / ~45 | 31 / ~57 |
| 26.0.1 | 23A355  | 20 / ~45 | 31 / ~57 |
| 26.1   | 23B85   | 20 / ~45 | 31 / ~57 |
| 26.2   | 23C55   | 20 / ~45 | 31 / ~57 |
| 26.2.1 | 23C71   | 20 / ~45 | 31 / ~57 |
| 26.3   | 23D127  | 20 / ~45 | 31 / ~57 |
| 26.3.1 | 23D8133 | 20 / ~45 | 31 / ~57 |
| 26.4   | 23E246  | 20 / ~45 | 31 / ~57 |
| 26.4.1 | 23E254  | 20 / ~45 | 31 / ~57 |
| 26.4.2 | 23E261  | 20 / ~45 | 31 / ~57 |

In iOS 26 OTAs the cluster layout shifted: `BuildManifest.plist` moved into chunk 2, and the A18 Pro (`iPhone17,1`) kernelcache is in chunk 4 — discovery now visits up to four chunks rather than two.

### Summary vs. naive download

A full OTA for these devices is 6.9 – 7.7 GiB. The fast path transfers ~0.6% of that on A15 builds and ~0.8% on A18 Pro builds.

| Class | Bytes saved | Requests |
| --- | --- | --- |
| iOS 18 (A15 / A18 Pro) | ~99.4% / ~99.3% | 20 / 29 |
| iOS 26 (A15 / A18 Pro) | ~99.4% / ~99.2% | 20 / 31 |

## Tuning notes

- **2 MiB rolling window** (`WINDOW_CHUNK_SIZE`). 1 MiB issues redundant fetches when adjacent header probes straddle a window boundary; 4 MiB and beyond pull excess body bytes that `yaaSkip` would otherwise discard. 2 MiB landed lowest on both metrics in the matrices above.
- **Linear walk beats stride-jump**. An earlier prototype attempted 8 MiB jump search with strong-magic probes, but ~256 KiB+ frame bodies are common inside Apple OTAs, so probes routinely landed in body data and triggered probe-miss fallbacks. The savings from skipping never paid for the wasted probe windows. Body skips inside a linear walk are free (cursor advance, no I/O).
- **BuildManifest is fatal if missing**. Phase A scans up to `PHASE_A_MAX_CHUNKS = 4` chunks (covers iOS 18 chunk 1 and iOS 26 chunk 2 with margin). On miss the call fails fast — speculative substring scanning over later chunks just amplifies request counts.
- **Per-segment LRU cache** (`AEAF_SEG_CACHE_MAX = 8`). The rolling window can re-enter a recently-decrypted AES-CTR segment when a frame straddles a 1 MiB segment boundary; caching the last 8 plaintext segments removes ~5 redundant decrypts per build.
