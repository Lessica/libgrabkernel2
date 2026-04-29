# AEA OTA fast path

iOS 18+ kernelcaches ship inside encrypted [AEA](https://developer.apple.com/documentation/applearchive) OTA assets, often exceeding 7 GiB. The fast path extracts the target kernelcache through HTTP Range reads, without buffering the full OTA on disk.

Across the current test matrix, extraction typically transfers ~42-60 MiB in ~20-31 HTTP requests. That is about 0.6%-0.8% of the full OTA size.

## Production path

All production code lives under [`src/aea/`](../src/aea). The entry point is `aea_fast_extract_kernelcache` in [`include/aea_fast.h`](../include/aea_fast.h). Public `grab_kernelcache_*` / `grabkernel.h` callers do not need to opt in: AppleDB marks OTA links with `isAEA`, provides the per-asset `decryptionKey`, and the existing grab flow dispatches AEA links to the fast path automatically.

Non-AEA assets continue to use the existing `libpartial` path.

| Module | Responsibility |
| --- | --- |
| `aea_crypto.m` | HKDF-SHA256, AES-256 CTR, and the AEA HMAC variant `HMAC(key, salt || data || u64_le(salt_len))`. |
| `aea_range.m` | `AEAFRangeOpener`: `NSURLSession` Range fetcher with retry plus byte/request counters. |
| `aea_index.m` | `AEAFClusterIndex`: parses the AEA prefix, walks cluster headers on demand, and decrypts plaintext slices by segment. |
| `aea_yop.m` | YAA frame decoder and `YOP_MANIFEST` parser used to locate chunk plaintext offsets. |
| `aea_im4p.m` | IM4P ASN.1 walker and `Compression` framework segment decompressor. |
| `aea_fast.m` | Prefix -> manifest -> outer YAA -> rolling-window inner YAA scan -> kernelcache slice fetch -> IM4P -> decompress -> write. |

AppleDB integration keeps the public `appledb.h` ABI unchanged. The AEA key is carried through the library-private [`src/appledb_internal.h`](../src/appledb_internal.h) API.

## Tests and probes

[`tests/aea/`](../tests/aea) contains harnesses that hit real Apple CDN Full OTAs. The long matrix tests are intentionally not part of the default `make test` path because they are network-heavy.

| Harness | Purpose | Default build target |
| --- | --- | --- |
| `appledb_dynamic.m` | Public `grabkernel.h` integration test. Dynamically asks AppleDB for an AEA-only case (`iOS 22A3351` / `iPhone17,1`) and verifies URL/key resolution plus fast-path dispatch. | Yes: `output/macos/tests/aea_appledb_dynamic` |
| `one.m` | Single-build smoke test with explicit build, URL, and key. | No |
| `test_18x.m` | 9-build iOS 18.x matrix. | No |
| `test_26x.m` | 20-build iOS 26.x matrix. | No |
| `applearchive_probe.m` | AppleArchive framework comparison probe over the same remote HTTP Range source. | No |

Default public API check:

```sh
make TARGET=macos
./output/macos/tests/aea_appledb_dynamic
```

The default arguments are:

```text
iOS 22A3351 iPhone17,1 InvalidBoardConfig
```

The invalid boardconfig is intentional. It proves the public API did not fall back to the IPSW/ZIP path, because only the AEA OTA path can satisfy that test case.

The latest dynamic AppleDB run resolved a `.aea` Full OTA with a key, dispatched to the fast path, and extracted the kernelcache with 29 HTTP requests / 54.69 MiB transferred.

## Matrix results

The matrix numbers include AEA prefix preparation, `BuildManifest.plist` discovery, in-chunk YAA scanning, and final kernelcache fetch.

### iOS 18.x

9 builds across `iPhone14,7` and `iPhone17,1`.

| Build | Model | KC chunk | Requests | Bytes (MiB) |
| --- | --- | ---: | ---: | ---: |
| 22A3351 | iPhone17,1 | 4 | 29 | 54.7 |
| 22B82 | iPhone14,7 | 2 | 20 | 43.3 |
| 22C150 | iPhone14,7 | 2 | 20 | 41.3 |
| 22D82 | iPhone14,7 | 2 | 20 | 41.3 |
| 22E252 | iPhone14,7 | 2 | 20 | 42.4 |
| 22F76 | iPhone14,7 | 2 | 20 | 42.3 |
| 22G100 | iPhone14,7 | 2 | 20 | 42.3 |
| 22H124 | iPhone14,7 | 2 | 20 | 42.3 |
| 22H352 | iPhone14,7 | 2 | 20 | 42.3 |

In these OTAs, `BuildManifest.plist` lives in chunk 1 near the beginning of the archive. The kernelcache is in chunk 2 for the tested A15 device and chunk 4 for the tested A18 Pro device.

### iOS 26.x

10 versions x 2 devices = 20 builds.

| Version | Build | iPhone14,7 reqs / MiB | iPhone17,1 reqs / MiB |
| --- | --- | ---: | ---: |
| 26.0 | 23A341 | 20 / ~45 | 31 / ~57 |
| 26.0.1 | 23A355 | 20 / ~45 | 31 / ~57 |
| 26.1 | 23B85 | 20 / ~45 | 31 / ~57 |
| 26.2 | 23C55 | 20 / ~45 | 31 / ~57 |
| 26.2.1 | 23C71 | 20 / ~45 | 31 / ~57 |
| 26.3 | 23D127 | 20 / ~45 | 31 / ~57 |
| 26.3.1 | 23D8133 | 20 / ~45 | 31 / ~57 |
| 26.4 | 23E246 | 20 / ~45 | 31 / ~57 |
| 26.4.1 | 23E254 | 20 / ~45 | 31 / ~57 |
| 26.4.2 | 23E261 | 20 / ~45 | 31 / ~57 |

In these OTAs, `BuildManifest.plist` moved to chunk 2. The A18 Pro kernelcache remains in chunk 4, so discovery visits more chunks than the iOS 18 A15 cases.

### Full download comparison

The tested Full OTAs are roughly 6.9-7.7 GiB.

| Class | Bytes saved | Requests |
| --- | ---: | ---: |
| iOS 18 A15 / A18 Pro | ~99.4% / ~99.3% | 20 / 29 |
| iOS 26 A15 / A18 Pro | ~99.4% / ~99.2% | 20 / 31 |

## AppleArchive framework probe

`applearchive_probe.m` exists to answer one question: can Apple's public AppleArchive framework improve the remote fast path?

It wraps the remote `.aea` object in an HTTP Range-backed `AACustomByteStream`, opens it through `AEADecryptionRandomAccessInputStreamOpen`, and then uses `AADecodeArchiveInputStreamOpen` inside YOP chunks to read:

- `AssetData/boot/BuildManifest.plist`
- `AssetData/boot/kernelcache.release.*`

Manual build:

```sh
clang -Wall -Werror -Wno-unused-command-line-argument \
  -I. -Iinclude -I_external/include -fPIC -fobjc-arc -O0 -g \
  -arch arm64 -mmacosx-version-min=11.0 \
  -framework Foundation -framework Security -lz -lcompression -lAppleArchive \
  -o output/macos/tests/aea_applearchive_probe \
  tests/aea/applearchive_probe.m src/aea/aea_yop.m src/aea/aea_crypto.m src/aea/aea_im4p.m
```

Representative result on `22B82` / `iPhone14,7`:

| Path | Requests | Bytes (MiB) | Wall time |
| --- | ---: | ---: | ---: |
| Current fast path | 20 | 43.31 | baseline matrix |
| AppleArchive probe | 292 | 235.29 | 103.25 s |

AppleArchive located the same objects:

| Object | Chunk | Headers read | Size |
| --- | ---: | ---: | ---: |
| `AssetData/boot/BuildManifest.plist` | 1 | 2 | 179,652 B |
| `AssetData/boot/kernelcache.release.iphone14b` | 2 | 90 | 17,989,876 B |

The framework is functionally compatible, but it does not expose the operation the fast path needs most: parse a YAA header, advance the logical cursor over a large body, and avoid fetching that body. In practice:

- Opening the random-access AEA stream and reaching the top YOP manifest touched 51 HTTP ranges / 23.06 MiB before any chunk-level search.
- The official archive decoder advances through chunk entries by consuming entry data, so it cannot precisely jump to the kernelcache before streaming through substantial preceding data.

Conclusion: AppleArchive is useful as a compatibility probe and reference implementation, but it is not currently a performance win for remote targeted kernelcache extraction.

## Tuning notes

- **2 MiB rolling window** (`WINDOW_CHUNK_SIZE`): 1 MiB creates redundant fetches near window boundaries; 4 MiB and larger windows pull body bytes that the YAA scanner can otherwise skip. 2 MiB was the best measured tradeoff.
- **Linear walk beats stride-jump**: Earlier 8 MiB jump probes often landed inside large frame bodies and triggered miss fallbacks. A linear header walk is cheaper because body skips are logical cursor moves, not HTTP reads.
- **BuildManifest miss is fatal**: Phase A scans up to `PHASE_A_MAX_CHUNKS = 4`, which covers the observed iOS 18 and iOS 26 layouts. On miss, the extractor fails fast instead of speculative substring scanning later chunks.
- **Per-segment LRU cache** (`AEAF_SEG_CACHE_MAX = 8`): Rolling windows can re-enter recently decrypted AES-CTR segments around 1 MiB segment boundaries. Caching the last 8 plaintext segments avoids redundant decryptions.
