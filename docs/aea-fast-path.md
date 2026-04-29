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

[`tests/aea/`](../tests/aea) downloads a real iOS 18 OTA kernelcache. Defaults to `iPhone17,1` / build `22A3351`; pass `osStr build model board` as positional args to override.

```sh
make TARGET=macos DEBUG=1
./output/macos/tests/aea
```
