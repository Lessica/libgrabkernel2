# libgrabkernel2

This is a simple library to download the kernelcache for the host iOS/macOS device. It is similar to the original [libgrabkernel](https://github.com/tihmstar/libgrabkernel) by tihmstar, but it uses the AppleDB API to find the kernelcache URL, which lets it work for beta versions of iOS/macOS as well.

libgrabkernel2 also contains a compatibility shim for the original libgrabkernel's `grabkernel()` function. This means that you can swap a libgrabkernel dylib for a libgrabkernel2 one in a pre-compiled project without issues.

## Building

Run `make` in the root directory.

- Add `TARGET=macos` for macOS (the default is iOS)
- Add `DEBUG=1` for a debug build.

The build products and headers will be in the `output` directory.

Huge credit to [dhinakg](https://github.com/dhinakg) for reimplementing the API parsing in Objective-C (as it was originally in Swift).

## AEA OTA fast path

iOS 18+ kernelcaches ship inside encrypted [AEA](https://developer.apple.com/documentation/applearchive) OTA assets that can exceed 7 GiB. This fork adds a streaming HTTP-Range path so `grab_kernelcache_*` can extract only the kernelcache chunk without downloading the full asset. The public ABI is unchanged, including the original `grabkernel.h` entry points.

### At a glance

Tested on real Apple CDN Full OTAs across 29 build/device combinations (iOS 18.0 - 26.4.2). Comparison vs. naive full download:

| Metric | Full asset download | Fast path |
| --- | --- | --- |
| Bytes transferred (typical) | 7.0 - 7.7 GiB | ~42 - 60 MiB |
| HTTP requests | 1 | ~20 - 31 |
| Time-to-kernelcache | minutes | seconds |
| Disk usage | full OTA buffered | none (streamed) |

Pass rate: **9/9 iOS 18.x** + **20/20 iOS 26.x** = **29/29** at the time of writing.

The default macOS test build also includes `aea_appledb_dynamic`, which verifies that the public `grabkernel.h` API can resolve an AppleDB AEA OTA URL plus decryption key and dispatch into the fast path.

See [docs/aea-fast-path.md](docs/aea-fast-path.md) for the design, per-build measurements, AppleArchive framework comparison, and test commands.
