# TEESecureDeletion

CoreLib plugin reproducing the cryptographic deletion-and-verification chain
of the TEE-based cloud secure-deletion patent. A user key share and a TEE key
share jointly derive a deterministic overwrite stream; the plugin directly
constructs and verifies the patent's SM9 pairing equation using CoreLib
primitives.

The key transform is a software model: real enclave key sealing, remote
attestation and hardware isolation require a deployment-specific TEE service.

## Build and test

```sh
git submodule update --init --recursive
cmake -S . -B build-release -DCAM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure
```

Only `3rdparty/CoreLib` is required. The hot-load algorithm type is
`TEESecureDeletion`.
