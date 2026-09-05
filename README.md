# TEESecureDeletion

CoreLib plugin reproducing the cryptographic core of the TEE-based cloud
secure-deletion patent. A user key share and a TEE key share jointly derive a
deterministic overwrite stream, then CoreLib's SM9 aggregate PDP verifies the
post-deletion data.

The key transform is a software model: real enclave key sealing, remote
attestation and hardware isolation require a deployment-specific TEE service.

## Build and test

```sh
cmake -S . -B build-release -DCAM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure
```

The hot-load algorithm type is `TEESecureDeletion`.
