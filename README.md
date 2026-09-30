# TEESecureDeletion

CoreLib plugin reproducing the cryptographic deletion-and-verification chain
of the TEE-based cloud secure-deletion patent. A user key share and a TEE key
share jointly derive a deterministic overwrite stream; the plugin directly
constructs and verifies the patent's SM9 pairing equation using CoreLib
primitives.

The key transform is a software model: real enclave key sealing, remote
attestation and hardware isolation require a deployment-specific TEE service.

## CoreLib lifecycle

No Bench- or CoreLib-specific interface is required for a deletion audit.  A
caller uses the normal lifecycle `TagGen -> Maintenance(Update) -> Challenge
-> Proof -> Verify` in one `AuditEngine` process.  The Update request carries
the deletion intent explicitly:

```json
{
  "fileId": "object-001",
  "opType": 0,
  "deletionMode": true,
  "targetBlockIndices": [3, 7, 11],
  "seed": "deletion-round-001"
}
```

`opType: 0` is CoreLib's `MaintenanceOpType::Update`.  Explicit `Delete`
requests remain supported.  A normal Update without `deletionMode: true` is
rejected, preventing ordinary dynamic-data updates from being treated as a
secure deletion operation.  The same `AuditEngine` and plugin instance must
remain alive through proof verification because this software TEE model keeps
the deletion state in process memory.

## Build and test

```sh
git submodule update --init --recursive
cmake -S . -B build-release -DCAM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure
```

Only `3rdparty/CoreLib` is required. The hot-load algorithm type is
`TEESecureDeletion`.
