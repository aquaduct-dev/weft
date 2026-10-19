<!-- docdaemon ts:2026-10-09T01:48:03Z hash:a4567fddff803604 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory defines the Bazel build rules for packaging and publishing multi-architecture container images for the Weft application.

## Overview
The `container` directory orchestrates the creation of OCI-compliant container images using Bazel. It ensures that consumers can pull the correct binary variant based on their host architecture by combining AMD64 and ARM64 builds into a single manifest list. The setup automates the publication of these images to the GitHub Container Registry with the `latest` tag, eliminating manual intervention for platform-specific deployments.

## Deep Dive
### Image Construction
The build process begins by archiving compiled binaries into tarballs using `pkg_tar`. Two tarballs are built from the Go binaries defined in the root `BUILD.bazel`: `weft_tar` (from `//:weft`) and `weft_tar_arm64` (from `//:weft_arm64`). Each feeds an `oci_image` on an Alpine Linux base. The binary keeps its Bazel output name, so the AMD64 image's entrypoint is `/usr/bin/weft` and the ARM64 image's is `/usr/bin/weft_arm64`. This separation ensures that each image layer contains only the necessary artifacts for its respective platform.

### Multi-Architecture Indexing
Individual architecture-specific images are combined into a single manifest list using the `oci_image_index` rule. This index allows Docker clients to automatically select the appropriate image variant based on the host's CPU architecture. By providing a unified image reference, the system abstracts away the complexity of managing separate image tags for different platforms.

### Publishing
The final step involves pushing the multi-architecture index to the GitHub Container Registry (`ghcr.io/aquaduct-dev/weft`). The `oci_push` rule is configured to publish this index with the `latest` tag. This configuration ensures that the most recent build is always available under a consistent name, simplifying deployment pipelines and reducing the risk of pulling outdated or incorrect variants.

## Key Interfaces
- `weft_image`: Multi-arch `oci_image_index`; this is the published artifact consumers pull.
- `weft_image_push`: `oci_push` rule publishing `weft_image` to `ghcr.io/aquaduct-dev/weft:latest`.
- `weft_image_amd64`, `weft_image_arm64_v8`: Per-architecture `oci_image` build steps that feed the index.
- `weft_tar`, `weft_tar_arm64`: `pkg_tar` layers placing the binaries from `//:weft` and `//:weft_arm64` under `/usr/bin`.

## Dependencies
- Bazel Buildifier
- Bazel Container Rules (rules_oci)
- Alpine Linux Base Images
- GitHub Container Registry Credentials

## Subcomponents
- BUILD.bazel