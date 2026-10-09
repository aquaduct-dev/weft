<!-- docdaemon ts:2026-10-09T01:48:03Z hash:a4567fddff803604 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory defines the Bazel build rules for packaging and publishing multi-architecture container images for the Weft application.

## Overview
The `container` directory orchestrates the creation of OCI-compliant container images using Bazel. It ensures that consumers can pull the correct binary variant based on their host architecture by combining AMD64 and ARM64 builds into a single manifest list. The setup automates the publication of these images to the GitHub Container Registry with the `latest` tag, eliminating manual intervention for platform-specific deployments.

## Deep Dive
### Image Construction
The build process begins by archiving compiled binaries into tarballs using `pkg_tar`. Two distinct targets are defined: one for AMD64 and another for ARM64 (v8). Each target utilizes an Alpine Linux base image, sets the entrypoint to `/usr/bin/weft`, and includes the specific binary tarball for that architecture. This separation ensures that each image layer contains only the necessary artifacts for its respective platform.

### Multi-Architecture Indexing
Individual architecture-specific images are combined into a single manifest list using the `oci_image_index` rule. This index allows Docker clients to automatically select the appropriate image variant based on the host's CPU architecture. By providing a unified image reference, the system abstracts away the complexity of managing separate image tags for different platforms.

### Publishing
The final step involves pushing the multi-architecture index to the GitHub Container Registry (`ghcr.io/aquaduct-dev/weft`). The `oci_push` rule is configured to publish this index with the `latest` tag. This configuration ensures that the most recent build is always available under a consistent name, simplifying deployment pipelines and reducing the risk of pulling outdated or incorrect variants.

## Key Interfaces
- `weft_amd64`: OCI image target for AMD64 architecture
- `weft_arm64`: OCI image target for ARM64 (v8) architecture
- `weft_multiarch`: Manifest list combining all supported architectures
- `weft_push`: Rule for publishing the multi-arch index to GHCR

## Dependencies
- Bazel Buildifier
- Bazel Container Rules (rules_oci)
- Alpine Linux Base Images
- GitHub Container Registry Credentials

## Subcomponents
- BUILD.bazel