<!-- docdaemon ts:2026-10-09T01:40:05Z hash:7293ef3c36aecf60 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for packaging and publishing multi-architecture container images for the Weft application.

It orchestrates the creation of OCI-compliant images by first archiving the compiled binaries into tarballs via `pkg_tar`. Two distinct architectures are supported: AMD64 and ARM64 (v8). Each architecture has a corresponding `oci_image` target that uses an Alpine Linux base image, sets the entrypoint to `/usr/bin/weft`, and includes the specific binary tarball.

These individual images are combined into a single manifest list using `oci_image_index`, enabling support for multiple platforms within one image reference. Finally, the `oci_push` rule is configured to publish this multi-arch index to the GitHub Container Registry (`ghcr.io/aquaduct-dev/weft`) with the `latest` tag. This setup ensures that consumers can pull the correct binary variant based on their host architecture without manual intervention.