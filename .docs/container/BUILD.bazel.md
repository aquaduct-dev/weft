<!-- docdaemon ts:2026-10-19T23:25:45Z hash:58977c05d7df5394 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file defines the Bazel build rules for constructing, indexing, and pushing multi-architecture OCI container images for the `weft` binary.

The build process creates separate `pkg_tar` targets for `amd64` and `arm64` architectures, packaging the compiled binaries into `/usr/bin`. These tars are combined with Alpine Linux base images via `oci_image` to produce platform-specific container images (`weft_image_amd64` and `weft_image_arm64_v8`). An `oci_image_index` aggregates these into a single multi-arch manifest named `weft_image`.

The `oci_push` rule publishes this index to `ghcr.io/aquaduct-dev/weft` with the `latest` tag.

A `go_test` target (`container_test`) performs offline validation of the built images. It verifies that the OCI layout configurations match expected OS/architecture pairs, confirms the entrypoint is set correctly, and ensures the entrypoint binary exists in the layers as a valid ELF executable for the target machine type. This test was introduced to catch configuration mismatches before pushing to a registry.