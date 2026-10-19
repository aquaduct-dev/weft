<!-- docdaemon ts:2026-10-19T23:26:05Z hash:6f88e166c1b6c264 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains offline integration tests that validate the structure and contents of OCI image layouts built by Bazel.

The test suite verifies `weft` images for `amd64` and `arm64` platforms, as well as a multi-arch index, without requiring a registry or Docker daemon. It reads the OCI layout directories specified via flags (`-amd64_layout`, `-arm64_layout`, `-index_layout`) and resolves paths relative to the Bazel runfiles tree if necessary.

Key components include:
*   **`checkManifest`**: Validates a single platform's manifest against expected OS, architecture, variant, and entrypoint. It ensures the entrypoint binary exists in the layer tars, is executable, and is a valid 64-bit ELF binary for the target machine.
*   **`openLayer`**: Reads layer blobs from the layout, transparently handling gzip-compressed tar archives.
*   **`findFile`**: Scans all layers in order to locate specific files (like the entrypoint), with later layers overriding earlier ones.
*   **`TestImageIndex`**: Verifies the multi-arch index lists exactly the expected platforms (`linux/amd64` and `linux/arm64/v8`) and delegates validation of each sub-manifest to `checkManifest`.

These checks ensure that the images published by `//container:weft_image_push` are correct before they are pushed to a registry.