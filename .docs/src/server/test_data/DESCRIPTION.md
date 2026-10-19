<!-- docdaemon ts:2026-10-09T01:41:28Z hash:1c156c75ba68a404 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This directory holds only a `BUILD.bazel` that exports labels for `cert.pem` and `key.pem`; neither file is checked in.

## Overview
`test_data` was meant to hold PEM-encoded TLS fixtures for server tests. At present it contains no fixtures: `cert.pem` and `key.pem` are declared in `exports_files` but do not exist in the repository, and no target or Go test references `//src/server/test_data`. Tests that need a certificate generate one at runtime with `crypto.GenerateCert` (RSA 2048) instead.

## Build Visibility
`BUILD.bazel` sets `default_visibility = ["//visibility:public"]` and calls `exports_files(["cert.pem", "key.pem"])`, which only makes those labels available for test targets to depend on. Because the files are missing, any target that did depend on them would fail to build.

## Key Interfaces
- None (file labels only)

## Dependencies
- Bazel build system

## Subcomponents
- BUILD.bazel
