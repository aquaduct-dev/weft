// image_test.go — verifies the weft OCI images that //container:weft_image_push
// publishes, offline, by reading the OCI image layouts Bazel builds (no
// registry or docker daemon). For each platform it checks the image config's
// os/architecture/variant and entrypoint, then reads the layer tars and
// asserts the entrypoint binary exists, is executable, and is an ELF for the
// right machine type. It also checks the multi-arch index lists exactly the
// expected platforms, each pointing at a manifest that passes the same checks.
package container_test

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	amd64Layout = flag.String("amd64_layout", "", "path to the weft_image_amd64 OCI layout directory")
	arm64Layout = flag.String("arm64_layout", "", "path to the weft_image_arm64_v8 OCI layout directory")
	indexLayout = flag.String("index_layout", "", "path to the weft_image (multi-arch index) OCI layout directory")
)

const (
	mediaTypeOCIIndex    = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeOCIManifest = "application/vnd.oci.image.manifest.v1+json"
)

type descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *platform `json:"platform,omitempty"`
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type index struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
}

type imageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
	Config       struct {
		Entrypoint []string `json:"Entrypoint"`
	} `json:"config"`
}

// expectation describes what one platform's image must contain.
type expectation struct {
	arch       string
	variant    string
	entrypoint string
	machine    elf.Machine
}

var (
	wantAMD64 = expectation{arch: "amd64", entrypoint: "/usr/bin/weft", machine: elf.EM_X86_64}
	wantARM64 = expectation{arch: "arm64", variant: "v8", entrypoint: "/usr/bin/weft_arm64", machine: elf.EM_AARCH64}
)

// blobPath maps a "sha256:<hex>" digest to its file in an OCI layout.
func blobPath(layout, digest string) (string, error) {
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hex == "" {
		return "", fmt.Errorf("malformed digest %q", digest)
	}
	return filepath.Join(layout, "blobs", algo, hex), nil
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func readBlobJSON(t *testing.T, layout string, d descriptor, v any) {
	t.Helper()
	p, err := blobPath(layout, d.Digest)
	if err != nil {
		t.Fatal(err)
	}
	readJSON(t, p, v)
}

// topDescriptor returns the single descriptor in the layout's index.json.
func topDescriptor(t *testing.T, layout string) descriptor {
	t.Helper()
	var top index
	readJSON(t, filepath.Join(layout, "index.json"), &top)
	if len(top.Manifests) != 1 {
		t.Fatalf("%s/index.json: want 1 top-level descriptor, got %d", layout, len(top.Manifests))
	}
	t.Logf("%s: top descriptor %s (%s)", layout, top.Manifests[0].Digest, top.Manifests[0].MediaType)
	return top.Manifests[0]
}

// openLayer returns a tar reader over a layer blob, transparently handling
// gzip-compressed and uncompressed layers.
func openLayer(t *testing.T, layout string, d descriptor) (*tar.Reader, func()) {
	t.Helper()
	p, err := blobPath(layout, d.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open layer %s: %v", d.Digest, err)
	}
	br := bufio.NewReader(f)
	magic, _ := br.Peek(4)
	var r io.Reader = br
	closeFn := func() { f.Close() }
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			t.Fatalf("gunzip layer %s: %v", d.Digest, err)
		}
		r = gz
		closeFn = func() { gz.Close(); f.Close() }
	case len(magic) == 4 && bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		f.Close()
		t.Fatalf("layer %s is zstd-compressed (%s); this test only reads gzip or plain tar layers", d.Digest, d.MediaType)
	}
	return tar.NewReader(r), closeFn
}

// findFile scans every layer in order and returns the last version of the
// file at absPath (later layers override earlier ones), or ok=false if no
// layer contains it.
func findFile(t *testing.T, layout string, layers []descriptor, absPath string) (hdr *tar.Header, content []byte, ok bool) {
	t.Helper()
	want := strings.TrimPrefix(absPath, "/")
	for i, l := range layers {
		tr, closeFn := openLayer(t, layout, l)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				closeFn()
				t.Fatalf("layer %d (%s): read tar: %v", i, l.Digest, err)
			}
			name := strings.TrimPrefix(strings.TrimPrefix(h.Name, "./"), "/")
			if name != want {
				continue
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				closeFn()
				t.Fatalf("layer %d: read %s: %v", i, absPath, err)
			}
			t.Logf("layer %d (%s): found %s (type %c, mode %o, %d bytes)", i, l.Digest, absPath, h.Typeflag, h.Mode, len(data))
			hdr, content, ok = h, data, true
		}
		closeFn()
	}
	return hdr, content, ok
}

// checkManifest verifies one platform image manifest against want.
func checkManifest(t *testing.T, layout string, md descriptor, want expectation) {
	t.Helper()
	if md.MediaType != "" && md.MediaType != mediaTypeOCIManifest {
		t.Fatalf("manifest %s: unexpected media type %q", md.Digest, md.MediaType)
	}
	var m manifest
	readBlobJSON(t, layout, md, &m)
	var cfg imageConfig
	readBlobJSON(t, layout, m.Config, &cfg)
	t.Logf("manifest %s: os=%s arch=%s variant=%q entrypoint=%v layers=%d",
		md.Digest, cfg.OS, cfg.Architecture, cfg.Variant, cfg.Config.Entrypoint, len(m.Layers))

	if cfg.OS != "linux" {
		t.Errorf("config os = %q, want linux", cfg.OS)
	}
	if cfg.Architecture != want.arch {
		t.Errorf("config architecture = %q, want %q", cfg.Architecture, want.arch)
	}
	if want.variant != "" && cfg.Variant != want.variant {
		t.Errorf("config variant = %q, want %q", cfg.Variant, want.variant)
	}
	if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != want.entrypoint {
		t.Fatalf("config entrypoint = %v, want [%s]", cfg.Config.Entrypoint, want.entrypoint)
	}

	hdr, data, ok := findFile(t, layout, m.Layers, want.entrypoint)
	if !ok {
		t.Fatalf("entrypoint %s not present in any layer", want.entrypoint)
	}
	if hdr.Typeflag != tar.TypeReg {
		t.Fatalf("entrypoint %s is not a regular file (type %c)", want.entrypoint, hdr.Typeflag)
	}
	if hdr.Mode&0o111 == 0 {
		t.Errorf("entrypoint %s is not executable (mode %o)", want.entrypoint, hdr.Mode)
	}
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("entrypoint %s is not an ELF binary: %v", want.entrypoint, err)
	}
	defer ef.Close()
	t.Logf("entrypoint %s: ELF class=%s machine=%s type=%s", want.entrypoint, ef.Class, ef.Machine, ef.Type)
	if ef.Machine != want.machine {
		t.Errorf("entrypoint %s ELF machine = %s, want %s", want.entrypoint, ef.Machine, want.machine)
	}
	if ef.Class != elf.ELFCLASS64 {
		t.Errorf("entrypoint %s ELF class = %s, want ELFCLASS64", want.entrypoint, ef.Class)
	}
}

// requireFlag returns the layout path passed in -name, resolved against the
// Bazel runfiles tree (rules_go runs tests from the package directory, while
// $(rootpath) is relative to the workspace root).
func requireFlag(t *testing.T, name, v string) string {
	t.Helper()
	if v == "" {
		t.Fatalf("-%s not set; run via bazel test //container:container_test", name)
	}
	if _, err := os.Stat(v); err == nil {
		return v
	}
	if srcdir, ws := os.Getenv("TEST_SRCDIR"), os.Getenv("TEST_WORKSPACE"); srcdir != "" && ws != "" {
		p := filepath.Join(srcdir, ws, v)
		t.Logf("-%s: resolved %s to runfiles path %s", name, v, p)
		return p
	}
	return v
}

func TestImageAMD64(t *testing.T) {
	layout := requireFlag(t, "amd64_layout", *amd64Layout)
	checkManifest(t, layout, topDescriptor(t, layout), wantAMD64)
}

func TestImageARM64(t *testing.T) {
	layout := requireFlag(t, "arm64_layout", *arm64Layout)
	checkManifest(t, layout, topDescriptor(t, layout), wantARM64)
}

func TestImageIndex(t *testing.T) {
	layout := requireFlag(t, "index_layout", *indexLayout)
	top := topDescriptor(t, layout)
	if top.MediaType != mediaTypeOCIIndex && top.MediaType != mediaTypeDockerList {
		t.Fatalf("top descriptor media type = %q, want an image index", top.MediaType)
	}
	var idx index
	readBlobJSON(t, layout, top, &idx)

	byPlatform := map[string]expectation{
		"linux/amd64":    wantAMD64,
		"linux/arm64/v8": wantARM64,
	}
	seen := map[string]bool{}
	for _, md := range idx.Manifests {
		if md.Platform == nil {
			t.Fatalf("index manifest %s has no platform", md.Digest)
		}
		key := md.Platform.OS + "/" + md.Platform.Architecture
		if md.Platform.Variant != "" {
			key += "/" + md.Platform.Variant
		}
		t.Logf("index entry %s -> %s", key, md.Digest)
		want, ok := byPlatform[key]
		if !ok {
			t.Errorf("index lists unexpected platform %s", key)
			continue
		}
		if seen[key] {
			t.Errorf("index lists platform %s twice", key)
		}
		seen[key] = true
		t.Run(strings.ReplaceAll(key, "/", "_"), func(t *testing.T) {
			checkManifest(t, layout, md, want)
		})
	}
	for key := range byPlatform {
		if !seen[key] {
			t.Errorf("index is missing platform %s", key)
		}
	}
}
