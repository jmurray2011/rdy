// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/rpmpack"
	"github.com/klauspost/compress/zstd"
	rpmutils "github.com/sassoftware/go-rpmutils"
	"github.com/ulikunitz/xz"
)

// fixtureRPM builds a fictional RPM with one file and one symlink.
func fixtureRPM(t *testing.T) []byte {
	t.Helper()
	r, err := rpmpack.NewRPM(rpmpack.RPMMetaData{Name: "fictional-gate-fixture", Version: "2.4.0", Release: "1", Arch: "noarch", Compressor: "gzip"})
	if err != nil {
		t.Fatal(err)
	}
	r.AddFile(rpmpack.RPMFile{Name: "/usr/share/fictional", Mode: 0o40755, Owner: "root", Group: "root"})
	r.AddFile(rpmpack.RPMFile{Name: "/usr/share/fictional/data.txt", Body: []byte("fixture"), Mode: 0o100644, Owner: "root", Group: "root"})
	r.AddFile(rpmpack.RPMFile{Name: "/usr/share/fictional/current", Body: []byte("data.txt"), Mode: 0o120777, Owner: "root", Group: "root"})
	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pad4(n int) []byte { return make([]byte, (4-n%4)%4) }

// stripPayload rewrites an RPM's newc payload into the stripped form RPM 6 writes:
// "07070X" plus the file's header index, padded to four, then the content padded to four.
func stripPayload(t *testing.T, rpm []byte) []byte {
	t.Helper()
	hdr, err := rpmutils.ReadHeader(bytes.NewReader(rpm))
	if err != nil {
		t.Fatal(err)
	}
	infos, err := hdr.GetFiles()
	if err != nil {
		t.Fatal(err)
	}
	index := map[string]int{}
	for i, fi := range infos {
		index[fi.Name()] = i
	}
	end := hdr.GetRange().End
	gz, err := gzip.NewReader(bytes.NewReader(rpm[end:]))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for pos := 0; ; {
		h := payload[pos : pos+110]
		size, _ := strconv.ParseInt(string(h[54:62]), 16, 64)
		namesize, _ := strconv.ParseInt(string(h[94:102]), 16, 64)
		name := string(payload[pos+110 : pos+110+int(namesize)-1])
		body := pos + 110 + int(namesize)
		body += len(pad4(body))
		if name == "TRAILER!!!" {
			out.Write(payload[pos:])
			break
		}
		idx, ok := index[strings.TrimPrefix(name, ".")]
		if !ok {
			t.Fatalf("archive entry %q not in header", name)
		}
		e := fmt.Sprintf("07070X%08x", idx)
		out.WriteString(e)
		out.Write(pad4(len(e)))
		out.Write(payload[body : body+int(size)])
		out.Write(pad4(int(size)))
		pos = body + int(size)
		pos += len(pad4(pos))
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{}, rpm[:end]...), z.Bytes()...)
}

func tarOf(t *testing.T, entries []*tar.Header, bodies map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		body := bodies[h.Name]
		h.Size = int64(len(body))
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeDir {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func compressed(t *testing.T, kind string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	var err error
	switch kind {
	case "gz":
		w = gzip.NewWriter(&buf)
	case "xz":
		w, err = xz.NewWriter(&buf)
	case "zst":
		w, err = zstd.NewWriter(&buf)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fixtureDEB builds a fictional .deb whose data member uses the given compression.
func fixtureDEB(t *testing.T, dataCompression string) []byte {
	t.Helper()
	control := tarOf(t, []*tar.Header{{Name: "./control", Mode: 0o644, Typeflag: tar.TypeReg}}, map[string]string{
		"./control": "Package: fictional-gate-fixture\nVersion: 1:2.4.0-3\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Fictional fixture\n",
	})
	data := tarOf(t, []*tar.Header{
		{Name: "./usr/share/fictional/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "./usr/share/fictional/data.txt", Mode: 0o644, Typeflag: tar.TypeReg},
		{Name: "./usr/share/fictional/current", Linkname: "data.txt", Typeflag: tar.TypeSymlink},
	}, map[string]string{"./usr/share/fictional/data.txt": "fixture"})
	members := [][2]string{
		{"debian-binary", "2.0\n"},
		{"control.tar.gz", string(compressed(t, "gz", control))},
		{"data.tar." + dataCompression, string(compressed(t, dataCompression, data))},
	}
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m[0], 0, 0, 0, "100644", len(m[1]))
		buf.WriteString(m[1])
		if len(m[1])%2 == 1 {
			buf.WriteString("\n")
		}
	}
	return buf.Bytes()
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertFixturePayload(t *testing.T, root string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "usr", "share", "fictional", "data.txt"))
	if err != nil || string(data) != "fixture" {
		t.Fatalf("payload = %q, %v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "usr", "share", "fictional", "current")); !os.IsNotExist(err) {
		t.Fatal("symlink was materialized; links must be skipped")
	}
}

func TestRPMExtractsInGo(t *testing.T) {
	t.Parallel()
	rpm := fixtureRPM(t)
	for name, data := range map[string][]byte{
		"APP.RPM":                         rpm, // uppercase extension still routes to RPM
		"fictional-gate-fixture-rpm6.rpm": stripPayload(t, rpm),
	} {
		root := filepath.Join(t.TempDir(), "out")
		links := 0
		version, err := extract(context.Background(), writeFixture(t, name, data), root, &links)
		if err != nil || version != "2.4.0" || links != 1 {
			t.Fatalf("%s: version=%s links=%d err=%v", name, version, links, err)
		}
		assertFixturePayload(t, root)
	}
}

func TestDEBExtractsInGo(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"gz", "xz", "zst"} {
		root := filepath.Join(t.TempDir(), "out")
		links := 0
		raw, err := extract(context.Background(), writeFixture(t, "fixture.deb", fixtureDEB(t, c)), root, &links)
		if err != nil || raw != "1:2.4.0-3" || normalizeDeclared(raw, "dpkg control") != "2.4.0" || links != 1 {
			t.Fatalf("data.tar.%s: raw=%s links=%d err=%v", c, raw, links, err)
		}
		assertFixturePayload(t, root)
	}
}

func TestPackageExtractionNeedsNoExternalTools(t *testing.T) {
	// Not parallel: clears PATH so any exec of bsdtar, rpm, or dpkg-deb fails.
	t.Setenv("PATH", "")
	for name, data := range map[string][]byte{"app.rpm": fixtureRPM(t), "app.deb": fixtureDEB(t, "xz")} {
		if _, err := extract(context.Background(), writeFixture(t, name, data), filepath.Join(t.TempDir(), "out"), nil); err != nil {
			t.Fatalf("%s needs an external tool: %v", name, err)
		}
	}
}
