package utils

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// withMaxLine lowers the line cap for one test so the oversized-line paths
// can be exercised without building a 100 MiB payload.
func withMaxLine(t *testing.T, n int) {
	t.Helper()
	prev := MaxBundleLineSize
	MaxBundleLineSize = n
	t.Cleanup(func() { MaxBundleLineSize = prev })
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	out := bytes.Buffer{}
	w := gzip.NewWriter(&out)
	if _, err := w.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return out.Bytes()
}

func gunzipAll(t *testing.T, b []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

// cloudTrailBlob builds a single-line CloudTrail delivery file holding n
// near-identical events, the shape that gzips hundreds-to-one and blows the
// proxy's line cap.
func cloudTrailBlob(n int) []byte {
	b := strings.Builder{}
	b.WriteString(`{"Records":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"eventVersion":"1.08","eventName":"AssumeRole","eventID":"id-%d","requestParameters":{"roleArn":"arn:aws:iam::111111111111:role/Some/Role"}}`, i)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func TestCloudTrailToJSONLines_SplitsRecords(t *testing.T) {
	out := bytes.Buffer{}
	n, err := CloudTrailToJSONLines(bytes.NewReader(cloudTrailBlob(3)), &out)
	if err != nil {
		t.Fatalf("CloudTrailToJSONLines: %v", err)
	}
	if n != 3 {
		t.Fatalf("record count = %d, want 3", n)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3", len(lines))
	}
	for i, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if rec["eventName"] != "AssumeRole" {
			t.Errorf("line %d eventName = %v", i, rec["eventName"])
		}
	}
}

func TestCloudTrailToJSONLines_RecordsNotFirstKey(t *testing.T) {
	in := `{"schemaVersion":"1.0","Records":[{"a":1},{"a":2}]}`
	out := bytes.Buffer{}
	n, err := CloudTrailToJSONLines(strings.NewReader(in), &out)
	if err != nil {
		t.Fatalf("CloudTrailToJSONLines: %v", err)
	}
	if n != 2 {
		t.Fatalf("record count = %d, want 2", n)
	}
}

// Pretty-printed input must not leak newlines into the middle of a record,
// or the proxy's line scanner would see fragments instead of events.
func TestCloudTrailToJSONLines_CompactsPrettyInput(t *testing.T) {
	in := "{\n \"Records\": [\n  {\n   \"a\": 1,\n   \"b\": \"x\"\n  },\n  {\n   \"a\": 2\n  }\n ]\n}"
	out := bytes.Buffer{}
	n, err := CloudTrailToJSONLines(strings.NewReader(in), &out)
	if err != nil {
		t.Fatalf("CloudTrailToJSONLines: %v", err)
	}
	if n != 2 {
		t.Fatalf("record count = %d, want 2", n)
	}
	if got := bytes.Count(out.Bytes(), []byte("\n")); got != 2 {
		t.Fatalf("newline count = %d, want 2 (one per record)", got)
	}
}

func TestCloudTrailToJSONLines_NotCloudTrail(t *testing.T) {
	for _, in := range []string{`[1,2,3]`, `{"other":{"nested":1}}`, `"just a string"`, ``} {
		out := bytes.Buffer{}
		if _, err := CloudTrailToJSONLines(strings.NewReader(in), &out); !errors.Is(err, ErrNotCloudTrail) {
			t.Errorf("input %q: err = %v, want ErrNotCloudTrail", in, err)
		}
	}
}

func TestLongestLine(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"abc\n", 3},
		{"a\nbbbb\ncc", 4},
		{"\n\n", 0},
		{"aa\nbbbbbb", 6},
	}
	for _, c := range cases {
		if got := longestLine([]byte(c.in)); got != c.want {
			t.Errorf("longestLine(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestLongestLineFromGzip(t *testing.T) {
	got, err := longestLineFromGzip(gz(t, []byte("aa\nbbbbbb\nc")))
	if err != nil {
		t.Fatalf("longestLineFromGzip: %v", err)
	}
	if got != 6 {
		t.Fatalf("longest = %d, want 6", got)
	}
}

// The regression test for the wedge: a gzipped single-line CloudTrail file
// over the cap must come back as splittable lines instead of an error.
func TestPrepareBundleData_OversizedGzippedCloudTrailIsSplit(t *testing.T) {
	withMaxLine(t, 2048)

	raw := cloudTrailBlob(200)
	if len(raw) <= MaxBundleLineSize {
		t.Fatalf("test blob %d bytes is not over the cap %d", len(raw), MaxBundleLineSize)
	}
	if got := longestLine(raw); got != len(raw) {
		t.Fatalf("blob should be a single line: longest %d of %d", got, len(raw))
	}

	data, isCompressed, err := PrepareBundleData("CloudTrail/x.json.gz", gz(t, raw))
	if err != nil {
		t.Fatalf("PrepareBundleData: %v", err)
	}
	if !isCompressed {
		t.Fatal("isCompressed = false, want true (flattened output is re-gzipped)")
	}
	lines := bytes.Split(bytes.TrimSuffix(gunzipAll(t, data), []byte("\n")), []byte("\n"))
	if len(lines) != 200 {
		t.Fatalf("line count = %d, want 200", len(lines))
	}
	for i, l := range lines {
		if len(l) > MaxBundleLineSize {
			t.Fatalf("line %d is %d bytes, still over cap %d", i, len(l), MaxBundleLineSize)
		}
		var rec map[string]any
		if err := json.Unmarshal(l, &rec); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
	}
}

func TestPrepareBundleData_OversizedPlainCloudTrailIsSplit(t *testing.T) {
	withMaxLine(t, 2048)

	data, isCompressed, err := PrepareBundleData("CloudTrail/x.json", cloudTrailBlob(200))
	if err != nil {
		t.Fatalf("PrepareBundleData: %v", err)
	}
	if !isCompressed {
		t.Fatal("isCompressed = false, want true")
	}
	if got := bytes.Count(gunzipAll(t, data), []byte("\n")); got != 200 {
		t.Fatalf("record lines = %d, want 200", got)
	}
}

// An oversized line with no record boundary to split on must fail just this
// file, not get shipped and wedge the connection.
func TestPrepareBundleData_OversizedNonCloudTrailIsSkipped(t *testing.T) {
	withMaxLine(t, 64)

	blob := bytes.Repeat([]byte("x"), 512)
	if _, _, err := PrepareBundleData("weird.log", blob); !errors.Is(err, ErrLineTooLarge) {
		t.Errorf("plain: err = %v, want ErrLineTooLarge", err)
	}
	if _, _, err := PrepareBundleData("weird.log.gz", gz(t, blob)); !errors.Is(err, ErrLineTooLarge) {
		t.Errorf("gzipped: err = %v, want ErrLineTooLarge", err)
	}
}

// Files under the cap must behave exactly as before the guard existed.
func TestPrepareBundleData_UnderCapUnchanged(t *testing.T) {
	plain := []byte("line one\nline two\n")
	data, isCompressed, err := PrepareBundleData("a.log", plain)
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	if isCompressed || !bytes.Equal(data, plain) {
		t.Fatalf("plain passthrough changed: isCompressed=%v", isCompressed)
	}

	zipped := gz(t, plain)
	data, isCompressed, err = PrepareBundleData("a.log.gz", zipped)
	if err != nil {
		t.Fatalf("gzipped: %v", err)
	}
	if !isCompressed || !bytes.Equal(data, zipped) {
		t.Fatalf("gzip passthrough changed: isCompressed=%v", isCompressed)
	}
}
