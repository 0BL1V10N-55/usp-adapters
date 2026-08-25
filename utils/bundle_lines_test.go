package utils

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

func withMaxLine(t *testing.T, n int) {
	t.Helper()
	prev := MaxBundleLineSize
	MaxBundleLineSize = n
	t.Cleanup(func() { MaxBundleLineSize = prev })
}

func gzBytes(t *testing.T, b []byte) []byte {
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
	got, err := longestLineFromGzip(gzBytes(t, []byte("aa\nbbbbbb\nc")))
	if err != nil {
		t.Fatalf("longestLineFromGzip: %v", err)
	}
	if got != 6 {
		t.Fatalf("longest = %d, want 6", got)
	}
}

// A CloudTrail file is one JSON object with no interior newlines, which is
// exactly the shape that trips the proxy's per-line cap.
func TestCheckMaxLineSize_SingleLineOverCap(t *testing.T) {
	withMaxLine(t, 64)

	blob := []byte(`{"Records":[` + strings.Repeat(`{"a":1},`, 100) + `{"a":1}]}`)

	err := CheckMaxLineSize("CloudTrail/x.json", blob, false)
	if !errors.Is(err, ErrLineTooLarge) {
		t.Errorf("plain: err = %v, want ErrLineTooLarge", err)
	}
	err = CheckMaxLineSize("CloudTrail/x.json.gz", gzBytes(t, blob), true)
	if !errors.Is(err, ErrLineTooLarge) {
		t.Errorf("gzipped: err = %v, want ErrLineTooLarge", err)
	}
	// The message must name the file and both sizes to be actionable.
	if s := err.Error(); !strings.Contains(s, "CloudTrail/x.json.gz") || !strings.Contains(s, "max 64") {
		t.Errorf("error lacks context: %q", s)
	}
}

func TestCheckMaxLineSize_UnderCapPasses(t *testing.T) {
	plain := []byte("line one\nline two\n")
	if err := CheckMaxLineSize("a.log", plain, false); err != nil {
		t.Errorf("plain: %v", err)
	}
	if err := CheckMaxLineSize("a.log.gz", gzBytes(t, plain), true); err != nil {
		t.Errorf("gzipped: %v", err)
	}
}

// Many small lines must pass even when the total dwarfs the cap: the proxy
// limits a line, not the payload.
func TestCheckMaxLineSize_ManySmallLinesPass(t *testing.T) {
	withMaxLine(t, 64)

	body := bytes.Repeat([]byte("0123456789\n"), 5000)
	if err := CheckMaxLineSize("many.log", body, false); err != nil {
		t.Errorf("plain: %v", err)
	}
	if err := CheckMaxLineSize("many.log.gz", gzBytes(t, body), true); err != nil {
		t.Errorf("gzipped: %v", err)
	}
}

func TestCheckMaxLineSize_BadGzip(t *testing.T) {
	if err := CheckMaxLineSize("broken.gz", []byte("not gzip at all"), true); err == nil {
		t.Error("expected an error for malformed gzip")
	}
}
