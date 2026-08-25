package utils

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// MaxBundleLineSize mirrors the ingestion proxy's per-line cap. The proxy
// splits a bundle payload on newlines and rejects the whole payload when any
// single line is bigger:
//
//	line too large: 107080958 bytes exceeds max 104857600
//
// That rejection tears down the websocket before the message is acked, so the
// uspclient ack buffer re-sends it on every reconnect ("re-transmitting N
// previously unacked messages") and the adapter never makes forward progress
// again. One bad object disables ingestion indefinitely instead of failing
// just that object, so it is worth detecting before shipping.
//
// A var rather than a const so tests can exercise the threshold without
// building a 100 MiB payload; treat it as read-only at runtime.
var MaxBundleLineSize = 100 * 1024 * 1024 // 104857600

// MaxDecompressedSize bounds how much output a gunzip pass will pull from an
// object before giving up, so a gzip bomb cannot exhaust memory.
const MaxDecompressedSize = 1 << 30

// ErrLineTooLarge marks a payload the proxy would reject for line length.
var ErrLineTooLarge = errors.New("line too large")

// CheckMaxLineSize reports whether data is safe to ship as a bundle payload,
// returning an error wrapping ErrLineTooLarge when any newline-delimited line
// exceeds MaxBundleLineSize. Set isCompressed when data is gzipped and the
// proxy will gunzip it; the check then measures the decompressed form, which
// is what the proxy's line scanner actually sees.
//
// The gzipped path streams and discards, so it costs one decompression pass
// but constant memory.
func CheckMaxLineSize(name string, data []byte, isCompressed bool) error {
	var longest int
	if isCompressed {
		n, err := longestLineFromGzip(data)
		if err != nil {
			return fmt.Errorf("scan %s: %w", name, err)
		}
		longest = n
	} else {
		longest = longestLine(data)
	}
	if longest > MaxBundleLineSize {
		return fmt.Errorf("%w: %s has a line of %d bytes, max %d", ErrLineTooLarge, name, longest, MaxBundleLineSize)
	}
	return nil
}

// longestLine returns the length of the longest newline-delimited line in
// data. A trailing run with no newline counts as a line.
func longestLine(data []byte) int {
	longest := 0
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			if len(data) > longest {
				longest = len(data)
			}
			return longest
		}
		if i > longest {
			longest = i
		}
		data = data[i+1:]
	}
}

// longestLineFromGzip streams the gunzipped form of data and returns the
// length of its longest line without ever holding the decompressed bytes.
func longestLineFromGzip(data []byte) (int, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	r := io.LimitReader(zr, MaxDecompressedSize+1)
	buf := make([]byte, 64*1024)
	longest, current, total := 0, 0, int64(0)
	for {
		n, readErr := r.Read(buf)
		total += int64(n)
		if total > MaxDecompressedSize {
			return 0, fmt.Errorf("decompressed size exceeds %d bytes", int64(MaxDecompressedSize))
		}
		chunk := buf[:n]
		for {
			i := bytes.IndexByte(chunk, '\n')
			if i < 0 {
				current += len(chunk)
				if current > longest {
					longest = current
				}
				break
			}
			current += i
			if current > longest {
				longest = current
			}
			current = 0
			chunk = chunk[i+1:]
		}
		if readErr == io.EOF {
			return longest, nil
		}
		if readErr != nil {
			return 0, readErr
		}
	}
}
