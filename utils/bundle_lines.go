package utils

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// MaxBundleLineSize mirrors the ingestion proxy's per-line cap. The proxy
// splits a bundle payload on newlines and rejects the entire payload with
//
//	line too large: 107080958 bytes exceeds max 104857600
//
// when any single line is bigger. That rejection tears down the websocket
// before the message is acked, so the uspclient ack buffer re-sends it on
// every reconnect ("re-transmitting N previously unacked messages") and the
// adapter never makes forward progress again. Detecting the condition here
// turns a permanent wedge into one skipped file.
//
// A var rather than a const so tests can exercise the threshold without
// allocating 100 MiB; treat it as read-only at runtime.
var MaxBundleLineSize = 100 * 1024 * 1024 // 104857600

// MaxDecompressedSize bounds how much output the measuring gunzip pass will
// pull from an object before giving up, so a gzip bomb cannot make the
// adapter spin. It matches MaxDecompressedParquetSize; kept separate because
// it applies to any gzipped object, not just parquet.
const MaxDecompressedSize = 1 << 30

// ErrLineTooLarge marks a payload the proxy would reject for line length.
// Callers treat it like any other PrepareBundleData error: log and skip the
// file rather than shipping something that will wedge the connection.
var ErrLineTooLarge = errors.New("line too large")

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
// Output is bounded by MaxDecompressedSize.
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
