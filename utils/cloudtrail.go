package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrNotCloudTrail reports that an object is not a JSON object carrying a
// top-level "Records" array, so the record-splitting path does not apply.
var ErrNotCloudTrail = errors.New("not a CloudTrail Records object")

// CloudTrailToJSONLines rewrites a CloudTrail {"Records":[...]} object into
// newline-delimited JSON, one line per record, and reports how many records
// it wrote.
//
// CloudTrail delivery files are a single JSON object with no interior
// newlines, so the proxy's line scanner sees the whole file as one line. A
// file holding a flood of near-identical events (repeated AssumeRole, or S3
// data events) gzips at several hundred to one, which is how a 200 KB object
// decompresses into a single line past the 100 MiB cap. Splitting on records
// is what makes such a file ingestible: every line is then one event.
//
// It streams. Only one record is held at a time, so a multi-GB object does
// not become a multi-GB allocation. Records are re-compacted rather than
// copied verbatim so that pretty-printed input cannot smuggle newlines into
// the middle of a record.
func CloudTrailToJSONLines(r io.Reader, w io.Writer) (int, error) {
	dec := json.NewDecoder(r)

	tok, err := dec.Token()
	if err != nil {
		return 0, ErrNotCloudTrail
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, ErrNotCloudTrail
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return 0, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return 0, ErrNotCloudTrail
		}
		if key != "Records" {
			// Some other top-level key: consume its value and keep looking.
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, err
			}
			continue
		}

		tok, err := dec.Token()
		if err != nil {
			return 0, err
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return 0, ErrNotCloudTrail
		}

		count := 0
		compacted := bytes.Buffer{}
		for dec.More() {
			var rec json.RawMessage
			if err := dec.Decode(&rec); err != nil {
				return count, err
			}
			compacted.Reset()
			if err := json.Compact(&compacted, rec); err != nil {
				return count, err
			}
			if compacted.Len() > MaxBundleLineSize {
				return count, fmt.Errorf("%w: single record of %d bytes exceeds max %d", ErrLineTooLarge, compacted.Len(), MaxBundleLineSize)
			}
			if _, err := w.Write(compacted.Bytes()); err != nil {
				return count, err
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return count, err
			}
			count++
		}
		return count, nil
	}

	return 0, ErrNotCloudTrail
}
