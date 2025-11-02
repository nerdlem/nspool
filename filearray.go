// Copyright (c) 2025 Luis E. Muñoz. All Rights Reserved.
// SPDX-License-Identifier: MIT

package nspool

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

// FileArray is a string slice that can be populated from a file or direct values in configuration.
// It supports three use cases:
//
//  1. Single file reference:
//     "@/path/to/file[.gz|.bz2|.xz]" -> [lines from file]
//     Each non-empty, non-comment line in the file becomes an element.
//     The file can be optionally compressed with gzip (.gz), bzip2 (.bz2),
//     or xz (.xz) compression - decompression happens automatically.
//
//  2. String slice:
//     ["ns1:53", "ns2:53"] -> ["ns1:53", "ns2:53"]
//     Array values are used directly.
//
//  3. Single string:
//     "ns1:53" -> ["ns1:53"]
//     Single string becomes a one-element slice.
type FileArray []string

// UnmarshalText implements encoding.TextUnmarshaler for FileArray
func (f *FileArray) UnmarshalText(text []byte) error {
	str := string(text)
	fa, err := NewFileArray(str)
	if err != nil {
		return err
	}
	*f = fa
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for FileArray
func (f *FileArray) UnmarshalJSON(data []byte) error {
	// Remove quotes if present
	str := string(data)
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		str = str[1 : len(str)-1]
	}

	// Try unmarshaling as string array first
	var strArr []string
	if err := json.Unmarshal(data, &strArr); err == nil {
		if len(strArr) == 1 && strings.HasPrefix(strArr[0], "@") {
			// Single array element with @ - treat as file reference
			fa, err := NewFileArray(strArr[0])
			if err != nil {
				return err
			}
			*f = fa
			return nil
		}
		*f = FileArray(strArr)
		return nil
	}

	// If not array, try as single string
	fa, err := NewFileArray(str)
	if err != nil {
		return err
	}
	*f = fa
	return nil
}

// UnmarshalTOML implements the interface for TOML decoding.
func (f *FileArray) UnmarshalTOML(data interface{}) error {
	switch v := data.(type) {
	case string:
		fa, err := NewFileArray(v)
		if err != nil {
			return err
		}
		*f = fa
	case []interface{}:
		if len(v) == 1 {
			if str, ok := v[0].(string); ok && strings.HasPrefix(str, "@") {
				fa, err := NewFileArray(str)
				if err != nil {
					return err
				}
				*f = fa
				return nil
			}
		}
		strArr := make([]string, len(v))
		for i, val := range v {
			if str, ok := val.(string); ok {
				strArr[i] = str
			} else {
				return fmt.Errorf("invalid array element type: %T", val)
			}
		}
		*f = FileArray(strArr)
	default:
		return fmt.Errorf("unsupported type for FileArray: %T", data)
	}
	return nil
}

// openCompressedFile opens a file and returns an appropriate reader based on the file extension.
// It supports .gz (gzip), .bz2 (bzip2), and .xz compression formats.
func openCompressedFile(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".gz":
		reader, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("gzip error: %v", err)
		}
		return reader, nil
	case ".bz2":
		// bzip2 doesn't need a Close method
		return struct {
			io.Reader
			io.Closer
		}{
			Reader: bzip2.NewReader(file),
			Closer: file,
		}, nil
	case ".xz":
		reader, err := xz.NewReader(file)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("xz error: %v", err)
		}
		return struct {
			io.Reader
			io.Closer
		}{
			Reader: reader,
			Closer: file,
		}, nil
	default:
		return file, nil
	}
}

// NewFileArray creates a FileArray from a string or []string input.
// If the input is a string starting with "@", it reads from the file.
// The file can be optionally compressed with gzip (.gz), bzip2 (.bz2),
// or xz (.xz) compression - decompression happens automatically.
func NewFileArray(input interface{}) (FileArray, error) {
	switch v := input.(type) {
	case string:
		var fa FileArray
		if strings.HasPrefix(v, "@") {
			path := strings.TrimPrefix(v, "@")
			reader, err := openCompressedFile(path)
			if err != nil {
				return nil, err
			}
			defer reader.Close()

			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					fa = append(fa, line)
				}
			}
			if err := scanner.Err(); err != nil {
				return nil, err
			}
		} else {
			fa = FileArray{v}
		}
		return fa, nil
	case []string:
		return FileArray(v), nil
	default:
		return nil, nil
	}
}

// StringSlice returns the underlying string slice
func (f FileArray) StringSlice() []string {
	if f == nil {
		return nil
	}
	return []string(f)
}
