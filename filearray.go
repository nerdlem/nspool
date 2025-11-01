package nspool

import (
	"bufio"
	"os"
	"strings"
)

// FileArray is a string slice that can be populated from a file or direct values in configuration.
// It supports three use cases:
//
//  1. Single file reference:
//     "@/path/to/file" -> [lines from file]
//     Each non-empty, non-comment line in the file becomes an element.
//
//  2. String slice:
//     ["ns1:53", "ns2:53"] -> ["ns1:53", "ns2:53"]
//     Array values are used directly.
//
//  3. Single string:
//     "ns1:53" -> ["ns1:53"]
//     Single string becomes a one-element slice.
type FileArray []string

// NewFileArray creates a FileArray from a string or []string input.
// If the input is a string starting with "@", it reads from the file.
func NewFileArray(input interface{}) (FileArray, error) {
	switch v := input.(type) {
	case string:
		var fa FileArray
		if strings.HasPrefix(v, "@") {
			file, err := os.Open(strings.TrimPrefix(v, "@"))
			if err != nil {
				return nil, err
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
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
