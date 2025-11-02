// Copyright (c) 2025 Luis E. Muñoz. All Rights Reserved.
// SPDX-License-Identifier: MIT

package nspool

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ulikunitz/xz"
)

func TestFileArray(t *testing.T) {
	t.Run("nil array returns nil slice", func(t *testing.T) {
		var fa FileArray
		if got := fa.StringSlice(); got != nil {
			t.Errorf("nil FileArray.StringSlice() = %v; want nil", got)
		}
	})

	t.Run("file reference", func(t *testing.T) {
		// Create a temporary file with some test data
		content := `# Test resolvers
1.1.1.1:53
8.8.8.8:53

# Google DNS
9.9.9.9:53`

		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "resolvers.txt")
		if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		// Use file reference directly
		resolvers, err := NewFileArray("@" + tmpFile)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		if !reflect.DeepEqual(resolvers.StringSlice(), expected) {
			t.Errorf("Expected %v, got %v", expected, resolvers.StringSlice())
		}
	})

	t.Run("direct values array", func(t *testing.T) {
		resolvers, err := NewFileArray([]string{"1.1.1.1:53", "8.8.8.8:53"})
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{"1.1.1.1:53", "8.8.8.8:53"}
		if !reflect.DeepEqual(resolvers.StringSlice(), expected) {
			t.Errorf("Expected %v, got %v", expected, resolvers.StringSlice())
		}
	})

	t.Run("single direct value", func(t *testing.T) {
		resolvers, err := NewFileArray("1.1.1.1:53")
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{"1.1.1.1:53"}
		if !reflect.DeepEqual(resolvers.StringSlice(), expected) {
			t.Errorf("Expected %v, got %v", expected, resolvers.StringSlice())
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := NewFileArray("@nonexistent.txt")
		if err == nil {
			t.Error("NewFileArray(@nonexistent) expected error, got nil")
		}
	})

	t.Run("file read error", func(t *testing.T) {
		// Create temporary file with no read permissions
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "noperm.txt")
		if err := os.WriteFile(tmpFile, []byte("1.1.1.1:53"), 0000); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		_, err := NewFileArray("@" + tmpFile)
		if err == nil {
			t.Error("NewFileArray with unreadable file expected error, got nil")
		}
	})

	t.Run("invalid input type", func(t *testing.T) {
		fa, err := NewFileArray(123) // Pass an int
		if err != nil {
			t.Fatalf("NewFileArray(int) error = %v", err)
		}
		if fa != nil {
			t.Errorf("NewFileArray(int) = %v; want nil", fa)
		}
	})

	t.Run("gzip compressed file", func(t *testing.T) {
		// Create a temporary gzip file with test data
		content := `# Compressed resolvers
1.1.1.1:53
8.8.8.8:53

# Google DNS
9.9.9.9:53`

		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "resolvers.gz")
		file, err := os.Create(tmpFile)
		if err != nil {
			t.Fatal(err)
		}
		gzw := gzip.NewWriter(file)
		if _, err := gzw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := gzw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}

		resolvers, err := NewFileArray("@" + tmpFile)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		if !reflect.DeepEqual(resolvers.StringSlice(), expected) {
			t.Errorf("Expected %v, got %v", expected, resolvers.StringSlice())
		}
	})

	t.Run("bzip2 compressed file", func(t *testing.T) {
		// Create a temporary bzip2 file with test data
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "resolvers.bz2")
		file, err := os.Create(tmpFile)
		if err != nil {
			t.Fatal(err)
		}

		// bzip2 doesn't have a Writer in stdlib, we'll verify error handling
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}

		// This should fail since we didn't write valid bzip2 data
		_, err = NewFileArray("@" + tmpFile)
		if err == nil {
			t.Error("Expected error with invalid bzip2 file, got nil")
		}
	})

	t.Run("xz compressed file", func(t *testing.T) {
		// Create a temporary xz file with test data
		content := `# Compressed resolvers
1.1.1.1:53
8.8.8.8:53

# Google DNS
9.9.9.9:53`

		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "resolvers.xz")
		file, err := os.Create(tmpFile)
		if err != nil {
			t.Fatal(err)
		}
		xzw, err := xz.NewWriter(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := xzw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := xzw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}

		resolvers, err := NewFileArray("@" + tmpFile)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		if !reflect.DeepEqual(resolvers.StringSlice(), expected) {
			t.Errorf("Expected %v, got %v", expected, resolvers.StringSlice())
		}
	})

	t.Run("invalid compressed file", func(t *testing.T) {
		// Create a file with .gz extension but invalid content
		tmpDir := t.TempDir()
		tmpFile := filepath.Join(tmpDir, "invalid.gz")
		if err := os.WriteFile(tmpFile, []byte("not a gzip file"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := NewFileArray("@" + tmpFile)
		if err == nil {
			t.Error("Expected error with invalid gzip file, got nil")
		}
	})
}
