// Copyright (c) 2025 Luis E. Muñoz. All Rights Reserved.
// SPDX-License-Identifier: MIT

package nspool

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
}
