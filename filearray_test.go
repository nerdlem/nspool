package nspool

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFileArray(t *testing.T) {
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
}
