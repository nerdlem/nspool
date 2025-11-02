// Copyright (c) 2025 Luis E. Muñoz. All Rights Reserved.
// SPDX-License-Identifier: MIT

package nspool

import (
	"testing"
)

func TestMaxQueryRetries(t *testing.T) {
	tests := []struct {
		name     string
		pool     *Pool
		value    int
		expected int
	}{
		{
			name:     "nil pool",
			pool:     nil,
			expected: 0,
		},
		{
			name:     "default value",
			pool:     NewFromPoolSlice([]string{}),
			expected: 3, // default value from constructor
		},
		{
			name:     "custom value",
			pool:     NewFromPoolSlice([]string{}),
			value:    5,
			expected: 5,
		},
		{
			name:     "zero value",
			pool:     NewFromPoolSlice([]string{}),
			value:    0,
			expected: 0,
		},
		{
			name:     "negative value normalized to zero",
			pool:     NewFromPoolSlice([]string{}),
			value:    -1,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != 0 || tt.name == "zero value" {
				tt.pool.SetMaxQueryRetries(tt.value)
			}
			
			got := tt.pool.MaxQueryRetries()
			if got != tt.expected {
				t.Errorf("MaxQueryRetries() = %v, want %v", got, tt.expected)
			}

			// Test that negative values are normalized to zero
			if tt.pool != nil {
				tt.pool.SetMaxQueryRetries(-1)
				if got := tt.pool.MaxQueryRetries(); got != 0 {
					t.Errorf("MaxQueryRetries() after setting negative = %v, want 0", got)
				}
			}
		})
	}
}

func TestMaxQueryRetriesThreadSafety(t *testing.T) {
	pool := NewFromPoolSlice([]string{})
	done := make(chan bool)
	
	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = pool.MaxQueryRetries()
			done <- true
		}()
	}
	
	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(val int) {
			pool.SetMaxQueryRetries(val)
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to finish
	for i := 0; i < 20; i++ {
		<-done
	}
}