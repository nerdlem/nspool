package nspool

import (
	"testing"
)

func TestHealthCheckWorkerCount(t *testing.T) {
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
			expected: 64, // default value from constructor
		},
		{
			name:     "custom value",
			pool:     NewFromPoolSlice([]string{}),
			value:    128,
			expected: 128,
		},
		{
			name:     "zero value",
			pool:     NewFromPoolSlice([]string{}),
			value:    0,
			expected: 0,
		},
		{
			name:     "negative value allowed",
			pool:     NewFromPoolSlice([]string{}),
			value:    -1,
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only set the value if this is not the default value test case
			if tt.name != "default value" {
				if tt.pool != nil {
					tt.pool.SetHealthCheckWorkerCount(tt.value)
				}
			}

			got := 0
			if tt.pool != nil {
				got = tt.pool.HealthCheckWorkerCount()
			}
			if got != tt.expected {
				t.Errorf("HealthCheckWorkerCount() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHealthCheckWorkerCountThreadSafety(t *testing.T) {
	pool := NewFromPoolSlice([]string{})
	done := make(chan bool)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = pool.HealthCheckWorkerCount()
			done <- true
		}()
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(val int) {
			pool.SetHealthCheckWorkerCount(val)
			done <- true
		}(i)
	}

	// Wait for all goroutines to finish
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestHealthCheckWorkerCountEffectOnRefresh(t *testing.T) {
	pool := NewFromPoolSlice([]string{"1.1.1.1", "8.8.8.8", "9.9.9.9"})
	pool.SetHealthDomainSuffix("example.com")

	// Test with different worker counts
	counts := []int{1, 2, len(pool.resolvers) + 1}

	for _, count := range counts {
		t.Run("worker_count_"+string(rune(count)), func(t *testing.T) {
			pool.SetHealthCheckWorkerCount(count)
			if got := pool.HealthCheckWorkerCount(); got != count {
				t.Errorf("HealthCheckWorkerCount() = %v, want %v", got, count)
			}

			// Verify Refresh still works
			err := pool.Refresh()
			if err != nil {
				t.Errorf("Refresh() with worker count %d failed: %v", count, err)
			}
		})
	}
}
