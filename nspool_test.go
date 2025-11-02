// Copyright (c) 2025 Luis E. Muñoz. All Rights Reserved.
// SPDX-License-Identifier: MIT

package nspool

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// mockDNSClient implements DnsClientLike for testing
type mockDNSClient struct {
	success     bool
	delay       time.Duration
	verifyQType func(uint16) bool // Optional function to verify query type
}

func (m *mockDNSClient) ExchangeContext(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	// Check if context is cancelled or has exceeded timeout
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) < m.delay {
			return nil, time.Since(start), fmt.Errorf("mock DNS timeout")
		}
	}

	select {
	case <-ctx.Done():
		return nil, time.Since(start), ctx.Err()
	default:
	}

	// Verify query type if verification function is set
	if m.verifyQType != nil && len(msg.Question) > 0 {
		if !m.verifyQType(msg.Question[0].Qtype) {
			return nil, time.Since(start), fmt.Errorf("incorrect query type: %d", msg.Question[0].Qtype)
		}
	}

	if m.delay > 0 {
		timer := time.NewTimer(m.delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, time.Since(start), ctx.Err()
		case <-timer.C:
		}
	}

	if !m.success {
		return nil, m.delay, fmt.Errorf("failed to query resolver")
	}

	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Rcode = dns.RcodeSuccess

	// Add a proper response record for health checks
	if len(msg.Question) > 0 {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   msg.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1"), // TEST-NET-1 address for testing
		}
		resp.Answer = append(resp.Answer, rr)
	}

	return resp, m.delay, nil
}

func (m *mockDNSClient) Exchange(msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	// Use default timeout of 2 seconds if not set via context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return m.ExchangeContext(ctx, msg, addr)
}

// newMockClient creates a new DNS client for testing
func newMockClient(success bool, delay time.Duration) DnsClientLike {
	return &mockDNSClient{
		success: success,
		delay:   delay,
	}
}

// newRandomMockClient creates a client that randomly succeeds or fails
func newRandomMockClient() DnsClientLike {
	return &mockDNSClient{
		success: rand.Float32() >= 0.5,
		delay:   time.Duration(10+rand.Intn(40)) * time.Millisecond,
	}
}

func TestDefaultHealthLabelGenerator(t *testing.T) {
	const samples = 10
	seen := make(map[string]struct{}, samples)

	for i := 0; i < samples; i++ {
		lbl := DefaultHealthLabelGenerator()

		if len(lbl) != 16 {
			t.Fatalf("label length = %d; want 16; label=%q", len(lbl), lbl)
		}

		if _, exists := seen[lbl]; exists {
			t.Fatalf("duplicate label generated: %q", lbl)
		}
		seen[lbl] = struct{}{}
	}
}

func TestNewFromPoolSlice(t *testing.T) {
	input := []string{"1.1.1.1:53", "8.8.8.8:53"}
	p := NewFromPoolSlice(input)

	if p == nil {
		t.Fatal("NewFromPoolSlice returned nil")
	}

	// Resolvers should be copied and equal
	got := p.resolvers.StringSlice()
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("resolvers = %v; want %v", got, input)
	}

	// Basic defaults
	if p.Client == nil {
		t.Fatal("Client should be non-nil")
	}
	if p.minResolvers != 1 {
		t.Fatalf("minResolvers = %d; want 1", p.minResolvers)
	}
	if p.maxQueryRetries != 3 {
		t.Fatalf("maxQueryRetries = %d; want 3", p.maxQueryRetries)
	}
	if p.queryTimeout != 10*time.Second {
		t.Fatalf("queryTimeout = %v; want 10s", p.queryTimeout)
	}
	if p.hcWpSize != 64 {
		t.Fatalf("hcWpSize = %d; want 64", p.hcWpSize)
	}
	if p.hcResolverTimeout != 10*time.Second {
		t.Fatalf("hcResolverTimeout = %v; want 10s", p.hcResolverTimeout)
	}
	if p.hcAutoRefreshInterval != 0 {
		t.Fatalf("hcAutoRefreshInterval = %v; want 0s", p.hcAutoRefreshInterval)
	}
}

func TestNewFromViper(t *testing.T) {
	t.Run("successful initialization", func(t *testing.T) {
		tag := "test.resolvers.tag"
		orig := []string{"9.9.9.9:53", "149.112.112.112:53"}
		viper.Set(tag, orig)

		p := NewFromViper(tag)
		if p == nil {
			t.Fatal("NewFromViper returned nil")
		}

		if p.viperResolversTag != tag {
			t.Fatalf("viperResolversTag = %q; want %q", p.viperResolversTag, tag)
		}

		got := p.resolvers.StringSlice()
		if !reflect.DeepEqual(got, orig) {
			t.Fatalf("resolvers = %v; want %v", got, orig)
		}

		if p.Client == nil {
			t.Fatal("Client should be non-nil")
		}

		// Spot check same defaults as other constructor
		if p.minResolvers != 1 {
			t.Fatalf("minResolvers = %d; want 1", p.minResolvers)
		}
		if p.queryTimeout != 10*time.Second {
			t.Fatalf("queryTimeout = %v; want 10s", p.queryTimeout)
		}
	})

	t.Run("handles viper unmarshal error", func(t *testing.T) {
		tag := "test.invalid.tag"
		// Clear any existing value and set an invalid type
		viper.Set(tag, map[string]interface{}{"invalid": true})

		p := NewFromViper(tag)
		if p == nil {
			t.Fatal("NewFromViper returned nil despite error")
		}

		// All slices should be empty but initialized
		if got := p.resolvers.StringSlice(); len(got) != 0 {
			t.Errorf("resolvers = %v; want empty slice", got)
		}

		if len(p.unavailableResolvers) != 0 {
			t.Errorf("unavailableResolvers = %v; want empty slice", p.unavailableResolvers)
		}

		// Other fields should still be properly initialized
		if p.Client == nil {
			t.Error("Client should be non-nil even after unmarshal error")
		}
		if p.hcHealthCheck == nil {
			t.Error("hcHealthCheck should be set to DefaultHealthCheckFunction")
		}
	})

	t.Run("handles empty tag", func(t *testing.T) {
		p := NewFromViper("")
		if p == nil {
			t.Fatal("NewFromViper returned nil for empty tag")
		}

		if p.resolvers != nil {
			t.Errorf("resolvers = %v; want nil for empty tag", p.resolvers)
		}

		if p.viperResolversTag != "" {
			t.Errorf("viperResolversTag = %q; want empty string", p.viperResolversTag)
		}
	})
}
func TestHealthDomainSuffixAccessors(t *testing.T) {
	p := NewFromPoolSlice([]string{"1.1.1.1:53"})

	// default should be empty
	if got := p.HealthDomainSuffix(); got != "" {
		t.Fatalf("default HealthDomainSuffix = %q; want empty", got)
	}

	// set and get
	suffix := "hc.example.invalid."
	p.SetHealthDomainSuffix(suffix)
	if got := p.HealthDomainSuffix(); got != suffix {
		t.Fatalf("HealthDomainSuffix = %q; want %q", got, suffix)
	}

	// set empty again
	p.SetHealthDomainSuffix("")
	if got := p.HealthDomainSuffix(); got != "" {
		t.Fatalf("HealthDomainSuffix after reset = %q; want empty", got)
	}
}

func TestHealthDomainSuffixFromViperPool(t *testing.T) {
	tag := "test.resolvers.tag.hc"
	orig := []string{"9.9.9.9:53"}
	viper.Set(tag, orig)

	p := NewFromViper(tag)
	if p == nil {
		t.Fatal("NewFromViper returned nil")
	}

	// default should be empty
	if got := p.HealthDomainSuffix(); got != "" {
		t.Fatalf("default HealthDomainSuffix = %q; want empty", got)
	}

	// set and verify does not affect other pools
	suffix := "viper-hc.example."
	p.SetHealthDomainSuffix(suffix)
	if got := p.HealthDomainSuffix(); got != suffix {
		t.Fatalf("HealthDomainSuffix = %q; want %q", got, suffix)
	}

	// create another pool and ensure it's independent
	p2 := NewFromPoolSlice([]string{"8.8.8.8:53"})
	if p2.HealthDomainSuffix() != "" {
		t.Fatalf("new pool HealthDomainSuffix = %q; want empty", p2.HealthDomainSuffix())
	}
}
func TestAvailableUnavailableCountsInitialAndAfterMove(t *testing.T) {
	input := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	p := NewFromPoolSlice(input)

	if got := p.AvailableCount(); got != 0 {
		t.Fatalf("AvailableCount = %d; want 0 (initial)", got)
	}
	if got := p.UnavailableCount(); got != len(input) {
		t.Fatalf("UnavailableCount = %d; want %d (initial)", got, len(input))
	}

	// Move one resolver from unavailable to available and verify counts update.
	p.mu.Lock()
	// take first unavailable and mark as available
	if len(p.unavailableResolvers) == 0 {
		p.mu.Unlock()
		t.Fatal("unexpected empty unavailableResolvers")
	}
	first := p.unavailableResolvers[0]
	p.unavailableResolvers = p.unavailableResolvers[1:]
	p.availableResolvers = append(p.availableResolvers, first)
	p.mu.Unlock()

	if got := p.AvailableCount(); got != 1 {
		t.Fatalf("AvailableCount after move = %d; want 1", got)
	}
	if got := p.UnavailableCount(); got != len(input)-1 {
		t.Fatalf("UnavailableCount after move = %d; want %d", got, len(input)-1)
	}
}

func TestCountsOnNilPool(t *testing.T) {
	var p *Pool = nil

	if got := p.AvailableCount(); got != 0 {
		t.Fatalf("AvailableCount on nil = %d; want 0", got)
	}
	if got := p.UnavailableCount(); got != 0 {
		t.Fatalf("UnavailableCount on nil = %d; want 0", got)
	}
}

func TestCountsConcurrentReaders(t *testing.T) {
	p := NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"})

	// set a known distribution: 2 available, 1 unavailable
	p.mu.Lock()
	p.availableResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	p.unavailableResolvers = []string{"9.9.9.9:53"}
	p.mu.Unlock()

	const readers = 200
	results := make(chan struct{ a, u int }, readers)

	for i := 0; i < readers; i++ {
		go func() {
			a := p.AvailableCount()
			u := p.UnavailableCount()
			results <- struct{ a, u int }{a, u}
		}()
	}

	for i := 0; i < readers; i++ {
		r := <-results
		if r.a != 2 {
			t.Fatalf("concurrent read: AvailableCount = %d; want 2", r.a)
		}
		if r.u != 1 {
			t.Fatalf("concurrent read: UnavailableCount = %d; want 1", r.u)
		}
	}
}
func TestRefresh(t *testing.T) {
	t.Run("nil pool returns error", func(t *testing.T) {
		var p *Pool = nil
		err := p.Refresh()
		if err != ErrNilPool {
			t.Fatalf("Refresh() error = %v; want %v", err, ErrNilPool)
		}
	})

	t.Run("nil dns client returns error", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.Client = nil // force nil client
		err := p.Refresh()
		if err != ErrNilDnsClient {
			t.Fatalf("Refresh() error = %v; want %v", err, ErrNilDnsClient)
		}
	})

	t.Run("nil health check function returns error", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.mu.Lock()
		p.hcHealthCheck = nil // force nil health check function
		p.mu.Unlock()
		err := p.Refresh()
		if err != ErrNilHealthCheck {
			t.Fatalf("Refresh() error = %v; want %v", err, ErrNilHealthCheck)
		}
	})

	t.Run("no health check suffix returns error and marks resolvers unavailable", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
		p := NewFromPoolSlice(resolvers)

		// ensure health check suffix is empty
		p.SetHealthDomainSuffix("")

		err := p.Refresh()
		if err != ErrNoHcSuffix {
			t.Fatalf("Refresh() error = %v; want %v", err, ErrNoHcSuffix)
		}

		// verify all resolvers are unavailable
		if got := p.AvailableCount(); got != 0 {
			t.Fatalf("AvailableCount = %d; want 0", got)
		}

		if got := p.UnavailableCount(); got != len(resolvers) {
			t.Fatalf("UnavailableCount = %d; want %d", got, len(resolvers))
		}

		// verify the unavailable resolvers are exactly our input resolvers
		p.mu.Lock()
		if !reflect.DeepEqual(p.unavailableResolvers, resolvers) {
			t.Fatalf("unavailableResolvers = %v; want %v", p.unavailableResolvers, resolvers)
		}
		p.mu.Unlock()
	})

	t.Run("working resolvers are marked available", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
		p := NewFromPoolSlice(resolvers)
		p.SetHealthDomainSuffix("hc.example.invalid.")

		// Replace the DNS client with our mock
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Run health check
		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v; want nil", err)
		}

		// All resolvers should be available
		if got := p.AvailableCount(); got != len(resolvers) {
			t.Fatalf("AvailableCount = %d; want %d", got, len(resolvers))
		}

		if got := p.UnavailableCount(); got != 0 {
			t.Fatalf("UnavailableCount = %d; want 0", got)
		}

		// Verify the available resolvers are exactly our input resolvers
		p.mu.Lock()
		if !reflect.DeepEqual(p.availableResolvers, resolvers) {
			t.Fatalf("availableResolvers = %v; want %v", p.availableResolvers, resolvers)
		}
		if len(p.unavailableResolvers) != 0 {
			t.Fatalf("unavailableResolvers = %v; want empty", p.unavailableResolvers)
		}
		p.mu.Unlock()
	})

	t.Run("failing resolvers are marked unavailable", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
		p := NewFromPoolSlice(resolvers)
		p.SetHealthDomainSuffix("hc.example.invalid.")

		// Replace the DNS client with our failing mock
		p.Client = newMockClient(false, time.Second)

		// Run health check
		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v; want nil", err)
		}

		// All resolvers should be unavailable
		if got := p.AvailableCount(); got != 0 {
			t.Fatalf("AvailableCount = %d; want 0", got)
		}

		if got := p.UnavailableCount(); got != len(resolvers) {
			t.Fatalf("UnavailableCount = %d; want %d", got, len(resolvers))
		}

		// Verify the unavailable resolvers are exactly our input resolvers
		p.mu.Lock()
		if !reflect.DeepEqual(p.unavailableResolvers, resolvers) {
			t.Fatalf("unavailableResolvers = %v; want %v", p.unavailableResolvers, resolvers)
		}
		if len(p.availableResolvers) != 0 {
			t.Fatalf("availableResolvers = %v; want empty", p.availableResolvers)
		}
		p.mu.Unlock()
	})

	t.Run("viper pool updates resolvers on refresh", func(t *testing.T) {
		// Setup initial resolvers in viper
		tag := "test.resolvers.refresh"
		initialResolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
		viper.Set(tag, initialResolvers)

		p := NewFromViper(tag)
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Initial state check
		got := p.resolvers.StringSlice()
		if !reflect.DeepEqual(got, initialResolvers) {
			t.Fatalf("initial resolvers = %v; want %v", got, initialResolvers)
		}

		// Update viper config
		updatedResolvers := []string{"9.9.9.9:53", "149.112.112.112:53"}
		viper.Set(tag, updatedResolvers)

		// Run refresh and verify resolvers are updated
		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}

		// Check that resolvers were updated from viper
		got = p.resolvers.StringSlice()
		if !reflect.DeepEqual(got, updatedResolvers) {
			t.Fatalf("after refresh resolvers = %v; want %v", got, updatedResolvers)
		}

		// All resolvers should be available (mock client returns success)
		if got := p.AvailableCount(); got != len(updatedResolvers) {
			t.Errorf("AvailableCount = %d; want %d", got, len(updatedResolvers))
		}

		// Verify available resolvers list matches updated config
		p.mu.Lock()
		if !reflect.DeepEqual(p.availableResolvers, updatedResolvers) {
			t.Errorf("availableResolvers = %v; want %v", p.availableResolvers, updatedResolvers)
		}
		p.mu.Unlock()
	})

	t.Run("non-viper pool preserves resolvers on refresh", func(t *testing.T) {
		originalResolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
		p := NewFromPoolSlice(originalResolvers)
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Set some viper config to ensure it doesn't affect non-viper pools
		viper.Set("test.resolvers.other", []string{"9.9.9.9:53"})

		// Run refresh
		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}

		// Verify resolvers list remains unchanged
		got := p.resolvers.StringSlice()
		if !reflect.DeepEqual(got, originalResolvers) {
			t.Fatalf("after refresh resolvers = %v; want %v", got, originalResolvers)
		}
	})

	t.Run("concurrent refreshes maintain mutex safety", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		p := NewFromPoolSlice(resolvers)
		p.SetHealthDomainSuffix("hc.example.invalid.")

		// Use a new random mock client for the test
		p.Client = newRandomMockClient()

		// Run concurrent refreshes
		const workers = 10
		var wg sync.WaitGroup
		wg.Add(workers)

		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				err := p.Refresh()
				if err != nil {
					t.Errorf("Refresh() error = %v", err)
				}
			}()
		}

		wg.Wait()

		// After all refreshes, check invariants
		p.mu.Lock()
		availLen := len(p.availableResolvers)
		unavailLen := len(p.unavailableResolvers)
		totalLen := availLen + unavailLen
		p.mu.Unlock()

		// Total count of resolvers should remain constant
		if totalLen != len(resolvers) {
			t.Fatalf("total resolvers = %d; want %d", totalLen, len(resolvers))
		}

		// Each resolver should appear exactly once (either available or unavailable)
		p.mu.Lock()
		seenResolvers := make(map[string]bool)
		for _, r := range p.availableResolvers {
			seenResolvers[r] = true
		}
		for _, r := range p.unavailableResolvers {
			if seenResolvers[r] {
				t.Errorf("resolver %q appears in both available and unavailable lists", r)
			}
			seenResolvers[r] = true
		}
		p.mu.Unlock()

		// Verify we saw each input resolver exactly once
		for _, r := range resolvers {
			if !seenResolvers[r] {
				t.Errorf("resolver %q not found in either available or unavailable lists", r)
			}
		}
	})
}

func TestHealthCheckQType(t *testing.T) {
	t.Run("defaults to TypeA", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		if got := p.HealthCheckQType(); got != dns.TypeA {
			t.Fatalf("default HealthCheckQType = %d; want %d (TypeA)", got, dns.TypeA)
		}
	})

	t.Run("returns TypeA for nil pool", func(t *testing.T) {
		var p *Pool = nil
		if got := p.HealthCheckQType(); got != dns.TypeA {
			t.Fatalf("nil pool HealthCheckQType = %d; want %d (TypeA)", got, dns.TypeA)
		}
	})

	t.Run("set and get", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		want := dns.TypeAAAA
		p.SetHealthCheckQType(want)
		if got := p.HealthCheckQType(); got != want {
			t.Fatalf("HealthCheckQType = %d; want %d", got, want)
		}
	})

	t.Run("concurrent set and get operations", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		const workers = 100
		var wg sync.WaitGroup
		wg.Add(workers)

		for i := 0; i < workers; i++ {
			go func(n int) {
				defer wg.Done()
				qtype := dns.TypeA
				if n%2 == 1 {
					qtype = dns.TypeAAAA
				}
				p.SetHealthCheckQType(qtype)
				got := p.HealthCheckQType()
				if got != dns.TypeA && got != dns.TypeAAAA {
					t.Errorf("unexpected qtype value: %d", got)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("nil pool set operation is safe", func(t *testing.T) {
		var p *Pool = nil
		// This should not panic
		p.SetHealthCheckQType(dns.TypeAAAA)
	})

	t.Run("affects health check queries", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.SetHealthCheckQType(dns.TypeAAAA)

		// Use a mock client that verifies query type
		mock := &mockDNSClient{
			success: true,
			delay:   10 * time.Millisecond,
			verifyQType: func(qtype uint16) bool {
				return qtype == dns.TypeAAAA
			},
		}
		p.Client = mock

		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v; want nil", err)
		}

		if got := p.AvailableCount(); got != 1 {
			t.Fatalf("AvailableCount = %d; want 1", got)
		}
	})
}

func TestRefreshNameServerTimeout(t *testing.T) {
	t.Run("sets positive timeout", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		want := 5 * time.Second
		p.RefreshNameServerTimeout(want)
		if p.hcResolverTimeout != want {
			t.Fatalf("hcResolverTimeout = %v; want %v", p.hcResolverTimeout, want)
		}
	})

	t.Run("ignores negative timeout", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		original := p.hcResolverTimeout
		p.RefreshNameServerTimeout(-1 * time.Second)
		if p.hcResolverTimeout != original {
			t.Fatalf("hcResolverTimeout = %v; want %v (unchanged)", p.hcResolverTimeout, original)
		}
	})

	t.Run("accepts zero timeout", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.RefreshNameServerTimeout(0)
		if p.hcResolverTimeout != 0 {
			t.Fatalf("hcResolverTimeout = %v; want 0", p.hcResolverTimeout)
		}
	})

	t.Run("updates affect health checks", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")

		// Use a mock client with a fixed delay
		delay := 100 * time.Millisecond
		p.Client = newMockClient(true, delay)

		// Set timeout less than delay (should fail)
		p.RefreshNameServerTimeout(delay / 2)
		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v; want nil", err)
		}
		if got := p.UnavailableCount(); got != 1 {
			t.Fatalf("UnavailableCount with short timeout = %d; want 1", got)
		}

		// Set timeout greater than delay (should succeed)
		p.RefreshNameServerTimeout(delay * 2)
		err = p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v; want nil", err)
		}
		if got := p.AvailableCount(); got != 1 {
			t.Fatalf("AvailableCount with longer timeout = %d; want 1", got)
		}
	})
}

func TestAutoRefresh(t *testing.T) {
	t.Run("nil pool operation is safe", func(t *testing.T) {
		var p *Pool = nil
		// Should not panic
		p.AutoRefresh(time.Second)
	})

	t.Run("handles nil logger gracefully", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(false, 10*time.Millisecond) // Will cause error
		p.SetLogger(nil)

		// Should not panic when Refresh errors without logger
		interval := 50 * time.Millisecond
		if interval <= 0 {
			t.Fatal("test interval must be positive")
		}
		p.AutoRefresh(interval)
		time.Sleep(100 * time.Millisecond)
		p.AutoRefresh(0) // Stop
	})

	t.Run("multiple stop operations are safe", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Start and immediately stop multiple times
		for i := 0; i < 3; i++ {
			p.AutoRefresh(50 * time.Millisecond)
			p.AutoRefresh(0)
		}

		// Double stop should be safe
		p.AutoRefresh(50 * time.Millisecond)
		p.AutoRefresh(0)
		p.AutoRefresh(0)
	})

	t.Run("disables and re-enables auto-refresh with different intervals", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Setup a logger to capture refresh calls
		buf := &bytes.Buffer{}
		logger := logrus.New()
		logger.SetOutput(buf)
		logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
		p.mu.Lock()
		p.logger = logger
		p.mu.Unlock()

		// Enable auto-refresh with 100ms interval
		p.AutoRefresh(100 * time.Millisecond)

		// Wait for at least one auto-refresh cycle
		time.Sleep(150 * time.Millisecond)

		// Disable auto-refresh
		p.AutoRefresh(0)

		// Wait briefly to ensure no more refreshes
		time.Sleep(150 * time.Millisecond)
		output1 := buf.String()
		buf.Reset()

		// Re-enable with shorter interval
		p.AutoRefresh(50 * time.Millisecond)

		// Wait for at least one more cycle
		time.Sleep(100 * time.Millisecond)
		output2 := buf.String()

		// Verify we got log output for both periods
		if !strings.Contains(output1, "health check refresh completed") {
			t.Errorf("Expected refresh logs in first period, got: %s", output1)
		}
		if !strings.Contains(output2, "health check refresh completed") {
			t.Errorf("Expected refresh logs in second period, got: %s", output2)
		}

		// Clean up
		p.AutoRefresh(0)
	})

	t.Run("handles refresh errors", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		// Don't set health domain suffix to trigger error

		buf := &bytes.Buffer{}
		logger := logrus.New()
		logger.SetOutput(buf)
		logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
		p.mu.Lock()
		p.logger = logger
		p.mu.Unlock()

		// Start auto-refresh with short interval
		p.AutoRefresh(50 * time.Millisecond)

		// Wait for error log
		time.Sleep(100 * time.Millisecond)

		// Disable auto-refresh
		p.AutoRefresh(0)

		// Verify error was logged
		if !strings.Contains(buf.String(), "health check failed") {
			t.Errorf("Expected error log, got: %s", buf.String())
		}
	})

	t.Run("immediately performs initial refresh", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Setup a logger to track the refresh
		buf := &bytes.Buffer{}
		logger := logrus.New()
		logger.SetOutput(buf)
		logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
		p.mu.Lock()
		p.logger = logger
		p.mu.Unlock()

		// Track time of enabling auto-refresh with long interval
		start := time.Now()
		p.AutoRefresh(1 * time.Hour) // Long interval but should refresh immediately

		// Give a small window for the initial refresh to complete
		deadline := time.Now().Add(50 * time.Millisecond)
		var count int
		for time.Now().Before(deadline) {
			count = p.AvailableCount()
			if count == 1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

		// Verify resolvers are available
		if count != 1 {
			t.Errorf("Expected 1 available resolver within 50ms, got %d", count)
		}

		// Verify refresh was logged
		if !strings.Contains(buf.String(), "health check refresh completed") {
			t.Error("Expected refresh completion log message")
		}

		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			t.Errorf("Initial refresh took too long: %v", elapsed)
		}

		// Cleanup
		p.AutoRefresh(0)
	})

	t.Run("honors refresh interval", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		buf := &bytes.Buffer{}
		logger := logrus.New()
		logger.SetOutput(buf)
		logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
		p.mu.Lock()
		p.logger = logger
		p.mu.Unlock()

		// Start auto-refresh with 100ms interval
		interval := 100 * time.Millisecond
		p.AutoRefresh(interval)

		// Clear initial output after first refresh
		time.Sleep(20 * time.Millisecond) // Wait for initial refresh
		buf.Reset()

		// Wait for initial refresh to complete
		time.Sleep(20 * time.Millisecond)

		// Now clear the buffer to ignore the initial refresh output
		buf.Reset()

		// Start timing our test window
		start := time.Now()

		// Wait for 2.5 intervals to ensure we catch 2 ticks
		waitTime := interval * 5 / 2 // 2.5 times the interval
		time.Sleep(waitTime)

		// Get output before stopping
		output := buf.String()

		// Stop auto-refresh and wait for goroutine to stop
		p.AutoRefresh(0)
		time.Sleep(20 * time.Millisecond)

		// Count refresh log entries
		refreshCount := strings.Count(output, "health check refresh completed")

		// We should see 2 periodic refreshes in our window
		// (not counting initial refresh which was cleared)
		if refreshCount < 2 {
			t.Errorf("Expected at least 2 refreshes in %v with %v interval, got %d. Output: %s",
				time.Since(start), interval, refreshCount, output)
		}
		if refreshCount > 3 {
			t.Errorf("Expected no more than 3 refreshes in %v with %v interval, got %d. Output: %s",
				time.Since(start), interval, refreshCount, output)
		}
	})

	t.Run("handles negative refresh interval", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Set negative interval (should effectively disable)
		p.AutoRefresh(-1 * time.Second)

		if p.hcAutoRefreshInterval != -1*time.Second {
			t.Errorf("hcAutoRefreshInterval = %v; want -1s", p.hcAutoRefreshInterval)
		}

		// Channel should be nil or closed
		if p.hcAutoRefreshChan != nil {
			select {
			case <-*p.hcAutoRefreshChan:
				// Channel is closed (good)
			default:
				t.Error("Auto-refresh channel should be closed for negative interval")
			}
		}
	})

	t.Run("restart with same interval is safe", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		// Start with interval
		interval := 100 * time.Millisecond
		p.AutoRefresh(interval)

		// Allow initial refresh to complete
		time.Sleep(20 * time.Millisecond)

		// Restart with same interval
		p.AutoRefresh(interval)
		time.Sleep(20 * time.Millisecond) // Allow new routine to start

		// Should still be working
		if p.hcAutoRefreshInterval != interval {
			t.Errorf("hcAutoRefreshInterval = %v; want %v", p.hcAutoRefreshInterval, interval)
		}

		p.AutoRefresh(0) // Cleanup
	})
}

func TestResolverListAccessors(t *testing.T) {
	t.Run("nil pool returns nil", func(t *testing.T) {
		var p *Pool = nil
		if got := p.AvailableResolvers(); got != nil {
			t.Errorf("AvailableResolvers() on nil pool = %v; want nil", got)
		}
		if got := p.UnavailableResolvers(); got != nil {
			t.Errorf("UnavailableResolvers() on nil pool = %v; want nil", got)
		}
	})

	t.Run("empty lists return nil", func(t *testing.T) {
		p := NewFromPoolSlice(nil)
		if got := p.AvailableResolvers(); got != nil {
			t.Errorf("AvailableResolvers() on empty pool = %v; want nil", got)
		}
		if got := p.UnavailableResolvers(); got != nil {
			t.Errorf("UnavailableResolvers() on empty pool = %v; want nil", got)
		}
	})

	t.Run("returns copy of lists", func(t *testing.T) {
		input := []string{"1.1.1.1:53", "8.8.8.8:53"}
		p := NewFromPoolSlice(input)

		// Setup known state
		p.mu.Lock()
		p.availableResolvers = []string{input[0]}
		p.unavailableResolvers = []string{input[1]}
		p.mu.Unlock()

		// Get copies
		avail := p.AvailableResolvers()
		unavail := p.UnavailableResolvers()

		// Verify contents
		if !reflect.DeepEqual(avail, []string{input[0]}) {
			t.Errorf("AvailableResolvers() = %v; want [%v]", avail, input[0])
		}
		if !reflect.DeepEqual(unavail, []string{input[1]}) {
			t.Errorf("UnavailableResolvers() = %v; want [%v]", unavail, input[1])
		}

		// Modify returned slices
		if len(avail) > 0 {
			avail[0] = "modified"
		}
		if len(unavail) > 0 {
			unavail[0] = "modified"
		}

		// Verify original lists are unchanged
		p.mu.Lock()
		if !reflect.DeepEqual(p.availableResolvers, []string{input[0]}) {
			t.Errorf("internal availableResolvers modified: got %v; want [%v]",
				p.availableResolvers, input[0])
		}
		if !reflect.DeepEqual(p.unavailableResolvers, []string{input[1]}) {
			t.Errorf("internal unavailableResolvers modified: got %v; want [%v]",
				p.unavailableResolvers, input[1])
		}
		p.mu.Unlock()
	})

	t.Run("concurrent access is safe", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		p := NewFromPoolSlice(resolvers)

		// Setup initial state
		p.mu.Lock()
		p.availableResolvers = []string{resolvers[0], resolvers[1]}
		p.unavailableResolvers = []string{resolvers[2]}
		p.mu.Unlock()

		const workers = 100
		var wg sync.WaitGroup
		wg.Add(workers)

		// Create worker goroutines that read and modify copies concurrently
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()

				// Get copies and modify them locally
				avail := p.AvailableResolvers()
				unavail := p.UnavailableResolvers()

				if len(avail) > 0 {
					avail[0] = "modified"
				}
				if len(unavail) > 0 {
					unavail[0] = "modified"
				}
			}()
		}

		wg.Wait()

		// Verify original lists are unchanged
		p.mu.Lock()
		if !reflect.DeepEqual(p.availableResolvers, []string{resolvers[0], resolvers[1]}) {
			t.Errorf("internal availableResolvers modified after concurrent access: got %v",
				p.availableResolvers)
		}
		if !reflect.DeepEqual(p.unavailableResolvers, []string{resolvers[2]}) {
			t.Errorf("internal unavailableResolvers modified after concurrent access: got %v",
				p.unavailableResolvers)
		}
		p.mu.Unlock()
	})

	t.Run("during refresh operation", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
		p := NewFromPoolSlice(resolvers)
		p.SetHealthDomainSuffix("hc.example.invalid.")

		// Setup a slow mock client
		p.Client = newMockClient(true, 100*time.Millisecond)

		// Start a refresh in the background
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Refresh()
		}()

		// While refresh is running, read resolver lists repeatedly
		timeout := time.After(200 * time.Millisecond)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

	loop:
		for {
			select {
			case <-timeout:
				break loop
			case <-ticker.C:
				avail := p.AvailableResolvers()
				unavail := p.UnavailableResolvers()

				// Verify total number of resolvers is constant
				total := len(avail) + len(unavail)
				if total != 0 && total != len(resolvers) {
					t.Errorf("invalid resolver count during refresh: available=%d + unavailable=%d != total=%d",
						len(avail), len(unavail), len(resolvers))
				}
			}
		}

		wg.Wait()
	})
}

func TestMinResolversAccessors(t *testing.T) {
	t.Run("nil pool operations", func(t *testing.T) {
		var p *Pool = nil
		if got := p.MinResolvers(); got != 0 {
			t.Errorf("MinResolvers() on nil pool = %d; want 0", got)
		}

		// Should not panic
		p.SetMinResolvers(5)
	})

	t.Run("default value", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		if got := p.MinResolvers(); got != 1 {
			t.Errorf("default MinResolvers() = %d; want 1", got)
		}
	})

	t.Run("set and get", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		want := 3
		p.SetMinResolvers(want)
		if got := p.MinResolvers(); got != want {
			t.Errorf("MinResolvers() = %d; want %d", got, want)
		}
	})

	t.Run("negative value treated as zero", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetMinResolvers(-5)
		if got := p.MinResolvers(); got != 0 {
			t.Errorf("MinResolvers() after negative = %d; want 0", got)
		}
	})

	t.Run("affects GetRandomResolver behavior", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})

		// Set up some available resolvers
		p.mu.Lock()
		p.availableResolvers = []string{"1.1.1.1:53"}
		p.mu.Unlock()

		// Test with min=1 (should succeed)
		p.SetMinResolvers(1)
		_, err := p.GetRandomResolver()
		if err != nil {
			t.Errorf("GetRandomResolver() with min=1, available=1: got error %v", err)
		}

		// Test with min=2 (should fail)
		p.SetMinResolvers(2)
		_, err = p.GetRandomResolver()
		if err != ErrInsufficientResolvers {
			t.Errorf("GetRandomResolver() with min=2, available=1: got error %v, want %v",
				err, ErrInsufficientResolvers)
		}
	})

	t.Run("concurrent access is safe", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		const workers = 100
		var wg sync.WaitGroup
		wg.Add(workers)

		// Create worker goroutines that read and write concurrently
		for i := 0; i < workers; i++ {
			go func(val int) {
				defer wg.Done()
				p.SetMinResolvers(val)
				_ = p.MinResolvers()
			}(i)
		}

		wg.Wait()

		// Verify we can still read and write after concurrent access
		p.SetMinResolvers(5)
		if got := p.MinResolvers(); got != 5 {
			t.Errorf("MinResolvers() after concurrent access = %d; want 5", got)
		}
	})
}

func TestGetRandomResolver(t *testing.T) {
	t.Run("nil pool returns error", func(t *testing.T) {
		var p *Pool = nil
		_, err := p.GetRandomResolver()
		if err != ErrNilPool {
			t.Fatalf("GetRandomResolver() error = %v; want %v", err, ErrNilPool)
		}
	})

	t.Run("insufficient resolvers returns error", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})
		p.mu.Lock()
		p.availableResolvers = []string{} // force empty
		p.mu.Unlock()

		_, err := p.GetRandomResolver()
		if err != ErrInsufficientResolvers {
			t.Fatalf("GetRandomResolver() error = %v; want %v", err, ErrInsufficientResolvers)
		}
	})

	t.Run("returns resolver when sufficient available", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		p := NewFromPoolSlice(resolvers)
		p.mu.Lock()
		p.availableResolvers = append([]string{}, resolvers...) // all available
		p.mu.Unlock()

		got, err := p.GetRandomResolver()
		if err != nil {
			t.Fatalf("GetRandomResolver() error = %v; want nil", err)
		}

		found := false
		for _, r := range resolvers {
			if got == r {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetRandomResolver() = %q; want one of %v", got, resolvers)
		}
	})

	t.Run("distribution is random", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		p := NewFromPoolSlice(resolvers)
		p.mu.Lock()
		p.availableResolvers = append([]string{}, resolvers...)
		p.mu.Unlock()

		// Track frequency of each resolver
		freq := make(map[string]int)
		const iterations = 1000
		for i := 0; i < iterations; i++ {
			r, err := p.GetRandomResolver()
			if err != nil {
				t.Fatalf("GetRandomResolver() error = %v; want nil", err)
			}
			freq[r]++
		}

		// Verify each resolver was selected and roughly evenly distributed
		for _, r := range resolvers {
			count := freq[r]
			if count == 0 {
				t.Errorf("Resolver %q was never selected", r)
			}
			// Expected ~333 selections per resolver (1000/3)
			// Allow significant variance but catch gross distribution errors
			if count < 200 || count > 500 {
				t.Errorf("Resolver %q selected %d times, outside acceptable range [200,500]", r, count)
			}
		}
	})

	t.Run("concurrent access is safe", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		p := NewFromPoolSlice(resolvers)
		p.mu.Lock()
		p.availableResolvers = append([]string{}, resolvers...)
		p.mu.Unlock()

		const workers = 100
		var wg sync.WaitGroup
		wg.Add(workers)
		errs := make(chan error, workers)

		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				_, err := p.GetRandomResolver()
				if err != nil {
					errs <- err
				}
			}()
		}

		wg.Wait()
		close(errs)

		for err := range errs {
			t.Errorf("Concurrent GetRandomResolver() error = %v", err)
		}
	})
}

func TestExchange(t *testing.T) {
	// Helper to create a test DNS message
	makeTestQuery := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		m.RecursionDesired = true
		return m
	}

	t.Run("nil pool returns error", func(t *testing.T) {
		var p *Pool = nil
		_, _, err := p.Exchange(makeTestQuery())
		if err != ErrNilPool {
			t.Errorf("Exchange() error = %v; want %v", err, ErrNilPool)
		}
	})

	t.Run("nil client returns error", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.Client = nil
		_, _, err := p.Exchange(makeTestQuery())
		if err != ErrNilDnsClient {
			t.Errorf("Exchange() error = %v; want %v", err, ErrNilDnsClient)
		}
	})

	t.Run("insufficient resolvers returns error", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.mu.Lock()
		p.minResolvers = 2
		p.availableResolvers = []string{"1.1.1.1:53"}
		p.mu.Unlock()

		_, _, err := p.Exchange(makeTestQuery())
		if err != ErrInsufficientResolvers {
			t.Errorf("Exchange() error = %v; want %v", err, ErrInsufficientResolvers)
		}
	})

	t.Run("successful query returns response", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53"}
		p := NewFromPoolSlice(resolvers)
		p.mu.Lock()
		p.availableResolvers = append([]string{}, resolvers...)
		p.Client = newMockClient(true, 10*time.Millisecond)
		p.mu.Unlock()

		resp, rtt, err := p.Exchange(makeTestQuery())
		if err != nil {
			t.Fatalf("Exchange() error = %v; want nil", err)
		}
		if resp == nil {
			t.Error("Exchange() response is nil")
		}
		if rtt <= 0 {
			t.Errorf("Exchange() rtt = %v; want > 0", rtt)
		}
	})

	t.Run("retry on failure", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
		p := NewFromPoolSlice(resolvers)
		p.mu.Lock()
		p.availableResolvers = append([]string{}, resolvers...)
		// Mock client that fails first time but succeeds second time
		failFirst := &mockDNSClient{
			success: false,
			delay:   10 * time.Millisecond,
		}
		p.Client = failFirst
		p.mu.Unlock()

		// First attempt should fail but second should succeed
		_, _, err := p.Exchange(makeTestQuery())
		if err == nil {
			t.Error("Exchange() expected error but got nil")
		}

		// Now make it succeed
		p.mu.Lock()
		p.Client = newMockClient(true, 10*time.Millisecond)
		p.mu.Unlock()

		resp2, _, err := p.Exchange(makeTestQuery())
		if err != nil {
			t.Errorf("Exchange() retry error = %v; want nil", err)
		}
		if resp2 == nil {
			t.Error("Exchange() retry response is nil")
		}
	})
}

func TestExchangeContext(t *testing.T) {
	// Helper to create a test DNS message
	makeTestQuery := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		m.RecursionDesired = true
		return m
	}

	t.Run("respects context cancellation", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53"}
		p := NewFromPoolSlice(resolvers)
		p.mu.Lock()
		p.availableResolvers = append([]string{}, resolvers...)
		p.Client = newMockClient(true, 100*time.Millisecond) // Slow client
		p.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, _, err := p.ExchangeContext(ctx, makeTestQuery())
		if err == nil {
			t.Error("ExchangeContext() expected timeout error but got nil")
		}
	})

	t.Run("nil pool returns error", func(t *testing.T) {
		var p *Pool = nil
		ctx := context.Background()
		_, _, err := p.ExchangeContext(ctx, makeTestQuery())
		if err != ErrNilPool {
			t.Errorf("ExchangeContext() error = %v; want %v", err, ErrNilPool)
		}
	})

	t.Run("nil client returns error", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.Client = nil
		ctx := context.Background()
		_, _, err := p.ExchangeContext(ctx, makeTestQuery())
		if err != ErrNilDnsClient {
			t.Errorf("ExchangeContext() error = %v; want %v", err, ErrNilDnsClient)
		}
	})

	t.Run("uses provided context", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53"}
		p := NewFromPoolSlice(resolvers)
		p.mu.Lock()
		p.availableResolvers = append([]string{}, resolvers...)
		p.Client = newMockClient(true, 10*time.Millisecond)
		p.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		resp, _, err := p.ExchangeContext(ctx, makeTestQuery())
		if err != nil {
			t.Fatalf("ExchangeContext() error = %v; want nil", err)
		}
		if resp == nil {
			t.Error("ExchangeContext() response is nil")
		}
	})

	t.Run("debug logging on failure", func(t *testing.T) {
		var resolver string
		if config, configErr := dns.ClientConfigFromFile("/etc/resolv.conf"); configErr != nil || len(config.Servers) == 0 {
			t.Skip("No system resolvers found:", configErr)
		} else {
			// Add port to the first nameserver
			resolver = config.Servers[0] + ":53"
		}

		p := NewFromPoolSlice([]string{resolver})
		p.mu.Lock()
		p.availableResolvers = append([]string{}, []string{resolver}...)

		// Use a mock client that will always fail with a specific error
		mockClient := &mockDNSClient{
			success: false,
			delay:   10 * time.Millisecond,
		}
		p.Client = mockClient
		// Force only one attempt
		p.maxQueryRetries = 0

		// Setup debug logging with a plain text formatter
		buf := &bytes.Buffer{}
		logger := logrus.New()
		logger.SetOutput(buf)
		logger.SetLevel(logrus.DebugLevel) // Enable debug logging!
		logger.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
			DisableColors:    true,
			QuoteEmptyFields: true,
		})
		p.logger = logger
		p.debug = true
		p.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, _, err := p.ExchangeContext(ctx, makeTestQuery())
		if err == nil {
			t.Error("ExchangeContext() expected error but got nil")
		}

		// Let's look at what we got
		output := buf.String()
		t.Logf("Log output: %q", output)

		logCount := strings.Count(output, "msg=\"querying resolver failed\"")
		if logCount != 1 {
			t.Errorf("expected exactly 1 failure message, got %d. Output: %q", logCount, output)
		}
		if !strings.Contains(output, "level=debug") {
			t.Errorf("missing debug level, got: %q", output)
		}
		resolverInOutput := false
		formattedResolver := fmt.Sprintf("resolver=\"%s\"", resolver)
		t.Logf("Looking for resolver format: %q", formattedResolver)
		if strings.Contains(output, formattedResolver) {
			resolverInOutput = true
		}
		if !resolverInOutput {
			t.Errorf("missing resolver info, got: %q, expected: %q", output, formattedResolver)
		}
	})
}

func TestDebugAccessors(t *testing.T) {
	t.Run("nil pool operations", func(t *testing.T) {
		var p *Pool = nil
		if got := p.Debug(); got != false {
			t.Errorf("Debug() on nil pool = %v; want false", got)
		}

		// Ensure calling SetDebug on nil pool is safe
		p.SetDebug(true)
		if got := p.Debug(); got != false {
			t.Errorf("Debug() on nil pool after SetDebug = %v; want false", got)
		}
	})

	t.Run("initial value is false", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		if got := p.Debug(); got != false {
			t.Errorf("initial Debug() = %v; want false", got)
		}
	})

	t.Run("set and get debug flag", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		logger := logrus.New()
		logger.SetLevel(logrus.InfoLevel) // Start at info level
		p.SetLogger(logger)

		// Enable debug - should only change internal flag
		p.SetDebug(true)
		if got := p.Debug(); got != true {
			t.Errorf("Debug() after setting true = %v; want true", got)
		}

		// Logger level should remain unchanged
		if logger.GetLevel() != logrus.InfoLevel {
			t.Errorf("logger level changed = %v; should remain at InfoLevel", logger.GetLevel())
		}

		// Disable debug - should only change internal flag
		p.SetDebug(false)
		if got := p.Debug(); got != false {
			t.Errorf("Debug() after setting false = %v; want false", got)
		}
		if logger.GetLevel() != logrus.InfoLevel {
			t.Errorf("logger level changed = %v; should remain at InfoLevel", logger.GetLevel())
		}
	})

	t.Run("set with nil logger", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetLogger(nil)
		p.SetDebug(true)
		if got := p.Debug(); got != true {
			t.Errorf("Debug() after setting true with nil logger = %v; want true", got)
		}
	})

	t.Run("concurrent debug and logger operations", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		logger := logrus.New()
		p.SetLogger(logger)

		// Run concurrent debug operations
		const ops = 100
		done := make(chan bool, ops)
		for i := 0; i < ops; i++ {
			go func(n int) {
				p.SetDebug(n%2 == 0)
				_ = p.Debug()
				done <- true
			}(i)
		}

		// Wait for all operations
		for i := 0; i < ops; i++ {
			<-done
		}

		// Verify we can still set and get debug state
		p.SetDebug(true)
		if !p.Debug() {
			t.Error("Debug state not properly set after concurrent operations")
		}
	})
}

func TestLastRefreshedAccessors(t *testing.T) {
	t.Run("nil pool returns zero time", func(t *testing.T) {
		var p *Pool = nil
		if got := p.LastRefreshed(); !got.IsZero() {
			t.Errorf("LastRefreshed() on nil pool = %v; want zero time", got)
		}
	})

	t.Run("initial value is zero time", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		if got := p.LastRefreshed(); !got.IsZero() {
			t.Errorf("initial LastRefreshed() = %v; want zero time", got)
		}
	})

	t.Run("updates after refresh", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		before := p.LastRefreshed()
		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}

		after := p.LastRefreshed()
		if after.IsZero() {
			t.Error("LastRefreshed() still zero after refresh")
		}
		if !after.After(before) {
			t.Errorf("LastRefreshed() = %v is not after %v", after, before)
		}
	})
}

func TestHealthCheckFunctionAccessors(t *testing.T) {
	t.Run("nil pool operations", func(t *testing.T) {
		var p *Pool = nil
		if got := p.HealthCheckFunction(); got != nil {
			t.Errorf("HealthCheckFunction() on nil pool = %v; want nil", got)
		}
		// Should not panic
		p.SetHealthCheckFunction(nil)
	})

	t.Run("defaults to DefaultHealthCheckFunction", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		got := p.HealthCheckFunction()
		if reflect.ValueOf(got).Pointer() != reflect.ValueOf(DefaultHealthCheckFunction).Pointer() {
			t.Error("HealthCheckFunction() did not return DefaultHealthCheckFunction")
		}
	})

	t.Run("set nil restores default", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		custom := func(ans dns.Msg, t time.Duration, p *Pool) bool { return true }
		p.SetHealthCheckFunction(custom)
		p.SetHealthCheckFunction(nil) // Should restore default

		got := p.HealthCheckFunction()
		if reflect.ValueOf(got).Pointer() != reflect.ValueOf(DefaultHealthCheckFunction).Pointer() {
			t.Error("setting nil did not restore DefaultHealthCheckFunction")
		}
	})

	t.Run("custom function is used in Refresh", func(t *testing.T) {
		resolvers := []string{"1.1.1.1:53"}
		p := NewFromPoolSlice(resolvers)
		p.SetHealthDomainSuffix("hc.example.invalid.")
		p.Client = newMockClient(true, 10*time.Millisecond)

		customCalled := false
		custom := func(ans dns.Msg, t time.Duration, pool *Pool) bool {
			customCalled = true
			return true
		}
		p.SetHealthCheckFunction(custom)

		err := p.Refresh()
		if err != nil {
			t.Fatalf("Refresh() error = %v; want nil", err)
		}

		if !customCalled {
			t.Error("custom health check function was not called during Refresh")
		}

		if got := p.AvailableCount(); got != 1 {
			t.Errorf("AvailableCount = %d; want 1 (custom function returned true)", got)
		}
	})

	t.Run("concurrent access is safe", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		const workers = 100
		var wg sync.WaitGroup
		wg.Add(workers)

		custom1 := func(ans dns.Msg, t time.Duration, p *Pool) bool { return true }
		custom2 := func(ans dns.Msg, t time.Duration, p *Pool) bool { return false }

		for i := 0; i < workers; i++ {
			go func(n int) {
				defer wg.Done()
				if n%2 == 0 {
					p.SetHealthCheckFunction(custom1)
				} else {
					p.SetHealthCheckFunction(custom2)
				}
				_ = p.HealthCheckFunction()
			}(i)
		}

		wg.Wait()

		// Verify we can still set and get after concurrent access
		p.SetHealthCheckFunction(custom1)
		got := p.HealthCheckFunction()
		if reflect.ValueOf(got).Pointer() != reflect.ValueOf(custom1).Pointer() {
			t.Error("HealthCheckFunction not properly set after concurrent access")
		}
	})
}

func TestLoggerAccessors(t *testing.T) {
	t.Run("nil pool operations", func(t *testing.T) {
		var p *Pool = nil
		if got := p.Logger(); got != nil {
			t.Errorf("Logger() on nil pool = %v; want nil", got)
		}
		// Should not panic
		p.SetLogger(logrus.New())
	})

	t.Run("set and get logger", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})

		// Initially nil
		if got := p.Logger(); got != nil {
			t.Errorf("initial Logger() = %v; want nil", got)
		}

		// Set and verify
		logger := logrus.New()
		p.SetLogger(logger)
		if got := p.Logger(); got != logger {
			t.Errorf("Logger() after set = %v; want %v", got, logger)
		}

		// Set nil and verify
		p.SetLogger(nil)
		if got := p.Logger(); got != nil {
			t.Errorf("Logger() after set nil = %v; want nil", got)
		}
	})

	t.Run("concurrent access is safe", func(t *testing.T) {
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		logger := logrus.New()

		const workers = 100
		var wg sync.WaitGroup
		wg.Add(workers)

		for i := 0; i < workers; i++ {
			go func(n int) {
				defer wg.Done()
				if n%2 == 0 {
					p.SetLogger(logger)
				} else {
					p.SetLogger(nil)
				}
				_ = p.Logger()
			}(i)
		}

		wg.Wait()

		// Verify we can still set and get after concurrent access
		p.SetLogger(logger)
		if got := p.Logger(); got != logger {
			t.Errorf("Logger() after concurrent access = %v; want %v", got, logger)
		}
	})
}

func TestDefaultHealthCheckFunction(t *testing.T) {
	t.Run("success returns true", func(t *testing.T) {
		msg := dns.Msg{}
		msg.Rcode = dns.RcodeSuccess
		// p may be nil for success path because function only references p on failure.
		ok := DefaultHealthCheckFunction(msg, 10*time.Millisecond, nil)
		if !ok {
			t.Fatalf("expected true for success rcode")
		}
	})

	t.Run("non-success without debug returns false", func(t *testing.T) {
		msg := dns.Msg{}
		msg.Rcode = dns.RcodeNameError
		msg.Question = []dns.Question{{Name: "test.", Qclass: dns.ClassINET, Qtype: dns.TypeA}}
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})
		// ensure debug disabled and no logger
		p.SetDebug(false)
		p.mu.Lock()
		p.logger = nil
		p.mu.Unlock()

		ok := DefaultHealthCheckFunction(msg, 1*time.Second, p)
		if ok {
			t.Fatalf("expected false for non-success")
		}
	})

	t.Run("non-success with debug and logger logs and returns false", func(t *testing.T) {
		msg := dns.Msg{}
		msg.Rcode = dns.RcodeNotImplemented
		msg.Question = []dns.Question{{Name: "example.invalid.", Qclass: dns.ClassINET, Qtype: dns.TypeA}}
		p := NewFromPoolSlice([]string{"8.8.4.4:53"})

		buf := &bytes.Buffer{}
		logger := logrus.New()
		logger.SetOutput(buf)
		logger.SetLevel(logrus.DebugLevel)
		logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

		p.SetDebug(true)
		p.mu.Lock()
		p.logger = logger
		p.mu.Unlock()

		ok := DefaultHealthCheckFunction(msg, 2*time.Millisecond, p)
		if ok {
			t.Fatalf("expected false for non-success with logger")
		}
		out := buf.String()
		if !strings.Contains(out, "response was not ok") && !strings.Contains(out, "😵 response was not ok") {
			t.Fatalf("expected log message in output; got %q", out)
		}
		if !strings.Contains(out, "example.invalid.") {
			t.Fatalf("expected query name in log; got %q", out)
		}
	})

	t.Run("non-success unknown rcode falls back to numeric string", func(t *testing.T) {
		msg := dns.Msg{}
		msg.Rcode = 999
		msg.Question = []dns.Question{{Name: "unknown.example.", Qclass: dns.ClassINET, Qtype: dns.TypeA}}
		p := NewFromPoolSlice([]string{"1.1.1.1:53"})

		buf := &bytes.Buffer{}
		logger := logrus.New()
		logger.SetOutput(buf)
		logger.SetLevel(logrus.DebugLevel)
		logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

		p.SetDebug(true)
		p.mu.Lock()
		p.logger = logger
		p.mu.Unlock()

		ok := DefaultHealthCheckFunction(msg, 3*time.Millisecond, p)
		if ok {
			t.Fatalf("expected false for unknown rcode")
		}
		out := buf.String()
		if !strings.Contains(out, "999") {
			t.Fatalf("expected numeric rcode in log; got %q", out)
		}
	})
}
