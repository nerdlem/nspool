// Copyright (c) 2025 Luis E. Muñoz. All Rights Reserved.
// SPDX-License-Identifier: MIT

package nspool_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/nerdlem/nspool/v2"
	"github.com/sirupsen/logrus"
)

// Example demonstrates basic usage of nspool with a resolver pool.
func Example() {
	// Create pool with resolver addresses
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})

	// Configure health checking
	nsp.SetHealthDomainSuffix("example.com")
	nsp.SetMinResolvers(1)

	// Perform initial health check
	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion("github.com.", dns.TypeA)

	// Query using the pool
	response, _, err := nsp.Exchange(msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Received %d answers\n", len(response.Answer))
}

// ExampleNewFromPoolSlice demonstrates creating a pool with explicit resolver addresses.
func ExampleNewFromPoolSlice() {
	// Create pool with specific resolvers
	nsp := nspool.NewFromPoolSlice([]string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
	})

	// Configure health checking
	nsp.SetHealthDomainSuffix("example.com")

	// Perform health check
	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Available resolvers: %d\n", nsp.AvailableCount())
}

// ExamplePool_SetHealthCheckFunction demonstrates using a custom health check function.
func ExamplePool_SetHealthCheckFunction() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// Custom health check that validates response content
	customCheck := func(ans dns.Msg, t time.Duration, resolver string, p *nspool.Pool) bool {
		// Must respond within 2 seconds
		if t > 2*time.Second {
			return false
		}

		// Must have NOERROR response
		if ans.Rcode != dns.RcodeSuccess {
			return false
		}

		// Must have at least one answer
		if len(ans.Answer) == 0 {
			return false
		}

		return true
	}

	nsp.SetHealthCheckFunction(customCheck)

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Healthy resolvers: %d\n", nsp.AvailableCount())
}

// ExamplePool_SetRefreshPreHook demonstrates using a pre-refresh hook for logging.
func ExamplePool_SetRefreshPreHook() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// Log before refresh
	nsp.SetRefreshPreHook(func(p *nspool.Pool) bool {
		log.Printf("Starting refresh with %d resolvers",
			p.AvailableCount()+p.UnavailableCount())
		return true
	})

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}
}

// ExamplePool_SetRefreshPostHook demonstrates using a post-refresh hook for logging.
func ExamplePool_SetRefreshPostHook() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// Log after refresh
	nsp.SetRefreshPostHook(func(p *nspool.Pool) {
		log.Printf("Refresh complete: %d available, %d unavailable",
			p.AvailableCount(), p.UnavailableCount())
	})

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}
}

// ExamplePool_SetRefreshPreHook_conditional demonstrates conditional refresh using pre-hook.
func ExamplePool_SetRefreshPreHook_conditional() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// Only allow refresh during off-peak hours
	nsp.SetRefreshPreHook(func(p *nspool.Pool) bool {
		hour := time.Now().Hour()
		if hour >= 8 && hour <= 18 {
			log.Println("Skipping refresh during peak hours")
			return false
		}
		return true
	})

	err := nsp.Refresh()
	if err == nspool.ErrRefreshAbortedByPreHook {
		log.Println("Refresh was skipped by policy")
	}
}

// ExamplePool_AutoRefresh demonstrates automatic periodic health checking.
func ExamplePool_AutoRefresh() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// Perform initial refresh
	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	// Start auto-refresh every 5 minutes
	nsp.AutoRefresh(5 * time.Minute)

	// Stop auto-refresh when done
	defer nsp.AutoRefresh(0)

	// Use the pool for queries...
	fmt.Println("Auto-refresh enabled")
}

// ExamplePool_ExchangeContext demonstrates DNS queries with context timeout.
func ExamplePool_ExchangeContext() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53"})
	nsp.SetHealthDomainSuffix("example.com")

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion("github.com.", dns.TypeA)

	// Query with context
	response, rtt, err := nsp.ExchangeContext(ctx, msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Query completed in %v with %d answers\n", rtt, len(response.Answer))
}

// ExamplePool_SetLogger demonstrates enabling logging with logrus.
func ExamplePool_SetLogger() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// Create and configure logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Enable logging
	nsp.SetLogger(logger)
	nsp.SetDebug(true)

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Logging enabled")
}

// ExamplePool_SetMaxQueryRetries demonstrates configuring query retry behavior.
func ExamplePool_SetMaxQueryRetries() {
	nsp := nspool.NewFromPoolSlice([]string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
	})
	nsp.SetHealthDomainSuffix("example.com")

	// Set maximum retries to 5 (up to 6 total attempts)
	nsp.SetMaxQueryRetries(5)

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Max retries set to %d\n", nsp.MaxQueryRetries())
}

// ExamplePool_GetRandomResolver demonstrates getting a resolver address directly.
func ExamplePool_GetRandomResolver() {
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})
	nsp.SetHealthDomainSuffix("example.com")

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	// Get a random resolver
	resolver, err := nsp.GetRandomResolver()
	if err != nil {
		log.Fatal(err)
	}

	// Use it directly with dns.Client
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("github.com.", dns.TypeA)

	response, _, err := client.Exchange(msg, resolver)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Query via %s returned %d answers\n", resolver, len(response.Answer))
}

// ExamplePool_SetHealthCheckWorkerCount demonstrates configuring health check concurrency.
func ExamplePool_SetHealthCheckWorkerCount() {
	nsp := nspool.NewFromPoolSlice([]string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
	})
	nsp.SetHealthDomainSuffix("example.com")

	// Use 10 workers for health checks
	nsp.SetHealthCheckWorkerCount(10)

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Health checks use %d workers\n", nsp.HealthCheckWorkerCount())
}

// ExampleDefaultHealthCheckFunction demonstrates the default health check behavior.
func ExampleDefaultHealthCheckFunction() {
	// Create a pool
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// The default health check function is used automatically
	// It simply verifies the response has RCODE = NOERROR

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Using default health check")
}

// ExampleDefaultRefreshPreHook demonstrates the default pre-hook behavior.
func ExampleDefaultRefreshPreHook() {
	// The default pre-hook always returns true (allows refresh)
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// You can explicitly set it if desired
	nsp.SetRefreshPreHook(nspool.DefaultRefreshPreHook)

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Using default pre-hook")
}

// ExampleDefaultRefreshPostHook demonstrates the default post-hook behavior.
func ExampleDefaultRefreshPostHook() {
	// The default post-hook is a no-op
	nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53"})
	nsp.SetHealthDomainSuffix("example.com")

	// You can explicitly set it if desired
	nsp.SetRefreshPostHook(nspool.DefaultRefreshPostHook)

	if err := nsp.Refresh(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Using default post-hook")
}
