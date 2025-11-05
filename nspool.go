// Copyright (c) 2025 Luis E. Muñoz. All Rights Reserved.
// SPDX-License-Identifier: MIT

package nspool

// Package nspool manages a pool of upstream DNS resolvers and the health-check
// machinery that keeps track of which resolvers are usable. It provides a
// configurable framework to probe resolvers with DNS queries, evaluate their
// responses, and maintain an available set for query selection and retry logic.
//
// The package is intended to be used by DNS client code that needs to rely on
// multiple upstream resolvers and wants automatic failover and health
// monitoring. Typical responsibilities of this package include:
//
//   - storing configured resolver addresses,
//   - performing periodic health checks using customizable query names and
//     evaluation logic,
//   - maintaining an available-resolver list for serving queries,
//   - providing concurrency-safe operations for selection and configuration.
//
// Usage overview:
//   1. Construct a Pool via the package constructor. All resolvers start as available.
//   2. Configure health check behaviour (label generator, suffixes, timeouts,
//      check interval, worker pool size) and logging as needed.
//   3. Optionally call Refresh() to validate resolver health, or start background
//      health checking with AutoRefresh().
//   4. Use Pool methods to select resolvers and perform queries, relying on
//      the pool's retry and selection semantics.
//

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/gammazero/workerpool"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	// ErrNilPool is returned when methods are invoked against a nil Pool.
	ErrNilPool = fmt.Errorf("nil pool")
	// ErrNilDnsClient is returned when the internal DNS Client is nil.
	ErrNilDnsClient = fmt.Errorf("nil dns client")
	// ErrNoHcSuffix is returned whenever a health check is required and
	// there is no HealthDomainSuffix() set.
	ErrNoHcSuffix = fmt.Errorf("health check domain suffix not set")
	// ErrInsufficientResolvers is returned when there are not enough available resolvers
	// to satisfy the minimum resolver requirement.
	ErrInsufficientResolvers = fmt.Errorf("insufficient available resolvers")
	// ErrNilHealthCheck is returned when Refresh() is called and the health check
	// function is nil.
	ErrNilHealthCheck = fmt.Errorf("nil health check function")
	// ErrRefreshAbortedByPreHook is returned when the pre-refresh hook returns false,
	// preventing the refresh operation from proceeding.
	ErrRefreshAbortedByPreHook = fmt.Errorf("refresh aborted by pre-hook")
)

// HealthLabelGenerator is the signature for a function that generates the label
// used for resolver health checks. It must return a string that will be used to
// construct the name that will be queried on each candidate resolver during
// health checks.
type HealthLabelGenerator func() string

// HealthCheckFunction is the signature for the function that powers resolver health
// check. It receives the DNS response to the health check query, the time it took
// to get the answer and a pointer to the nspool that is running the health check.
// It must return true to indicate a healthy, usable resolver. False marks the
//
//	resolver as unavailable for use.
type HealthCheckFunction func(dns.Msg, time.Duration, *Pool) bool

// RefreshPreHook is the signature for a function called before Refresh() starts.
// It receives a pointer to the Pool being refreshed and must return a boolean.
// If it returns false, the Refresh() operation is aborted and Refresh() returns
// an error. This hook can be used to implement conditions under which refresh
// should not proceed, or to log/track refresh attempts.
type RefreshPreHook func(*Pool) bool

// RefreshPostHook is the signature for a function called after Refresh() completes.
// It receives a pointer to the Pool that was just refreshed. This hook has no
// return value and is called regardless of whether the refresh succeeded or failed.
// It can be used to log results, update metrics, or trigger other actions based
// on the refresh outcome.
type RefreshPostHook func(*Pool)

// DnsClientLike is an interface that should accept dns.Client. This is used to
// facilitate testing and allowing easier overriding to support special use cases.
type DnsClientLike interface {
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

// Pool represents a new nspool object.
type Pool struct {
	availableResolvers    []string
	debug                 bool
	hcAutoRefreshChan     *chan bool
	hcAutoRefreshInterval time.Duration
	hcDomainSuffix        string
	hcNameGenerator       HealthLabelGenerator
	hcHealthCheck         HealthCheckFunction
	hcResolverTimeout     time.Duration
	hcQType               uint16
	hcWpSize              int
	lastRefreshed         time.Time
	logger                *logrus.Logger
	maxQueryRetries       int
	minResolvers          int
	mu                    sync.Mutex
	muRefresh             sync.Mutex
	queryTimeout          time.Duration
	refreshPreHook        RefreshPreHook
	refreshPostHook       RefreshPostHook
	resolvers             FileArray
	unavailableResolvers  []string
	viperResolversTag     string
	// Client is a pointer to the dns.Client that will be used for sending all queries.
	// This value is automatically set by the constructors to a vainilla dns.Client
	// object. It is exposed to allow the caller to further customize behavior.
	// Setting this value to nil will cause all operations to return an error.
	Client DnsClientLike
}

// DefaultHealthLabelGenerator is the dafault function to generate labels used
// for resolver health checking. It returns a 16 character ASCII label made up of
// random characters from a restricted alphabet built into the function. The result
// of this function will be concatenated with the default suffix to generate the
// final FQDNs that will be used to test the resolvers.
func DefaultHealthLabelGenerator() string {
	ret := ""
	alphabet := "0123456789abcdefghijklmnopqrstuvwyz"
	for i := 0; i < 16; i++ {
		ret = ret + string(alphabet[rand.Intn(len(alphabet))])
	}

	return ret
}

// DefaultHealthCheckFunction provides default health check behaviour, which simply
// verifies tha the response indicated success. If the debug attribute is enabled
// and a logger has been provided, it will log data about the response.
func DefaultHealthCheckFunction(ans dns.Msg, t time.Duration, p *Pool) bool {
	if ans.Rcode != dns.RcodeSuccess {
		if p.debug && p.logger != nil {
			rcode, ok := dns.RcodeToString[ans.Rcode]
			if !ok {
				rcode = fmt.Sprintf("%d", ans.Rcode)
			}
			p.logger.WithFields(logrus.Fields{
				"query": ans.Question[0].Name,
				"class": ans.Question[0].Qclass,
				"type":  ans.Question[0].Qtype,
				"rcode": rcode,
				"time":  t.String(),
			}).Debug("😵 response was not ok")
		}
		return false
	}
	return true
}

// DefaultRefreshPreHook is the default pre-refresh hook that always allows
// the refresh to proceed. This function serves as an example and documentation
// for implementing custom pre-refresh hooks.
//
// Example usage:
//
//	nsp.SetRefreshPreHook(func(p *nspool.Pool) bool {
//	    // Only allow refresh during off-peak hours
//	    hour := time.Now().Hour()
//	    return hour < 8 || hour > 18
//	})
func DefaultRefreshPreHook(p *Pool) bool {
	return true
}

// DefaultRefreshPostHook is the default post-refresh hook that does nothing.
// This function serves as an example and documentation for implementing custom
// post-refresh hooks.
//
// Example usage:
//
//	nsp.SetRefreshPostHook(func(p *nspool.Pool) {
//	    log.Printf("Refresh complete: %d available, %d unavailable",
//	        p.AvailableCount(), p.UnavailableCount())
//	})
func DefaultRefreshPostHook(p *Pool) {
	// No-op by default
}

// NewFromPoolSlice returns a newly configured Pool primed with the resolvers
// explicitly provided in the call. All resolvers are initially marked as available.
// Use Refresh() to validate resolver health if needed.
func NewFromPoolSlice(res []string) *Pool {
	np := Pool{
		Client:                new(dns.Client),
		hcAutoRefreshInterval: 0 * time.Second,
		hcNameGenerator:       DefaultHealthLabelGenerator,
		hcHealthCheck:         DefaultHealthCheckFunction,
		hcQType:               dns.TypeA,
		hcResolverTimeout:     10 * time.Second,
		hcWpSize:              64,
		maxQueryRetries:       3,
		minResolvers:          1,
		queryTimeout:          10 * time.Second,
		resolvers:             FileArray(res),
		availableResolvers:    append([]string{}, res...),
	}
	return &np
}

// NewFromViper returns a newly configured Pool primed with the resolvers
// from viper using the provided tag. If the value in viper starts with '@',
// it will be treated as a file reference and the resolvers will be read from
// that file. All resolvers are initially marked as available.
// Use Refresh() to validate resolver health if needed.
func NewFromViper(tag string) *Pool {
	var resolvers FileArray
	err := viper.UnmarshalKey(tag, &resolvers)
	if err != nil {
		resolvers = nil
	}

	np := Pool{
		Client:                new(dns.Client),
		hcAutoRefreshInterval: 0 * time.Second,
		hcNameGenerator:       DefaultHealthLabelGenerator,
		hcHealthCheck:         DefaultHealthCheckFunction,
		hcQType:               dns.TypeA,
		hcResolverTimeout:     10 * time.Second,
		hcWpSize:              64,
		maxQueryRetries:       3,
		minResolvers:          1,
		queryTimeout:          10 * time.Second,
		resolvers:             resolvers,
		availableResolvers:    append([]string{}, resolvers.StringSlice()...),
		viperResolversTag:     tag,
	}
	return &np
}

// HealthDomainSuffix returns the currently configured health-check
// domain suffix.
func (p *Pool) HealthDomainSuffix() string {
	return p.hcDomainSuffix
}

// SetHealthDomainSuffix sets the health-check domain suffix.
// You must initialize the health-check domain suffix in order for
// automatic health-check to work. Calling Refresh() without this step
// will result in simply marking all resolvers as unavailable.
func (p *Pool) SetHealthDomainSuffix(suffix string) {
	p.hcDomainSuffix = suffix
}

// AvailableCount returns the number of currently available resolvers.
func (p *Pool) AvailableCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.availableResolvers)
}

// UnavailableCount returns the number of currently unavailable resolvers.
func (p *Pool) UnavailableCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.unavailableResolvers)
}

// Debug returns the current value of the debug flag.
func (p *Pool) Debug() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.debug
}

// SetDebug sets the debug flag for internal module debug logging.
func (p *Pool) SetDebug(enabled bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.debug = enabled
}

// SetLogger sets the logger to be used for debug and error messages.
// Pass nil to disable logging.
func (p *Pool) SetLogger(l *logrus.Logger) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logger = l
}

// Logger returns the current logger used by the pool.
// Returns nil if no logger is set or if the pool is nil.
func (p *Pool) Logger() *logrus.Logger {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logger
}

// SetHealthCheckFunction sets the function that will be used to evaluate resolver
// health during refresh operations. If nil is provided, the default health check
// function will be used.
func (p *Pool) SetHealthCheckFunction(fn HealthCheckFunction) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if fn == nil {
		p.hcHealthCheck = DefaultHealthCheckFunction
	} else {
		p.hcHealthCheck = fn
	}
}

// HealthCheckFunction returns the current function used to evaluate resolver health.
// Returns nil if the pool is nil.
func (p *Pool) HealthCheckFunction() HealthCheckFunction {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hcHealthCheck
}

// SetRefreshPreHook sets the function that will be called before each Refresh()
// operation. If the hook returns false, the refresh will be aborted and Refresh()
// will return ErrRefreshAbortedByPreHook. Pass nil to disable the pre-hook.
func (p *Pool) SetRefreshPreHook(fn RefreshPreHook) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshPreHook = fn
}

// RefreshPreHook returns the current pre-refresh hook function.
// Returns nil if no hook is set or if the pool is nil.
func (p *Pool) RefreshPreHook() RefreshPreHook {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshPreHook
}

// SetRefreshPostHook sets the function that will be called after each Refresh()
// operation completes, regardless of success or failure. Pass nil to disable
// the post-hook.
func (p *Pool) SetRefreshPostHook(fn RefreshPostHook) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshPostHook = fn
}

// RefreshPostHook returns the current post-refresh hook function.
// Returns nil if no hook is set or if the pool is nil.
func (p *Pool) RefreshPostHook() RefreshPostHook {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshPostHook
}

// Refresh implements health checking of the candidate resolvers. It will iterate
// over each candidate through a workerpool issuing queries in parallel fashion.
// Candidate resolvers that pass the test will be added to the availableResolvers
// slice while failing resolvers will be added to the unavailableResolvers slice.
//
// The whole Refresh() cycle is protected so there can only be one Refresh() running
// at a time. Concurrent attempts will serialize. Refresh() will return an error if
// HealthDomainSuffix() has not been called with a valid domain name suffix.
//
// If a pre-refresh hook is set, it will be called before the refresh starts. If the
// hook returns false, the refresh is aborted and ErrRefreshAbortedByPreHook is returned.
//
// If a post-refresh hook is set, it will be called after the refresh completes,
// regardless of success or failure (except when aborted by the pre-hook).
//
// If a logger has been set, significant events will be logged as Info(). If the debug
// flag has been set via SetDebug(), more detailed logging will be provided via
// Debug().
func (p *Pool) Refresh() error {
	if p == nil {
		return ErrNilPool
	}

	p.muRefresh.Lock()
	defer p.muRefresh.Unlock()

	// Call pre-hook if set
	if p.refreshPreHook != nil {
		if !p.refreshPreHook(p) {
			return ErrRefreshAbortedByPreHook
		}
	}

	// Ensure post-hook is called when we return (unless aborted by pre-hook)
	defer func() {
		if p.refreshPostHook != nil {
			p.refreshPostHook(p)
		}
	}()

	if p.Client == nil {
		return ErrNilDnsClient
	}

	if p.hcHealthCheck == nil {
		return ErrNilHealthCheck
	}

	// If pool was configured via viper, update resolvers from viper
	if p.viperResolversTag != "" {
		var resolvers FileArray
		if err := viper.UnmarshalKey(p.viperResolversTag, &resolvers); err == nil {
			p.resolvers = resolvers
		}
	}

	// If no domain suffix configured, mark all resolvers unavailable and return error.
	if p.hcDomainSuffix == "" {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.availableResolvers = []string{}
		p.unavailableResolvers = append([]string{}, p.resolvers.StringSlice()...)
		return ErrNoHcSuffix
	}

	// normalize worker pool and retry settings
	wp := p.hcWpSize
	if wp <= 0 {
		wp = 1
	}
	retries := p.maxQueryRetries
	if retries <= 0 {
		retries = 1
	}

	type result struct {
		resolver string
		healthy  bool
	}

	results := make(chan result, len(p.resolvers))

	// helper to ensure resolver has a port
	addPort := func(addr string) string {
		// naive check: if contains colon assume port present (covers IPv6 too in most cases)
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				return addr
			}
		}
		return addr + ":53"
	}

	// use workerpool for concurrency
	pool := workerpool.New(wp)

	for _, resolver := range p.resolvers {
		res := resolver // capture loop variable
		task := func() {
			// generate query name once
			label := p.hcNameGenerator()
			name := dns.Fqdn(label + "." + p.hcDomainSuffix)

			healthy := false
			var lastErr error
			for i := 0; i < retries; i++ {
				// Create a new message for each attempt to avoid any potential
				// concurrent modification issues
				m := new(dns.Msg)
				m.SetQuestion(name, p.hcQType)
				m.RecursionDesired = true // Explicitly request recursion

				ctx, cancel := context.WithTimeout(context.Background(), p.hcResolverTimeout)
				start := time.Now()
				ans, _, err := p.Client.ExchangeContext(ctx, m, addPort(res))
				cancel()
				elapsed := time.Since(start)
				lastErr = err
				if err == nil && ans != nil {
					// Verify the response has a valid question section matching our query
					if len(ans.Question) > 0 && ans.Question[0].Name == name && ans.Question[0].Qtype == p.hcQType {
						if p.hcHealthCheck(*ans, elapsed, p) {
							healthy = true
							break
						}
					} else if p.debug && p.logger != nil {
						p.logger.WithFields(logrus.Fields{
							"resolver":     res,
							"query_name":   name,
							"query_type":   p.hcQType,
							"has_question": len(ans.Question) > 0,
							"answer_name": func() string {
								if len(ans.Question) > 0 {
									return ans.Question[0].Name
								}
								return "<empty>"
							}(),
						}).Debug("received DNS response with invalid question section")
					}
				} // small backoff between retries
				time.Sleep(50 * time.Millisecond)
			}

			if p.debug && p.logger != nil {
				if healthy {
					p.logger.WithField("resolver", res).Debug("resolver passed health check")
				} else {
					if lastErr != nil {
						p.logger.WithFields(logrus.Fields{"resolver": res, "error": lastErr}).Debug("resolver failed health check")
					} else {
						p.logger.WithField("resolver", res).Debug("resolver failed health check (unhealthy response)")
					}
				}
			}

			results <- result{resolver: res, healthy: healthy}
		}

		pool.Submit(task)
	}

	// wait for all submitted tasks to finish
	pool.StopWait()
	close(results)

	// Gather results into a map for O(1) lookup
	healthyMap := make(map[string]bool, len(p.resolvers))
	for r := range results {
		healthyMap[r.resolver] = r.healthy
	}

	// Build available and unavailable lists in original resolver order
	avail := make([]string, 0, len(p.resolvers))
	unavail := make([]string, 0, len(p.resolvers))
	for _, resolver := range p.resolvers {
		if healthyMap[resolver] {
			avail = append(avail, resolver)
		} else {
			unavail = append(unavail, resolver)
		}
	}

	// Update pool state while holding the lock
	p.mu.Lock()
	defer p.mu.Unlock()

	p.availableResolvers = avail
	p.unavailableResolvers = unavail
	p.lastRefreshed = time.Now()

	if p.logger != nil {
		p.logger.WithFields(logrus.Fields{
			"available":   len(p.availableResolvers),
			"unavailable": len(p.unavailableResolvers),
			"when":        p.lastRefreshed.Format(time.RFC3339),
		}).Info("health check refresh completed")
	}

	return nil
}

// RefreshNameServerTimeout sets the timeout interval to use when performing
// resolver health checks. Will refuse negative timeout intervals.
func (p *Pool) RefreshNameServerTimeout(t time.Duration) {
	if t < 0 {
		return
	}
	p.hcResolverTimeout = t
}

// LastRefreshed returns the time of the last successful refresh operation.
// Returns zero time if no refresh has been performed or if the pool is nil.
func (p *Pool) LastRefreshed() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastRefreshed
}

// HealthCheckQType returns the DNS query type used for health checks.
// If not explicitly set, defaults to TypeA.
func (p *Pool) HealthCheckQType() uint16 {
	if p == nil {
		return dns.TypeA
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hcQType
}

// SetHealthCheckQType sets the DNS query type to be used for health checks.
func (p *Pool) SetHealthCheckQType(qtype uint16) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hcQType = qtype
}

// HealthCheckWorkerCount returns the number of worker goroutines used for parallel health checks.
// A value of 0 or negative will still be returned as-is, but during Refresh operations
// these values will result in using a single worker. Defaults to 64.
func (p *Pool) HealthCheckWorkerCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hcWpSize
}

// SetHealthCheckWorkerCount sets the number of worker goroutines used for parallel health checks.
// Values of 0 or negative will result in using a single worker. The default is 64.
// This setting affects the number of concurrent health checks performed during Refresh().
func (p *Pool) SetHealthCheckWorkerCount(count int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hcWpSize = count
}

// MinResolvers returns the minimum number of resolvers that must be available for
// the pool to be considered operational. A value of 0 means no minimum is required.
func (p *Pool) MinResolvers() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.minResolvers
}

// SetMinResolvers sets the minimum number of resolvers that must be available for
// the pool to be considered operational. A value of 0 means no minimum is required.
// Negative values are treated as 0.
func (p *Pool) SetMinResolvers(min int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if min < 0 {
		min = 0
	}
	p.minResolvers = min
}

// MaxQueryRetries returns the maximum number of times a query will be retried with
// different resolvers before giving up. This affects both health checks and regular
// DNS queries. A value of 0 means only one attempt will be made (no retries).
func (p *Pool) MaxQueryRetries() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxQueryRetries
}

// SetMaxQueryRetries sets the maximum number of times a query will be retried with
// different resolvers before giving up. This affects both health checks and regular
// DNS queries. A value of 0 means only one attempt will be made (no retries).
// Negative values are treated as 0.
func (p *Pool) SetMaxQueryRetries(retries int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if retries < 0 {
		retries = 0
	}
	p.maxQueryRetries = retries
}

// AvailableResolvers returns a copy of the list of currently available resolvers.
// The returned slice can be safely modified without affecting the pool's internal state.
// Returns nil if the pool is nil.
func (p *Pool) AvailableResolvers() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.availableResolvers) == 0 {
		return nil
	}

	result := make([]string, len(p.availableResolvers))
	copy(result, p.availableResolvers)
	return result
}

// UnavailableResolvers returns a copy of the list of currently unavailable resolvers.
// The returned slice can be safely modified without affecting the pool's internal state.
// Returns nil if the pool is nil.
func (p *Pool) UnavailableResolvers() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.unavailableResolvers) == 0 {
		return nil
	}

	result := make([]string, len(p.unavailableResolvers))
	copy(result, p.unavailableResolvers)
	return result
}

// Exchange performs a DNS query using a randomly selected resolver from the pool.
// It will retry the query up to maxQueryRetries times if a resolver fails to respond.
// The query will timeout after queryTimeout duration for each attempt.
// Returns the DNS response, elapsed time, and any error encountered.
func (p *Pool) Exchange(m *dns.Msg) (*dns.Msg, time.Duration, error) {
	if p == nil {
		return nil, 0, ErrNilPool
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.queryTimeout)
	defer cancel()

	return p.ExchangeContext(ctx, m)
}

// ExchangeContext performs a DNS query using a randomly selected resolver from the pool.
// It will retry the query up to maxQueryRetries times if a resolver fails to respond.
// The context controls the overall timeout for all retry attempts.
// Returns the DNS response, elapsed time, and any error encountered.
func (p *Pool) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	if p == nil {
		return nil, 0, ErrNilPool
	}
	if p.Client == nil {
		return nil, 0, ErrNilDnsClient
	}

	start := time.Now()
	var lastErr error
	var lastResolver string

	for attempt := 0; attempt <= p.maxQueryRetries; attempt++ {
		// Check context before each attempt
		if err := ctx.Err(); err != nil {
			return nil, time.Since(start), err
		}

		// Get a random resolver
		resolver, err := p.GetRandomResolver()
		if err != nil {
			return nil, time.Since(start), err
		}

		// Remember the current resolver for error reporting
		lastResolver = resolver

		// Try the query
		ans, rtt, err := p.Client.ExchangeContext(ctx, m, resolver)
		if err == nil && ans != nil {
			return ans, rtt, nil
		}

		lastErr = err

		// Small backoff between retries, but respect context
		select {
		case <-ctx.Done():
			return nil, time.Since(start), ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Log the final failure if we have a logger
	if p.logger != nil && p.debug {
		p.logger.WithFields(logrus.Fields{
			"resolver": lastResolver,
		}).Debug("querying resolver failed")
	}

	return nil, time.Since(start), fmt.Errorf("all resolvers failed after %d attempts: %v", p.maxQueryRetries+1, lastErr)
}

// GetRandomResolver returns a randomly selected resolver from the pool of available
// resolvers. It returns an error if the number of available resolvers is less than
// the minimum required threshold. The returned resolver address will have `:53`
// appended if no port is present.
func (p *Pool) GetRandomResolver() (string, error) {
	if p == nil {
		return "", ErrNilPool
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.availableResolvers) < p.minResolvers {
		return "", ErrInsufficientResolvers
	}

	idx := rand.Intn(len(p.availableResolvers))
	resolver := p.availableResolvers[idx]
	
	// Ensure resolver has a port
	// naive check: if contains colon assume port present (covers IPv6 too in most cases)
	for i := len(resolver) - 1; i >= 0; i-- {
		if resolver[i] == ':' {
			return resolver, nil
		}
	}
	return resolver + ":53", nil
}

// AutoRefresh enables automatic refresh of resolver health checks at the interval
// specified by hcAutoRefreshInterval. The behavior is as follows:
//
//   - If hcAutoRefreshInterval is <= 0, automatic refresh is disabled and any
//     existing auto-refresh goroutine is stopped.
//   - If hcAutoRefreshInterval is > 0, a new goroutine is launched that will
//     periodically call Refresh() at the specified interval.
//   - Any existing auto-refresh goroutine is stopped before starting a new one.
//   - The first health check is performed immediately upon enabling auto-refresh.
//   - All Refresh() errors are logged if a logger is configured.
//
// The auto-refresh goroutine can be stopped by either:
//   - Calling AutoRefresh with an interval <= 0
//   - Garbage collecting the Pool (the goroutine will exit automatically)
//
// If you need to manually trigger a refresh while auto-refresh is active,
// you can still call Refresh() directly at any time.
func (p *Pool) AutoRefresh(t time.Duration) {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.hcAutoRefreshInterval = t

	// Stop existing auto-refresh if any
	if p.hcAutoRefreshChan != nil {
		close(*p.hcAutoRefreshChan)
		p.hcAutoRefreshChan = nil
	}

	// Validate interval before proceeding
	if p.hcAutoRefreshInterval <= 0 {
		// If stopping auto-refresh, ensure channel is closed and cleared
		if p.hcAutoRefreshChan != nil {
			close(*p.hcAutoRefreshChan)
			p.hcAutoRefreshChan = nil
		}
		return
	}

	// Create new stop channel for this auto-refresh instance
	stop := make(chan bool)
	p.hcAutoRefreshChan = &stop

	// Ensure positive interval for ticker
	if p.hcAutoRefreshInterval <= 0 {
		return
	}

	// Make a local copy of the interval while holding the lock
	interval := p.hcAutoRefreshInterval

	// Launch auto-refresh goroutine with validated interval
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Perform initial refresh immediately
		if err := p.Refresh(); err != nil && p.logger != nil {
			p.logger.WithError(err).Warn("auto-refresh: initial health check failed")
		}

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := p.Refresh(); err != nil && p.logger != nil {
					p.logger.WithError(err).Warn("auto-refresh: health check failed")
				}
			}
		}
	}()
}
