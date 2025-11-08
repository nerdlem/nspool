# nspool — DNS Resolver Pool with Health Checking

[![GoDoc](https://godoc.org/github.com/nerdlem/nspool/v2?status.svg)](https://godoc.org/github.com/nerdlem/nspool/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/nerdlem/nspool/v2)](https://goreportcard.com/report/github.com/nerdlem/nspool/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go library for managing a pool of DNS resolvers with automatic health checking, failover, and retry logic.

## Features

- **Health Checking**: Periodic validation of resolver availability
- **Automatic Failover**: Queries automatically retry on different resolvers
- **Configurable**: Timeouts, retry counts, worker pools, and health check behavior
- **Thread-Safe**: Concurrent refresh and query operations
- **Refresh Hooks**: Pre and post-refresh callbacks for logging and metrics
- **Viper Integration**: Dynamic configuration from config files

## Installation

```bash
go get github.com/nerdlem/nspool/v2
```

## Quick Start

```go
import "github.com/nerdlem/nspool/v2"

// Create pool with resolver addresses (resolvers start as available)
nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})

// Configure health checking
nsp.SetHealthDomainSuffix("example.com")
nsp.SetMinResolvers(1)

// Optionally perform health check to validate resolvers
if err := nsp.Refresh(); err != nil {
    log.Fatal(err)
}

// Query DNS using the pool
msg := new(dns.Msg)
msg.SetQuestion("github.com.", dns.TypeA)
response, _, err := nsp.Exchange(msg)
```

## Use Cases

### Basic Resolver Pool
Create and use a pool of DNS resolvers with automatic health checking.

### Configuration from Viper
Load resolver configuration from config files with hot-reload support.

### Custom Health Checks
Implement custom validation logic to verify resolver responses.

### Refresh Hooks
Add pre/post-refresh callbacks for logging, metrics, or conditional refresh.

### Auto-Refresh
Automatically refresh resolver health at regular intervals.

### Quiet Mode for Production
Reduce log verbosity by suppressing demotion messages while still tracking critical state changes (suspensions and reinstatements).

```go
nsp := nspool.NewFromPoolSlice([]string{"1.1.1.1:53", "8.8.8.8:53"})
nsp.SetLogger(logger)

// Enable quiet mode - only logs when resolvers are suspended or reinstated
nsp.SetQuietResolverStateChange(true)

// Set error thresholds
nsp.SetResolverErrorThreshold(0.05)    // 5% error rate triggers weight reduction (logged only if quiet mode is off)
nsp.SetResolverDisableThreshold(0.20)  // 20% error rate triggers suspension (always logged)
```

## Documentation

Full documentation with examples is available at [pkg.go.dev/github.com/nerdlem/nspool/v2](https://pkg.go.dev/github.com/nerdlem/nspool/v2).

## Important Note

**This code should only be used with recursive resolvers you control, operate, or are authorized to use.** Sending large volumes of DNS queries to public resolvers may be considered abusive and can result in complaints or blacklisting.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

Luis E. Muñoz
