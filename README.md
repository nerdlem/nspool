[![GoDoc](https://godoc.org/github.com/nerdlem/nspool?status.svg)](https://godoc.org/github.com/nerdlem/nspool)
[![Go Report Card](https://goreportcard.com/badge/github.com/nerdlem/nspool)](https://goreportcard.com/report/github.com/nerdlem/nspool)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# nspool — Work with healthy subset of a constellation of DNS (recursive, caching) resolvers

This module is a merge of my private version of the nspool library dating back to 2014, modernized. It has been run through various tools to expand documentation, provide comments and better adapt to contemporary Go practices.

This module provides a basic schema for using a group of nameservers provided that they pass a basic health check. It also supports selecting subsets of name servers that respond within a specific threshold.

> This code should always be used with recursive resolvers and authoritative nameservers you control and operate yourself, or that you are authorized to use. Sending large amounts of DNS queries indiscriminately will often be construed as abusive and can result in complaints to your ISP or blacklisting.

The initial name server pool can be provided via the constructor function.

```go
 // Initialize the pool with an explicit, fixed set of nameservers
 nsp := nspool.NewFromSlice([]string{"ns1.resolver.example:53", 
                                         "ns2.resolver.example:53"})
```

 It can also be specified as a selector for `viper.GetStringSlice()`, which provides for a handy way to update the set of resolvers on the fly provided that your code handles automatic config file changes.

```go
// Initialize the pool with whatever name servers are provided via the config
nsp := nspool.NewFromViper("dns.resolvers")
```

In the example above, your TOML config file could have something like this:

```toml
[dns]
resolvers = [ "ns1.resolver.example:53", "ns2.resolver.example:53" ]
```

## DNS resolver health checks

When the automatic timer triggers or the `Refresh()` method is invoked, the following actions will be taken:

* If the pool was initialized from `viper`, the list of candidate resolvers will be pulled.
* A query to a randomly generated FQDN under the `HealthDomainSuffix()` domain will be sent to each candidate nameserver.
* The response will be tallied and checked against the validation function.
* Candidate nameservers that respond within the allocated time and for whom the validation function returns a `true` value are marked as available.
* All remaining nameservers are marked as unavailable.

Candidate nameservers marked as available can be used to submit queries.

Query submission and random nameserver selection will either return and error or block—depending on whether an automatic refresh has been requested—when less than the minimum number of available nameservers are present.

Note that `Refresh()` will briefly block query operations to the pool.

Duration performs its checks using an internal worker pool whose size can be configured via the `RefreshWorkers()` method.

The time to wait for a response from each candidate nameserver is controlled by the `RefreshNameserverTimeout(t time.Duration)`. It defaults to `10s` which is probably fine for a small number of resolvers under your control and in close network proximity. Your code can use a construct like this for setting up the pool:

```go
viper.SetDefault("dns.resolver_health_timeout", "10s")
  ⋮
nsp.RefreshNameserverTimeout(viper.GetDuration("dns.resolver_health_timeout"))
```

For applications performing many DNS queries and using a wider base of resolvers at differrent locations, you will probably need a much longer interval as the test itself can take a long time. Verbose logging will provide hopefully helpful information to tune this value.

### Random hostname generation

Random hostnames are generated using a function following this signature

```go
type HealthLabelGenerator func() string
```

The default implementation of this function returns a random 16 character alphanumeric string, which is then concatenated with `HealthDomainSuffix()` to generate a random hostname. This process is repeated once per health check with the same FQDN being used to probe all candidate resolvers.

Note that `HealthDomainSuffix()` should be set to a domain or subdomain under your control, for which you provide authoritative name services. Pointing this to a domain managed elsewhere can be abusive.

This example shows how this function can be overriden to use a specific hostname:

```go
nsp.HealthLabelGenerator(func() { return "fixed-label" })
```

Using this approach allows prospective resolvers to answer the query from their cache. This check is lighter in resources at both the candidate resolvers and your own authoritative nameservers for `HealthDomainSuffix()`.

## Automatic nameserver refreshing

The `nsp.AutoRefresh(t time.Duration)` function can be used to request that the pool issues a `Refresh()` each `t` interval. Typical usage is as follows:

```go
viper.SetDefault("dns.auto_refresh", "5m")
  ⋮
nsp.AutoRefresh(viper.GetDuration("dns.auto_refresh"))
```

## Retrying failed queries

The `nsp.MaxQueryRetries(n int)` and `nsp.QueryTimeout(t time.Duration)` are used to handle DNS query timeouts and retries when using `nsp.Exchange()` and `nsp.ExchangeContext()` to perform queries against random servers in the pool.

Queries failing due to timeouts or networking issues are retried automatically—up to `MaxQueryRetries()` times—on behalf of the caller.

## Logging with logrus

This module can use the [github.com/sirupsen/logrus](https://github.com/sirupsen/logrus) logging library to log query failures and other exceptional conditions. In order to enable this behavior, you need to follow this example:

```go
// Create and maybe configure your logging object
Log = logrus.New()
  ⋮
// Create your nameserver pool
nsp := nspool.NewFromViper("dns.resolvers")
  ⋮
// Enable logging from the nameserver pool
nsp.SetLogger(Log)
```

Logging can be disabled as follows:

```go
nsp.SetLogger(nil)
```

## The health-check function

This is a user-supplied function that verifies the response of the periodic nameserver health check and returns a boolean value to inform the pool about the health status of each nameserver. A `true` value indicates a healthy, usable resolver while a `false` value indicates that the resolver should not be used.

The module includes a default health-check function `DefaultHealtCheck` that returns `true` when the nameserver response was successful. You can provide custom functions for more case-specific tests. This is an example:

```go
// myHealthCheck is a custom function satisfying the nspool.HealthCheckFunc inerface.
// It checks that the response came in under 10 secods, that the response was successful
// (NOERROR), that it includes at least one RR in the answer section, that the first RR
// in the answer section is an A RR and that the IP address in the A record is the magic
// number 42.42.42.42
//
// This can easily be arranged by providing a wildcard record on a specific subdomain on
// a zone under your control.
func myHealthCheck(resp *dns.Msg, t time.Duration, p *nspool.Pool) bool {
    if t < 10 * time.Second {
        if resp.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
            if a, ok := resp.Answer[0].(*dns.A); ok {
                return a.A.String() == "42.42.42.42"
            }
        }
    }
    return false
}
  ⋮
// Tell the pool to use your custom health check function
nsp.HealthCheckFunction(myHealthCheck)
```

# Performing DNS queries

The pool can be used directly to perform DNS queries as follows. In the first example, we use a `context` to provide a specific timeout for this query.

```go
// Initialize (and maybe configure) your nameserver pool
nsp := nspool.NewFromViper("dns.resolvers")
  ⋮
// Setup a context to use to handle the DNS query
ctx, cancel := context.WithTimeout(context.Background(), viper.GetDuration("dns.processing_timeout"))
defer cancel()
  ⋮
// Create the DNS query, look for the SOA of domain.example
qSOA := new(dns.Msg)
qSOA.SetQuestion("domain.example", dns.TypeSOA)
qSOA.RecursionDesired = true

// Send the DNS query to a randomly selected nameserver
r, _, err := nsp.ExchangeContext(ctx, qSOA)
if err != nil {
    return err
}
```

In this example, the DNS query does not use a `context`.

```go
// Initialize (and maybe configure) your nameserver pool
nsp := nspool.NewFromViper("dns.resolvers")
  ⋮
// Create the DNS query, look for the SOA of domain.example
qSOA := new(dns.Msg)
qSOA.SetQuestion("domain.example", dns.TypeSOA)
qSOA.RecursionDesired = true

// Send the DNS query to a randomly selected nameserver
r, _, err := nsp.Exchange(qSOA)
if err != nil {
    return err
}
```

You can also obtain a randomly selected nameserver directly and use it in your code, for better control.

```go
// Initialize (and maybe configure) your nameserver pool and DNS client
nsp := nspool.NewFromViper("dns.resolvers")
c := new(dns.Client)
  ⋮
// Setup a context to use to handle the DNS query
ctx, cancel := context.WithTimeout(context.Background(), viper.GetDuration("dns.processing_timeout"))
defer cancel()
  ⋮
// Create the DNS query, look for the SOA of domain.example
qSOA := new(dns.Msg)
qSOA.SetQuestion("domain.example", dns.TypeSOA)
qSOA.RecursionDesired = true

// Send the DNS query to a randomly selected nameserver.
r, _, err := c.ExchangeContext(ctx, qSOA, nsp.GetRandomNameserver())
if err != nil {
    return err
}
```
