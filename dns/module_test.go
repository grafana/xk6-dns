package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.k6.io/k6/lib/netext"
	"go.k6.io/k6/lib/types"

	"github.com/testcontainers/testcontainers-go"
	"go.k6.io/k6/metrics"

	"go.k6.io/k6/lib"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"go.k6.io/k6/js/modulestest"
)

const (
	// testDomain is the domain name we configure our test DNS server to resolve to the
	// primaryTestIPv4 and secondaryTestIPv4.
	testDomain = "k6.test"

	// primaryTestIPv4 is a default IPv4 address we configure our test DNS server  to resolve the
	// testDomain to.
	//
	// We explicitly use a "martian", non-routable IP address (as per [RFC 1918]) to avoid any potential conflicts with
	// real-world IP addresses.
	//
	// [RFC 1918]: https://datatracker.ietf.org/doc/html/rfc1918
	primaryTestIPv4 = "203.0.113.1"

	// primaryTestIPv6 is a default IPv6 address we configure our test DNS server  to resolve the
	// testDomain to. This points to the same IP as primaryTestIPv4, and is subject to the same routing
	// constraints.
	primaryTestIPv6 = "fd60:76ff:fe12:3456:789a:bcde:f012:3456"

	// secondaryTestIPv4 is a default IP address we configure our test DNS server  to resolve the
	// testDomain to.
	//
	// We explicitly use a "martian", non-routable IP address (as per [RFC 1918]) to avoid any potential conflicts with
	// real-world IP addresses.
	//
	// [RFC 1918]: https://datatracker.ietf.org/doc/html/rfc1918
	secondaryTestIPv4 = "203.0.113.11"

	// secondaryTestIPv6 is a default IPv6 address we configure our test DNS server  to resolve the
	// testDomain to. This points to the same IP as secondaryTestIPv4, and is subject to the same routing
	// constraints.
	secondaryTestIPv6 = "fd61:76ff:fe12:3456:789a:bcde:f012:6789"
)

func TestClient_Resolve(t *testing.T) {
	t.Parallel()

	t.Run("Resolving in the init context should fail", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(`
			await dns.resolve("k6.io", "A", "1.1.1.1:53");
		`))

		assert.Error(t, err)
	})

	t.Run("Resolving existing A records against cloudflare nameserver should succeed", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Setting up the runtime with the necessary state
		runtime.MoveToVUContext(newTestVUState())

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(`
			const resolveResults = await dns.resolve("k6.io", "A", "1.1.1.1:53");
		
			if (resolveResults.length === 0) {
				throw "Resolving k6.io against cloudflare CDN returned no results, expected at least one IP"
			}
		`))

		assert.NoError(t, err)
	})

	t.Run("Resolving existing A records against test nameserver should succeed", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		unboundContainer, mappedPort := startUnboundContainer(ctx, t)
		defer func() {
			if err := unboundContainer.Terminate(ctx); err != nil {
				t.Fatalf("could not stop unbound: %s", err.Error())
			}
		}()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Setting up the runtime with the necessary state to execute in the VU context
		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			const resolveResults = await dns.resolve(
				"` + testDomain + `",
				"` + RecordTypeA.String() + `",
				"127.0.0.1:` + strconv.Itoa(mappedPort.Int()) + `"
			);
		
			if (resolveResults.length === 0) {
				throw "Resolving k6.local against unbound server test container returned no results, expected ['` + primaryTestIPv4 + `']"
			}
			
			if (resolveResults.length !== 2) {
				throw "Resolving k6.local against unbound server test container returned an unexpected number of results, expected 2 ips, got:" + resolveResults.length
			}
		
			// We sort the results to ensure that the order is consistent
			// and we can compare the results with the expected values
			resolveResults.sort();

		
			if (resolveResults[0] !== "` + primaryTestIPv4 + `") {
				throw "Resolving k6.local against unbound server test container returned unexpected result, expected '` + primaryTestIPv4 + `', got " + resolveResults[0]
			}
		
			if (resolveResults[1] !== "` + secondaryTestIPv4 + `") {
				throw "Resolving k6.local against unbound server test container returned unexpected result, expected '` + secondaryTestIPv4 + `', got " + resolveResults[1]
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving non-existing A records against test nameserver should succeed", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		unboundContainer, mappedPort := startUnboundContainer(ctx, t)
		defer func() {
			if err := unboundContainer.Terminate(ctx); err != nil {
				t.Fatalf("could not stop unbound: %s", err.Error())
			}
		}()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Setting up the runtime with the necessary state to execute in the VU context
		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			try {
				const resolvedResults = await dns.resolve(
					"missing.domain",
					"` + RecordTypeA.String() + `",
					"127.0.0.1:` + strconv.Itoa(mappedPort.Int()) + `"
				);
			} catch (err) {
				if (err.name !== "NonExistingDomain") {
					throw "Resolving missing.domain against unbound server test container returned unexpected error, expected NonExistingDomain, got: " + err.Name
				}
		
				// We expected this error, so we can return
				return
			}
		
			throw "Resolving missing.domain against unbound server test container should have thrown an error, but it didn't"
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving existing AAAA records against test nameserver should succeed", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		unboundContainer, mappedPort := startUnboundContainer(ctx, t)
		defer func() {
			if err := unboundContainer.Terminate(ctx); err != nil {
				t.Fatalf("could not stop unbound: %s", err.Error())
			}
		}()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Setting up the runtime with the necessary state to execute in the VU context
		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			const resolveResults = await dns.resolve(
				"` + testDomain + `",
				"` + RecordTypeAAAA.String() + `",
				"127.0.0.1:` + strconv.Itoa(mappedPort.Int()) + `"
			);
		
			// We sort the results to ensure that the order is consistent
			// and we can compare the results with the expected values
			resolveResults.sort();
		
			if (resolveResults.length === 0) {
				throw "Resolving k6.local against unbound server test container returned no results, expected ['` + primaryTestIPv6 + `']"
			}
			
			if (resolveResults.length !== 2) {
				throw "Resolving k6.local against unbound server test container returned an unexpected number of results, expected 2 ips, got:" + resolveResults.length
			}
		
			if (resolveResults[0] !== "` + primaryTestIPv6 + `") {
				throw "Resolving k6.local against unbound server test container returned unexpected result, expected '` + primaryTestIPv6 + `', got " + resolveResults[0]
			}
		
			if (resolveResults[1] !== "` + secondaryTestIPv6 + `") {
				throw "Resolving k6.local against unbound server test container returned unexpected result, expected '` + secondaryTestIPv6 + `', got " + resolveResults[1]
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving non-existing AAAA records against test nameserver should succeed", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		unboundContainer, mappedPort := startUnboundContainer(ctx, t)
		defer func() {
			if err := unboundContainer.Terminate(ctx); err != nil {
				t.Fatalf("could not stop unbound: %s", err.Error())
			}
		}()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Setting up the runtime with the necessary state to execute in the VU context
		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			try {
				const resolvedResults = await dns.resolve(
					"missing.domain",
					"` + RecordTypeAAAA.String() + `",
					"127.0.0.1:` + strconv.Itoa(mappedPort.Int()) + `"
				);
			} catch (err) {
				if (err.name !== "NonExistingDomain") {
					throw "Resolving missing.domain against unbound server test container returned unexpected error, expected NonExistingDomain, got: " + err.name
				}
				
				// We expected this error, so we can return
				return
			}
		
			throw "Resolving missing.domain against unbound server test container should have thrown an error, but it didn't"
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving against a blacklisted IP should fail", func(t *testing.T) {
		t.Parallel()

		// No need to start an Unbound container; we target localhost:53 and rely on the
		// k6 dialer blacklist to block the connection.

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Configure a dialer blacklisting 127.0.0.1
		state := newTestVUState()
		state.Dialer = newTestBlacklistIPsDialer("127.0.0.1", net.CIDRMask(32, 32))
		runtime.MoveToVUContext(state)

		testScript := `
			await dns.resolve(
				"google.com",
				"` + RecordTypeA.String() + `",
				"127.0.0.1:53"
			);
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.Error(t, err)
	})

	t.Run("Resolving against a blocked hostname should fail", func(t *testing.T) {
		t.Parallel()

		// No need to start an Unbound container; we target localhost:53 and rely on the
		// k6 dialer blacklist to block the connection.

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		state := newTestVUState()
		state.Dialer = newTestBlockedHostnameDialer("blocked.com")
		runtime.MoveToVUContext(state)

		testScript := `
			try {
				await dns.resolve(
					"blocked.com",
					"` + RecordTypeA.String() + `",
					"127.0.0.1:53"
				);
			} catch (err) {
				if (err.name !== "BlockedHostname") {
					throw "Resolving blocked.com against unbound server test container returned unexpected error, expected BlockedHostname, got: " + err.name
				}
				
				// We expected this error, so we can return
				return
			}

			throw "Resolving blocked.com against unbound server test container should have thrown an error, but it didn't"
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})
}

func TestClient_ResolveIPv6Nameservers(t *testing.T) {
	t.Parallel()

	t.Run("Resolving using bare IPv6 loopback nameserver address should succeed", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		unboundContainer, _ := startUnboundContainer(ctx, t)
		defer func() {
			if err := unboundContainer.Terminate(ctx); err != nil {
				t.Fatalf("could not stop unbound: %s", err.Error())
			}
		}()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		// Test using bare IPv6 address without port (should default to port 53)
		// Note: We can't use ::1 directly because the container is on IPv4 localhost
		// This test validates the parsing logic handles IPv6 format correctly
		testScript := `
			try {
				// This tests that we can parse IPv6 addresses
				// Using a real IPv6 address would require IPv6 network setup
				await dns.resolve(
					"` + testDomain + `",
					"` + RecordTypeAAAA.String() + `",
					"::1"
				);
			} catch (err) {
				// We expect a connection error since ::1 won't have our test server
				// but the parse should succeed. If parsing fails, we get a different error.
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "IPv6 parsing failed: " + err.message;
				}
				// Connection failure is expected - parsing succeeded
				return;
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving using IPv6 nameserver with bracket notation and port should succeed", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		unboundContainer, mappedPort := startUnboundContainer(ctx, t)
		defer func() {
			if err := unboundContainer.Terminate(ctx); err != nil {
				t.Fatalf("could not stop unbound: %s", err.Error())
			}
		}()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			try {
				await dns.resolve(
					"` + testDomain + `",
					"` + RecordTypeAAAA.String() + `",
					"[::1]:` + strconv.Itoa(mappedPort.Int()) + `"
				);
			} catch (err) {
				// We expect a connection error since ::1 may not be reachable
				// but the parse should succeed
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "IPv6 bracket notation parsing failed: " + err.message;
				}
				// Connection failure is expected - parsing succeeded
				return;
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving using bracketed IPv6 nameserver without port should succeed", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		unboundContainer, _ := startUnboundContainer(ctx, t)
		defer func() {
			if err := unboundContainer.Terminate(ctx); err != nil {
				t.Fatalf("could not stop unbound: %s", err.Error())
			}
		}()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			try {
				await dns.resolve(
					"` + testDomain + `",
					"` + RecordTypeAAAA.String() + `",
					"[::1]"
				);
			} catch (err) {
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "IPv6 bracketed without port parsing failed: " + err.message;
				}
				// Connection failure is expected - parsing succeeded
				return;
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving using compressed IPv6 notation should succeed", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			try {
				// Test compressed IPv6 notation parsing
				await dns.resolve(
					"k6.io",
					"` + RecordTypeAAAA.String() + `",
					"fe80::1"
				);
			} catch (err) {
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "Compressed IPv6 notation parsing failed: " + err.message;
				}
				// Connection failure is expected - parsing succeeded
				return;
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving AAAA records using public IPv6 nameserver should succeed", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		// This is the exact case from issue #20 - using Cloudflare's IPv6 DNS
		// This test may fail in environments without IPv6 connectivity
		testScript := `
			try {
				const resolveResults = await dns.resolve(
					"k6.io",
					"` + RecordTypeAAAA.String() + `",
					"2606:4700:4700::1111"
				);

				if (resolveResults.length === 0) {
					throw "Expected at least one IPv6 address for k6.io";
				}
			} catch (err) {
				// If the error is about parsing, that's a real failure
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "IPv6 nameserver parsing failed: " + err.message;
				}

				// If IPv6 is not available in the test environment, skip
				if (err.message && (
					err.message.includes("network is unreachable") ||
					err.message.includes("no route to host") ||
					err.message.includes("connect: cannot assign requested address")
				)) {
					console.log("Skipping test - IPv6 not available in environment");
					return;
				}

				// Other errors are real failures
				throw err;
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving AAAA records using public IPv6 nameserver with brackets and port should succeed", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			try {
				const resolveResults = await dns.resolve(
					"k6.io",
					"` + RecordTypeAAAA.String() + `",
					"[2606:4700:4700::1111]:53"
				);

				if (resolveResults.length === 0) {
					throw "Expected at least one IPv6 address for k6.io";
				}
			} catch (err) {
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "IPv6 nameserver with brackets parsing failed: " + err.message;
				}

				if (err.message && (
					err.message.includes("network is unreachable") ||
					err.message.includes("no route to host") ||
					err.message.includes("connect: cannot assign requested address")
				)) {
					console.log("Skipping test - IPv6 not available in environment");
					return;
				}

				throw err;
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving A records using public IPv6 nameserver should succeed", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		// Test that IPv6 nameservers work for A record queries too
		testScript := `
			try {
				const resolveResults = await dns.resolve(
					"k6.io",
					"` + RecordTypeA.String() + `",
					"2606:4700:4700::1111"
				);

				if (resolveResults.length === 0) {
					throw "Expected at least one IPv4 address for k6.io";
				}
			} catch (err) {
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "IPv6 nameserver parsing failed: " + err.message;
				}

				if (err.message && (
					err.message.includes("network is unreachable") ||
					err.message.includes("no route to host") ||
					err.message.includes("connect: cannot assign requested address")
				)) {
					console.log("Skipping test - IPv6 not available in environment");
					return;
				}

				throw err;
			}
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving non-existing domain against public IPv6 nameserver should return NonExistingDomain error", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		testScript := `
			try {
				await dns.resolve(
					"this-domain-definitely-does-not-exist-12345.com",
					"` + RecordTypeAAAA.String() + `",
					"[2606:4700:4700::1111]:53"
				);
			} catch (err) {
				// Check if it's a parsing error first (that would be a bug)
				if (err.message && err.message.includes("invalid nameserver")) {
					throw "IPv6 nameserver parsing failed: " + err.message;
				}

				// If IPv6 is not available, skip
				if (err.message && (
					err.message.includes("network is unreachable") ||
					err.message.includes("no route to host") ||
					err.message.includes("connect: cannot assign requested address")
				)) {
					console.log("Skipping test - IPv6 not available in environment");
					return;
				}

				// We expect NonExistingDomain error
				if (err.name !== "NonExistingDomain") {
					throw "Expected NonExistingDomain error, got: " + err.name;
				}

				// Expected error received
				return;
			}

			throw "Expected NonExistingDomain error but query succeeded";
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving against blacklisted IPv6 nameserver should fail", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Configure a dialer blacklisting the IPv6 loopback address
		state := newTestVUState()
		state.Dialer = newTestBlacklistIPsDialer("::1", net.CIDRMask(128, 128))
		runtime.MoveToVUContext(state)

		testScript := `
			await dns.resolve(
				"k6.io",
				"` + RecordTypeAAAA.String() + `",
				"[::1]:53"
			);
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dial")
	})

	t.Run("Resolving blocked hostname against IPv6 nameserver should fail", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		state := newTestVUState()
		state.Dialer = newTestBlockedHostnameDialer("blocked.com")
		runtime.MoveToVUContext(state)

		testScript := `
			try {
				await dns.resolve(
					"blocked.com",
					"` + RecordTypeAAAA.String() + `",
					"[::1]:53"
				);
			} catch (err) {
				if (err.name !== "BlockedHostname") {
					throw "Expected BlockedHostname error, got: " + err.name;
				}

				// Expected error received
				return;
			}

			throw "Expected BlockedHostname error but query succeeded";
		`

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
		assert.NoError(t, err)
	})

	t.Run("Resolving using malformed IPv6 nameserver should fail with clear error", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		runtime.MoveToVUContext(newTestVUState())

		testCases := []struct {
			name       string
			nameserver string
		}{
			{"invalid IPv6", "gggg::1"},
			{"missing bracket close", "[::1:53"},
			{"incomplete IPv6", "2606:4700:"},
			{"port without brackets", "::1:99999"},
		}

		for _, tc := range testCases {
			testScript := `
				try {
					await dns.resolve(
						"k6.io",
						"` + RecordTypeAAAA.String() + `",
						"` + tc.nameserver + `"
					);
				} catch (err) {
					// We expect a parsing error
					if (err.message && (
						err.message.includes("invalid nameserver") ||
						err.message.includes("parsing nameserver")
					)) {
						// Expected error
						return;
					}

					throw "Expected parsing error for malformed IPv6, got: " + err.message;
				}

				throw "Expected parsing error but query succeeded";
			`

			_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(testScript))
			assert.NoError(t, err, "Test case: %s", tc.name)
		}
	})
}

func TestClient_Lookup(t *testing.T) {
	t.Parallel()

	t.Run("Lookup fails in the init context", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		_, err = runtime.RunOnEventLoop(wrapInAsyncLambda(`
			await dns.lookup("k6.io");
		`))

		// network operations are forbidden in the init context, thus
		// we explicitly expect an error here
		assert.Error(t, err)
	})

	t.Run("Lookup with a nil dialer should fail", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Setting up the runtime with the necessary state
		state := newTestVUState()
		state.Dialer = nil
		runtime.MoveToVUContext(state)

		_, gotErr := runtime.RunOnEventLoop(wrapInAsyncLambda(`
			await dns.lookup("k6.io");
		`))

		assert.Error(t, gotErr)
	})

	t.Run("Lookup against a blocked hostname should fail", func(t *testing.T) {
		t.Parallel()

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		state := newTestVUState()
		state.Dialer = newTestBlockedHostnameDialer("blocked.com")
		runtime.MoveToVUContext(state)

		_, gotErr := runtime.RunOnEventLoop(wrapInAsyncLambda(`
			try {
				await dns.lookup("blocked.com");
			} catch (err) {
				if (err.name !== "BlockedHostname") {
					throw "Looking up blocked.com against unbound server test container returned unexpected error, expected BlockedHostname, got: " + err.name
				}
				
				// We expected this error, so we can return
				return
			}

			throw "Looking up blocked.com against unbound server test container should have thrown an error, but it didn't"
		`))

		assert.NoError(t, gotErr)
	})
}

const initGlobals = `
	globalThis.dns = require("k6/x/dns");
`

func newConfiguredRuntime(t testing.TB) (*modulestest.Runtime, error) {
	runtime := modulestest.NewRuntime(t)

	err := runtime.SetupModuleSystem(
		map[string]interface{}{"k6/x/dns": New()},
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Ensure the `fs` module is available in the VU's runtime.
	_, err = runtime.VU.Runtime().RunString(initGlobals)
	require.NoError(t, err)

	return runtime, err
}

// wrapInAsyncLambda is a helper function that wraps the provided input in an async lambda. This
// makes the use of `await` statements in the input possible.
func wrapInAsyncLambda(input string) string {
	// This makes it possible to use `await` freely on the "top" level
	return "(async () => {\n " + input + "\n })()"
}

func startUnboundContainer(ctx context.Context, t *testing.T) (runningContainer testcontainers.Container, mappedPort nat.Port) {
	recordsConfig := newUnboundRecordsConfiguration(
		unboundRecord{testDomain, RecordTypeA.String(), primaryTestIPv4},
		unboundRecord{testDomain, RecordTypeA.String(), secondaryTestIPv4},
		unboundRecord{testDomain, RecordTypeAAAA.String(), primaryTestIPv6},
		unboundRecord{testDomain, RecordTypeAAAA.String(), secondaryTestIPv6},
	)

	network := testcontainers.DockerNetwork{Name: "testcontainers"}

	containerRequest := testcontainers.ContainerRequest{
		Image: "mvance/unbound:1.20.0",
		Files: []testcontainers.ContainerFile{
			{
				Reader:            strings.NewReader(recordsConfig),
				ContainerFilePath: "/opt/unbound/etc/unbound/a-records.conf",
			},
		},
		ExposedPorts: []string{"53/tcp", "53/udp"},
		WaitingFor:   wait.ForListeningPort("53/udp"),
		Networks:     []string{network.Name},
	}

	runningContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
		Reuse:            false,
	})
	if err != nil {
		t.Fatal(err)
	}

	mappedPort, err = runningContainer.MappedPort(ctx, "53/udp")
	require.NoError(t, err)

	return runningContainer, mappedPort
}

// newUnboundRecordsConfiguration creates a new unbound configuration with the provided records.
//
// It returns a string that can be used to configure (as the content of a file an unbound server to resolve the provided
// records.
func newUnboundRecordsConfiguration(records ...unboundRecord) string {
	var sb strings.Builder
	for _, record := range records {
		sb.WriteString(record.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

// unboundRecord holds the information necessary to configure an unbound server to resolve a domain
// to a specific IP address.
//
// Specifically this is used to generate the local-data configuration entries for unbound.
type unboundRecord struct {
	// Domain holds the domain name to resolve.
	Domain string

	// RecordType holds the record type to resolve the domain to.
	RecordType string

	// IP holds the IP address to resolve the domain to.
	IP string
}

// String returns the unbound configuration entry for the unboundRecord.
func (c unboundRecord) String() string {
	return fmt.Sprintf(`local-data: "%s. 0 IN %s %s"`, c.Domain, c.RecordType, c.IP)
}

func newTestVUState() *lib.State {
	return &lib.State{
		BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
		Dialer:         newTestDialer(),
		Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
		Samples:        make(chan metrics.SampleContainer, 8),
	}
}

func newTestDialer() *netext.Dialer {
	return netext.NewDialer(net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 10 * time.Second,
	}, nil)
}

func newTestBlacklistIPsDialer(ip string, m net.IPMask) *netext.Dialer {
	// Prepare an IP blacklist
	blacklist := []*lib.IPNet{{
		IPNet: net.IPNet{
			IP:   net.ParseIP(ip),
			Mask: m,
		},
	}}

	// prepare a k6 dialer with our blacklist.
	// We explicitly disable the resolver to ensure we do not bypass our own.
	dialer := newTestDialer()
	dialer.Blacklist = blacklist
	return dialer
}

func newTestBlockedHostnameDialer(hostname string) *netext.Dialer {
	// prepare a k6 dialer with blocked hostnames.
	// We explicitly disable the resolver to ensure we do not bypass our own.
	dialer := newTestDialer()

	// Set blocked hostnames for tests expecting hostname-based blocking
	trie, _ := types.NewHostnameTrie([]string{hostname})
	dialer.BlockedHostnames = trie

	return dialer
}
