package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/go-connections/nat"

	"github.com/testcontainers/testcontainers-go/wait"

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
		runtime.MoveToVUContext(&lib.State{
			BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
			Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
			Samples:        make(chan metrics.SampleContainer, 1024),
		})

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
		runtime.MoveToVUContext(&lib.State{
			BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
			Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
			Samples:        make(chan metrics.SampleContainer, 8),
		})

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
		runtime.MoveToVUContext(&lib.State{
			BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
			Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
			Samples:        make(chan metrics.SampleContainer, 8),
		})

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
		runtime.MoveToVUContext(&lib.State{
			BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
			Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
			Samples:        make(chan metrics.SampleContainer, 8),
		})

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
		runtime.MoveToVUContext(&lib.State{
			BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
			Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
			Samples:        make(chan metrics.SampleContainer, 8),
		})

		testScript := `
			try {
				const resolvedResults = await dns.resolve(
					"missing.domain",
					"` + RecordTypeAAAA.String() + `",
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

	t.Run("Lookup returns the system's default resolver results", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		wantIPs, err := net.DefaultResolver.LookupHost(ctx, "k6.io")
		require.NoError(t, err)

		runtime, err := newConfiguredRuntime(t)
		require.NoError(t, err)

		// Setting up the runtime with the necessary state
		runtime.MoveToVUContext(&lib.State{
			BuiltinMetrics: metrics.RegisterBuiltinMetrics(metrics.NewRegistry()),
			Tags:           lib.NewVUStateTags(metrics.NewRegistry().RootTagSet().With("tag-vu", "mytag")),
			Samples:        make(chan metrics.SampleContainer, 1024),
		})

		_, gotErr := runtime.RunOnEventLoop(wrapInAsyncLambda(fmt.Sprintf(`
			const lookupResults = await dns.lookup("k6.io");

			if (lookupResults.length !== %d) {
				throw "Looking up k6.io using the system's default resolver returned unexpected number of results, expected %d, got " + lookupResults
			}
		`, len(wantIPs), len(wantIPs))))

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
