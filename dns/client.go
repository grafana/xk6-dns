package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.k6.io/k6/js/modules"
	"go.k6.io/k6/lib"
)

// Resolver is the interface that wraps the Resolve method.
//
// Resolve resolves a domain name to an IP address. It returns a slice of IP
// addresses as strings.
type Resolver interface {
	Resolve(ctx context.Context, query, recordType string, nameserver Nameserver) ([]string, error)
}

// Lookuper is the interface that wraps the Lookup method.
//
// As opposed to a Resolver which uses a specific nameserver to resolve the
// query, a Lookuper uses the system's default resolver.
//
// Lookup resolves a domain name to an IP address. It returns a slice of IP
// addresses as strings.
type Lookuper interface {
	Lookup(ctx context.Context, hostname string) ([]string, error)
}

// Client is a DNS resolver that uses the `miekg/dns` package under the hood.
//
// It implements the Resolver interface.
type Client struct {
	// client is the DNS client used to resolve queries.
	client dns.Client

	// k6Client is lazily initialized with k6's dialer in VU context
	k6Client *k6DNSClient

	// once ensures k6Client is initialized only once
	once sync.Once

	vu modules.VU
}

// Ensure our Client implements the Resolver interface
var _ Resolver = &Client{}

// Ensure our Client implements the Lookuper interface
var _ Lookuper = &Client{}

// NewDNSClient creates a new Client.
func NewDNSClient(vu modules.VU) (*Client, error) {
	client := &Client{
		client: dns.Client{},
		vu:     vu,
	}

	return client, nil
}

// ensureK6Client lazily initializes the k6 DNS client with k6's dialer.
// This must be called in VU context where the dialer is available.
func (r *Client) ensureK6Client() error {
	var initErr error

	r.once.Do(func() {
		vuState := r.vu.State()
		if vuState == nil || vuState.Dialer == nil {
			// Fall back to standard DNS client if k6's dialer is not available
			// This can happen in test environments or init context
			r.k6Client = &k6DNSClient{
				Client:   dns.Client{},
				k6Dialer: nil, // Will use standard dialer behavior
			}
			return
		}

		// Create the k6 DNS client with k6's dialer
		r.k6Client = &k6DNSClient{
			Client: dns.Client{
				Timeout: 5 * time.Second,
			},
			k6Dialer: vuState.Dialer,
		}
	})

	return initErr
}

// Resolve resolves a domain name to a slice of IP addresses using the given nameserver.
// It returns a slice of IP addresses as strings.
func (r *Client) Resolve(
	ctx context.Context,
	query, recordType string,
	nameserver Nameserver,
) ([]string, error) {
	// Ensure k6 client is initialized (lazy initialization)
	if err := r.ensureK6Client(); err != nil {
		return nil, fmt.Errorf("failed to initialize k6 DNS client: %w", err)
	}

	concreteType, err := RecordTypeString(recordType)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve operation failed with %w, %s is an invalid DNS record type",
			ErrUnsupportedRecordType,
			recordType,
		)
	}

	// Prepare the DNS query message
	//
	// Because the dns package [dns.SetQuestion] function expects specific
	// uint16 values for the record type, and we don't want to leak that
	// to our public API, we need to convert our RecordType to the
	// corresponding uint16 value.
	message := dns.Msg{}
	message.SetQuestion(query+".", uint16(concreteType))

	// Query the nameserver using k6's dialer
	response, _, err := r.k6Client.ExchangeContext(ctx, &message, nameserver.Addr())
	if err != nil {
		return nil, fmt.Errorf("querying the DNS nameserver failed: %w", err)
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, newDNSError(response.Rcode, "DNS query failed")
	}

	var ips []string
	for _, a := range response.Answer {
		switch t := a.(type) {
		case *dns.A:
			ips = append(ips, t.A.String())
		case *dns.AAAA:
			ips = append(ips, t.AAAA.String())
		default:
			return nil, fmt.Errorf(
				"resolve operation failed with %w: unhandled DNS answer type %T",
				ErrUnsupportedRecordType,
				a,
			)
		}
	}

	return ips, nil
}

// Lookup resolves a domain name to a slice of IP addresses using the system's
// default resolver.
func (r *Client) Lookup(ctx context.Context, hostname string) ([]string, error) {
	// Note: We don't need to use k6's dialer for Lookup since it uses net.DefaultResolver
	// which operates at the system level, not requiring custom dial behavior.
	// k6's network restrictions would be applied at a different layer for system lookups.
	ips, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("lookup of %s failed: %w", hostname, err)
	}

	return ips, nil
}

// k6DNSClient wraps dns.Client to use k6's dialer
// This ensures k6's networking options (blockHostnames, blacklistIPs) are respected
type k6DNSClient struct {
	dns.Client
	k6Dialer lib.DialContexter
}

// ExchangeContext overrides the default ExchangeContext to use k6's dialer
func (c *k6DNSClient) ExchangeContext(ctx context.Context, m *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
	// If k6 dialer is not available, fall back to standard DNS client behavior
	if c.k6Dialer == nil {
		return c.Client.ExchangeContext(ctx, m, address)
	}

	start := time.Now()

	// Create a connection using k6's dialer
	conn, err := c.k6Dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		closeErr := conn.Close()
		if closeErr != nil {
			log.Fatalf("failed to close k6 DNS connection: %v", closeErr)
		}
	}()

	// Set a reasonable deadline for the operation
	var deadlineErr error
	if deadline, ok := ctx.Deadline(); ok {
		deadlineErr = conn.SetDeadline(deadline)
	} else {
		deadlineErr = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if deadlineErr != nil {
		return nil, 0, fmt.Errorf("unable to set dns connection deadline; reason: %w", err)
	}

	// Pack the DNS message and write it
	data, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}

	_, err = conn.Write(data)
	if err != nil {
		return nil, 0, err
	}

	// Read the response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, 0, err
	}

	// Unpack the response
	response := &dns.Msg{}
	err = response.Unpack(buffer[:n])
	if err != nil {
		return nil, 0, err
	}

	totalTime := time.Since(start)
	return response, totalTime, nil
}
