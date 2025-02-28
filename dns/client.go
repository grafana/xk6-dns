package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/miekg/dns"
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
}

// Ensure our Client implements the Resolver interface
var _ Resolver = &Client{}

// Ensure our Client implements the Lookuper interface
var _ Lookuper = &Client{}

// NewDNSClient creates a new Client.
func NewDNSClient() *Client {
	return &Client{
		client: dns.Client{},
	}
}

// Resolve resolves a domain name to a slice of IP addresses using the given nameserver.
// It returns a slice of IP addresses as strings.
func (r *Client) Resolve(
	ctx context.Context,
	query, recordType string,
	nameserver Nameserver,
) ([]string, error) {
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

	// Query the nameserver
	response, _, err := r.client.ExchangeContext(ctx, &message, nameserver.Addr())
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
		case *dns.NAPTR:
			ips = append(ips, fmtNAPTRAnswer(t))
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
	ips, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("lookup of %s failed: %w", hostname, err)
	}

	return ips, nil
}

// Format NAPTR answer.
func fmtNAPTRAnswer(answer *dns.NAPTR) string {
	return strconv.Itoa(int(answer.Order)) + " " +
		strconv.Itoa(int(answer.Preference)) + " " +
		"\"" + answer.Flags + "\" " +
		"\"" + answer.Service + "\" " +
		"\"" + answer.Regexp + "\" " +
		answer.Replacement
}
