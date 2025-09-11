package dns

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseNameserverAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		addr     string
		wantIP   net.IP
		wantPort uint16
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "IPv4 address with port",
			addr:     "192.168.1.1:8080",
			wantIP:   net.ParseIP("192.168.1.1"),
			wantPort: 8080,
			wantErr:  assert.NoError,
		},
		{
			name:     "IPv4 address without port",
			addr:     "192.168.1.1",
			wantIP:   net.ParseIP("192.168.1.1"),
			wantPort: 53,
			wantErr:  assert.NoError,
		},
		{
			name:     "IPv6 with port",
			addr:     "[2001:db8::1]:8080",
			wantIP:   net.ParseIP("2001:db8::1"),
			wantPort: 8080,
			wantErr:  assert.NoError,
		},
		{
			name:     "IPv6 without port",
			addr:     "[2001:db8::1]",
			wantIP:   net.ParseIP("2001:db8::1"),
			wantPort: 53,
			wantErr:  assert.NoError,
		},
		{
			name:     "Invalid IPv4 address",
			addr:     "invalid:53",
			wantIP:   nil,
			wantPort: 0,
			wantErr:  assert.Error,
		},
		{
			name:     "Invalid IPv6 address",
			addr:     "invalid]:53",
			wantIP:   nil,
			wantPort: 0,
			wantErr:  assert.Error,
		},
		{
			name:     "Invalid port",
			addr:     "192.168.1.1:invalid",
			wantIP:   nil,
			wantPort: 0,
			wantErr:  assert.Error,
		},
		{
			name:     "Port out of range",
			addr:     "192.168.1.1:99999",
			wantIP:   nil,
			wantPort: 0,
			wantErr:  assert.Error,
		},
		{
			"missing closing bracket for IPv6 address",
			"[2001:db8::1:8080",
			nil,
			0,
			assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotNameserver, err := parseNameserverAddr(tt.addr)
			if !tt.wantErr(t, err, fmt.Sprintf("parseNameserverAddr(%v)", tt.addr)) {
				return
			}
			assert.Equalf(t, tt.wantIP, gotNameserver.IP, "parseNameserverAddr(%v)", tt.addr)
			assert.Equalf(t, tt.wantPort, gotNameserver.Port, "parseNameserverAddr(%v)", tt.addr)
		})
	}
}
