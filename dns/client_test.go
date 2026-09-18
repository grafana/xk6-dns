package dns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_fmtNAPTRAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		answer *dns.NAPTR
		want   string
	}{
		{
			name: "typical ENUM SIP rewrite",
			answer: &dns.NAPTR{
				Order:       100,
				Preference:  10,
				Flags:       "U",
				Service:     "E2U+sip",
				Regexp:      "!^.*$!sip:customer-service@example.com!",
				Replacement: ".",
			},
			want: `100 10 "U" "E2U+sip" "!^.*$!sip:customer-service@example.com!" .`,
		},
		{
			name: "escapes quotes inside regexp",
			answer: &dns.NAPTR{
				Order:       100,
				Preference:  10,
				Flags:       "U",
				Service:     "E2U+sip",
				Regexp:      `!^.*$!sip:"quoted"@example.com!`,
				Replacement: ".",
			},
			want: `100 10 "U" "E2U+sip" "!^.*$!sip:\"quoted\"@example.com!" .`,
		},
		{
			name: "escapes backslash inside regexp",
			answer: &dns.NAPTR{
				Order:       100,
				Preference:  10,
				Flags:       "",
				Service:     "",
				Regexp:      `!^urn:cid:.+@([^\.]+\.)(.*)$!\2!i`,
				Replacement: ".",
			},
			want: `100 10 "" "" "!^urn:cid:.+@([^\\.]+\\.)(.*)$!\\2!i" .`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, fmtNAPTRAnswer(tt.answer))
		})
	}
}
