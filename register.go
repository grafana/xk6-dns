package dns

import (
	"github.com/grafana/xk6-dns/dns"
	"go.k6.io/k6/js/modules"
)

// Register the extension on module initialization, available to
// import from JS as "k6/x/webcrypto".
func init() {
	modules.Register("k6/x/dns", new(dns.RootModule))
}
