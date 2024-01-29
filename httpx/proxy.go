package httpx

import (
	"net/url"

	"golang.org/x/net/http/httpproxy"
)

// proxyFunc returns a function that can be used to determine the proper proxy URL for a request.
type proxyFunc func(*url.URL) (*url.URL, error)

// ProxyConfig holds the full configuration for proxy settings used by HTTP clients.
type ProxyConfig struct {
	httpproxy.Config

	// HTTPProxyUser is the username for proxy authentication for HTTP URLs.
	HTTPProxyUser string

	// HTTPProxyPass is the password for proxy authentication for HTTP URLs.
	HTTPProxyPass string

	// HTTPSProxyUser is the username for proxy authentication for HTTPS URLs.
	HTTPSProxyUser string

	// HTTPSProxyPass is the password for proxy authentication for HTTPS URLs.
	HTTPSProxyPass string
}
