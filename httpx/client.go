package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"

	"go.innotegrity.dev/cryptox"
	"go.innotegrity.dev/errorx"
	"go.innotegrity.dev/slogx"
)

// Client represents an HTTP client.
type Client struct {
	// ClientCertificates is a list of certificates to pass for client authentication.
	ClientCertificates []tls.Certificate

	// DisableSSLVerification disables HTTPS certificate verification when connecting to a server. You should
	// only do this if you are *really* sure. Otherwise, add the server's certificate to the RootCertificates
	// pool.
	DisableSSLVerification bool

	// RootCertificates is a pool of root CA certificates to trust.
	RootCertificates *cryptox.CertificatePool

	// unexported variables
	proxyConfig ProxyConfig // full proxy configuration settings
	getProxy    proxyFunc   // function to determine if URL requires proxying
}

// NewClient returns a new HTTP client object.
func NewClient(proxyConfig ProxyConfig) *Client {
	return &Client{
		ClientCertificates:     []tls.Certificate{},
		DisableSSLVerification: false,
		RootCertificates:       nil,
		proxyConfig:            proxyConfig,
		getProxy:               proxyConfig.ProxyFunc(),
	}
}

// Delete performs a DELETE request for the given URL and returns the raw body byte array.
//
// The following errors are returned by this function:
// ProxyError, RequestError, ResponseError
func (c *Client) Delete(ctx context.Context, url string, headers map[string]string, body []byte) (
	*http.Response, []byte, errorx.Error) {
	return c.doRequest(ctx, "DELETE", url, headers, body)
}

// Get performs a GET request for the given URL and returns the raw body byte array.
//
// The following errors are returned by this function:
// ProxyError, RequestError, ResponseError
func (c *Client) Get(ctx context.Context, url string, headers map[string]string) (
	*http.Response, []byte, errorx.Error) {
	return c.doRequest(ctx, "GET", url, headers, nil)
}

// Options performs an OPTIONS request for the given URL and returns the raw body byte array.
//
// The following errors are returned by this function:
// ProxyError, RequestError, ResponseError
func (c *Client) Options(ctx context.Context, url string, headers map[string]string) (
	*http.Response, []byte, errorx.Error) {
	return c.doRequest(ctx, "OPTIONS", url, headers, nil)
}

// Patch performs a PATCH request for the given URL and returns the raw body byte array.
//
// The following errors are returned by this function:
// ProxyError, RequestError, ResponseError
func (c *Client) Patch(ctx context.Context, url string, headers map[string]string, body []byte) (
	*http.Response, []byte, errorx.Error) {
	return c.doRequest(ctx, "PATCH", url, headers, body)
}

// Post performs a POST request for the given URL and returns the raw body byte array.
//
// The following errors are returned by this function:
// ProxyError, RequestError, ResponseError
func (c *Client) Post(ctx context.Context, url string, headers map[string]string, body []byte) (
	*http.Response, []byte, errorx.Error) {
	return c.doRequest(ctx, "POST", url, headers, body)
}

// Put performs a PUT request for the given URL and returns the raw body byte array.
//
// The following errors are returned by this function:
// ProxyError, RequestError, ResponseError
func (c *Client) Put(ctx context.Context, url string, headers map[string]string, body []byte) (
	*http.Response, []byte, errorx.Error) {
	return c.doRequest(ctx, "PUT", url, headers, body)
}

// NewRequest creates a new HTTP request object using any configured proxy information.
//
// Note that only HTTP Basic authentication is supported for proxied requests.
//
// The following errors are returned by this function:
// ProxyError, RequestError
func (c *Client) NewRequest(ctx context.Context, method, url string, body io.Reader) (
	*http.Client, *http.Request, errorx.Error) {

	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	// parse the URL passed in
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		e := NewRequestError(fmt.Sprintf("failed to parse %s request URL '%s'", method, url), url, method, err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, nil, e
	}

	// get any proxy URL required by our HTTP configuration
	proxyURL, err := c.getProxy(parsedURL)
	if err != nil {
		e := NewRequestError(fmt.Sprintf("failed to get proxy for %s request to URL '%s'", method, url), url, method, err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, nil, e
	}

	// add proxy authorization if required
	basicAuth := ""
	if proxyURL != nil {
		basicAuth = getProxyAuthorization(proxyURL, c.proxyConfig)
	}

	// configure HTTP transport object
	var rootCAs *x509.CertPool
	if c.RootCertificates != nil {
		rootCAs = c.RootCertificates.CertPool
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       c.ClientCertificates,
			RootCAs:            rootCAs,
			InsecureSkipVerify: c.DisableSSLVerification,
		},
		ProxyConnectHeader: http.Header{},
	}
	if proxyURL != nil {
		logger.Trace(fmt.Sprintf("using proxy URL: %s", proxyURL.String()), slog.String("url", url),
			slog.String("method", method))
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	if basicAuth != "" {
		transport.ProxyConnectHeader.Add("Proxy-Authorization", basicAuth)
		logger.Trace("added Proxy-Authorization header for CONNECT", slog.String("url", url),
			slog.String("method", method))
	}
	transport.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))

	// create a new HTTP client
	client := &http.Client{
		Transport: transport,
	}

	// create the request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		e := NewRequestError(fmt.Sprintf("failed to get create new %s request for URL '%s'", method, url),
			url, method, err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, nil, e
	}
	if basicAuth != "" {
		req.Header.Add("Proxy-Authorization", basicAuth)
		logger.Trace("added Proxy-Authorization header to request", slog.String("url", url),
			slog.String("method", method))
	}
	return client, req, nil
}

// doRequest handles performing the HTTP request and parsing the response.
//
// The following errors are returned by this function:
// ProxyError, RequestError, ResponseError
func (c *Client) doRequest(ctx context.Context, method string, url string, headers map[string]string, body []byte) (
	*http.Response, []byte, errorx.Error) {

	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	// create the request
	if body == nil {
		body = []byte{}
	}
	client, req, e := c.NewRequest(ctx, method, url, bytes.NewBuffer(body))
	if e != nil {
		return nil, nil, e
	}

	// add headers to request
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// perform the request
	resp, err := client.Do(req)
	if err != nil {
		e := NewRequestError(fmt.Sprintf("%s request to URL '%s' failed", method, url), url, method, err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return nil, nil, e
	}
	return c.parseResponse(ctx, method, url, resp)
}

// getProxyAuthorization returns the Basic Authorization header text if proxy authorization is required.
func getProxyAuthorization(proxyURL *neturl.URL, proxyConfig ProxyConfig) string {
	// HTTPS URLs
	if proxyURL.Scheme == "https" {
		if proxyConfig.HTTPSProxyUser != "" && proxyConfig.HTTPSProxyPass != "" {
			auth := fmt.Sprintf("%s:%s", proxyConfig.HTTPSProxyUser, proxyConfig.HTTPSProxyPass)
			return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(auth)))
		}
	}

	// HTTP URLs
	if proxyConfig.HTTPProxyUser != "" && proxyConfig.HTTPProxyPass != "" {
		auth := fmt.Sprintf("%s:%s", proxyConfig.HTTPProxyUser, proxyConfig.HTTPProxyPass)
		return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	// no credentials specified
	return ""
}

// parseResponse parses the response from the HTTP request and returns the raw byte body.
//
// The following errors are returned by this function:
// ResponseError
func (c *Client) parseResponse(ctx context.Context, method, url string, resp *http.Response) (*http.Response,
	[]byte, errorx.Error) {

	logger := slogx.ActiveLoggerFromContext(ctx)
	errAttr := slogx.ErrorAttrNameFromContext(ctx)

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		e := NewResponseError(fmt.Sprintf("failed to read response from %s request to URL '%s'", method, url),
			url, method, resp.StatusCode, err)
		logger.Error(e.Msg(), slogx.ErrX(errAttr, e))
		return resp, nil, e
	}
	return resp, body, nil
}
