//go:build tinygo

package resty

import (
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"

	"resty.dev/v3/cookiejar"
	"resty.dev/v3/publicsuffix"
)

// Version # of resty
const Version = "3.0.0-beta.1"

// New method creates a new Resty client.
func New() *Client {
	return NewWithTransportSettings(nil)
}

// NewWithDialerAndTransportSettings method creates a new Resty client with given Local Address
// to dial from.
func NewWithTransportSettings(ransportSettings *TransportSettings) *Client {
	jar := createCookieJar()
	transport := createTransport(nil, ransportSettings)
	transport.Jar = jar
	return createClient(&http.Client{
		Jar:       jar,
		Transport: transport,
	})
}

// NewWithClient method creates a new Resty client with given [http.Client].
func NewWithClient(hc *http.Client) *Client {
	return createClient(hc)
}

func createTransport(_ *net.Dialer, _ *TransportSettings) *AdvancedTransport {
	return &AdvancedTransport{}
}

func createCookieJar() *cookiejar.Jar {
	cookieJar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return cookieJar
}

// 覆盖 createClient 以使用 AdvancedTransport
func createClient(hc *http.Client) *Client {
	// 防止多次包装
	if _, ok := hc.Transport.(*AdvancedTransport); !ok {
		hc.Transport = &AdvancedTransport{
			Transport: hc.Transport,
			Jar:       hc.Jar,
		}
	}

	c := &Client{ // not setting language default values
		lock:                     &sync.RWMutex{},
		queryParams:              url.Values{},
		formData:                 url.Values{},
		header:                   http.Header{},
		authScheme:               defaultAuthScheme,
		cookies:                  make([]*http.Cookie, 0),
		retryWaitTime:            defaultWaitTime,
		retryMaxWaitTime:         defaultMaxWaitTime,
		isRetryDefaultConditions: true,
		pathParams:               make(map[string]string),
		headerAuthorizationKey:   hdrAuthorizationKey,
		jsonEscapeHTML:           true,
		httpClient:               hc,
		debugBodyLimit:           math.MaxInt32,
		contentTypeEncoders:      make(map[string]ContentTypeEncoder),
		contentTypeDecoders:      make(map[string]ContentTypeDecoder),
		contentDecompresserKeys:  make([]string, 0),
		contentDecompressers:     make(map[string]ContentDecompresser),
		certWatcherStopChan:      make(chan bool),
	}

	// Logger
	c.SetLogger(createLogger())
	c.SetDebugLogFormatter(DebugLogFormatter)

	c.AddContentTypeEncoder(jsonKey, encodeJSON)
	c.AddContentTypeEncoder(xmlKey, encodeXML)

	c.AddContentTypeDecoder(jsonKey, decodeJSON)
	c.AddContentTypeDecoder(xmlKey, decodeXML)

	// Order matter, giving priority to gzip
	c.AddContentDecompresser("deflate", decompressDeflate)
	c.AddContentDecompresser("gzip", decompressGzip)

	// request middlewares
	c.SetRequestMiddlewares(
		PrepareRequestMiddleware,
	)

	// response middlewares
	c.SetResponseMiddlewares(
		AutoParseResponseMiddleware,
		SaveToFileResponseMiddleware,
	)

	return c
}
