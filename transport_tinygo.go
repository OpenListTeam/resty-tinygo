package resty

import (
	"errors"
	"fmt"
	"net/http"
)

// AdvancedTransport is a wrapper around http.RoundTripper that adds
// cookie and redirect handling for TinyGo.
type AdvancedTransport struct {
	Transport     http.RoundTripper
	Jar           http.CookieJar
	CheckRedirect func(req *http.Request, via []*http.Request) error
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func (t *AdvancedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	var via []*http.Request
	checkRedirect := t.CheckRedirect
	if checkRedirect == nil {
		checkRedirect = defaultCheckRedirect
	}

	for {
		reqClone := req.Clone(req.Context())
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			reqClone.Body = body
		}
		via = append(via, reqClone)

		if t.Jar != nil {
			for _, cookie := range t.Jar.Cookies(req.URL) {
				req.AddCookie(cookie)
			}
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		if t.Jar != nil {
			if rc := resp.Cookies(); len(rc) > 0 {
				t.Jar.SetCookies(req.URL, rc)
			}
		}

		if !isRedirect(resp.StatusCode) {
			return resp, nil
		}

		err = checkRedirect(req, via)
		if err != nil {
			if errors.Is(err, ErrUseLastResponse) {
				return resp, nil
			}
			resp.Body.Close()
			return nil, err
		}

		loc, err := resp.Location()
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to get redirect location: %w", err)
		}

		resp.Body.Close()

		lastReq := via[len(via)-1]
		var nextReq *http.Request

		if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
			nextReq, err = http.NewRequest("GET", loc.String(), nil)
			if err != nil {
				return nil, err
			}

			nextReq.Header = cloneHeader(lastReq.Header)
			nextReq.Header.Del("Content-Length")
			nextReq.Header.Del("Content-Type")
			nextReq.Header.Del("Transfer-Encoding")
		} else {
			body, err := lastReq.GetBody()
			if err != nil {
				return nil, err
			}
			nextReq, err = http.NewRequest(lastReq.Method, loc.String(), body)
			if err != nil {
				return nil, err
			}
			nextReq.Header = cloneHeader(lastReq.Header)
		}

		if loc.Host != req.URL.Host {
			nextReq.Header.Del("Authorization")
			nextReq.Header.Del("Cookie")
		}

		req = nextReq
	}
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func defaultCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}
