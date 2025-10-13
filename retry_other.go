//go:build !tinygo

package resty

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

func applyRetryDefaultConditions(res *Response, err error) bool {
	// no retry on TLS error
	if _, ok := err.(*tls.CertificateVerificationError); ok {
		return false
	}

	// validate url error, so we can decide to retry or not
	if u, ok := err.(*url.Error); ok {
		if regexErrTooManyRedirects.MatchString(u.Error()) {
			return false
		}
		if regexErrScheme.MatchString(u.Error()) {
			return false
		}
		if regexErrInvalidHeader.MatchString(u.Error()) {
			return false
		}
		return u.Temporary() // possible retry if it's true
	}

	if res == nil {
		return false
	}

	// certain HTTP status codes are temporary so that we can retry
	//	- 429 Too Many Requests
	//	- 500 or above (it's better to ignore 501 Not Implemented)
	//	- 0 No status code received
	if res.StatusCode() == http.StatusTooManyRequests ||
		(res.StatusCode() >= 500 && res.StatusCode() != http.StatusNotImplemented) ||
		res.StatusCode() == 0 {
		return true
	}

	return false
}
