//go:build tinygo

package resty

import "errors"

// ErrUseLastResponse is returned by CheckRedirect functions to tell the
// client to stop redirection and return the last response.
// TinyGo's http package does not include this, so we define it ourselves.
var ErrUseLastResponse = errors.New("net/http: use last response")
