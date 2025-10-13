//go:build !tinygo

package resty

import "net/http"

var ErrUseLastResponse = http.ErrUseLastResponse
