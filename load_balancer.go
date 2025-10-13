// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

// LoadBalancer is the interface that wraps the HTTP client load-balancing
// algorithm that returns the "Next" Base URL for the request to target
type LoadBalancer interface {
	Next() (string, error)
	Feedback(*RequestFeedback)
	Close() error
}

// RequestFeedback struct is used to send the request feedback to load balancing
// algorithm
type RequestFeedback struct {
	BaseURL string
	Success bool
	Attempt int
}
