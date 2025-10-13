package cookiejar

import (
	"errors"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// ParseCookie parses a Cookie header value and returns all the cookies
// which were set in it.
func ParseCookie(line string) ([]*http.Cookie, error) {
	parts := strings.Split(textproto.TrimString(line), ";")
	if len(parts) == 1 && parts[0] == "" {
		return nil, errors.New("http: blank cookie")
	}
	cookies := make([]*http.Cookie, 0, len(parts))
	for _, s := range parts {
		s = textproto.TrimString(s)
		name, value, found := strings.Cut(s, "=")
		if !found {
			return nil, errors.New("http: '=' not found in cookie")
		}
		if !isToken(name) {
			return nil, errors.New("http: invalid cookie name")
		}
		value, _, found = parseCookieValue(value, true)
		if !found {
			return nil, errors.New("http: invalid cookie value")
		}
		cookies = append(cookies, &http.Cookie{Name: name, Value: value})
	}
	return cookies, nil
}

// ParseSetCookie parses a Set-Cookie header value and returns a cookie.
func ParseSetCookie(line string) (*http.Cookie, error) {
	parts := strings.Split(textproto.TrimString(line), ";")
	if len(parts) == 1 && parts[0] == "" {
		return nil, errors.New("http: blank cookie")
	}
	parts[0] = textproto.TrimString(parts[0])
	name, value, ok := strings.Cut(parts[0], "=")
	if !ok {
		return nil, errors.New("http: '=' not found in cookie")
	}
	name = textproto.TrimString(name)
	if !isToken(name) {
		return nil, errors.New("http: invalid cookie name")
	}
	value, _, ok = parseCookieValue(value, true)
	if !ok {
		return nil, errors.New("http: invalid cookie value")
	}
	c := &http.Cookie{
		Name:  name,
		Value: value,
		Raw:   line,
	}
	for i := 1; i < len(parts); i++ {
		parts[i] = textproto.TrimString(parts[i])
		if len(parts[i]) == 0 {
			continue
		}

		attr, val, _ := strings.Cut(parts[i], "=")
		lowerAttr := strings.ToLower(attr)
		val, _, ok = parseCookieValue(val, false)
		if !ok {
			c.Unparsed = append(c.Unparsed, parts[i])
			continue
		}

		switch lowerAttr {
		case "samesite":
			lowerVal := strings.ToLower(val)
			switch lowerVal {
			case "lax":
				c.SameSite = http.SameSiteLaxMode
			case "strict":
				c.SameSite = http.SameSiteStrictMode
			case "none":
				c.SameSite = http.SameSiteNoneMode
			default:
				c.SameSite = http.SameSiteDefaultMode
			}
			continue
		case "secure":
			c.Secure = true
			continue
		case "httponly":
			c.HttpOnly = true
			continue
		case "domain":
			c.Domain = val
			continue
		case "max-age":
			secs, err := strconv.Atoi(val)
			if err != nil || secs != 0 && val[0] == '0' {
				break
			}
			if secs <= 0 {
				secs = -1
			}
			c.MaxAge = secs
			continue
		case "expires":
			c.RawExpires = val
			exptime, err := time.Parse(time.RFC1123, val)
			if err != nil {
				exptime, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", val)
				if err != nil {
					c.Expires = time.Time{}
					break
				}
			}
			c.Expires = exptime.UTC()
			continue
		case "path":
			c.Path = val
			continue
		}
		c.Unparsed = append(c.Unparsed, parts[i])
	}
	return c, nil
}
