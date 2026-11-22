// Copyright (c) 2017 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package safehtmlutil contains functions shared by package safehtml and safehtml/template.
package safehtmlutil

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

// IsSafeTrustedResourceURLPrefix returns whether the given prefix is safe to use as a
// TrustedResourceURL prefix.
//
// TrustedResourceURL prefixes must start with one of the following:
//   - `https://<origin>/`
//   - `//<origin>/`
//   - `/<pathStart>`
//   - `about:blank#`
//
// `<origin>` must contain only alphanumerics, '.', ':', '[', ']', or '-'.
// These restrictions do not enforce a well-formed domain name, so '.' and '1.2' are valid.
//
// `<pathStart>` is any character except `/` and `\`. Based on
// https://url.spec.whatwg.org/commit-snapshots/56b74ce7cca8883eab62e9a12666e2fac665d03d/#url-parsing,
// an initial / which is not followed by another / or \ will end up in the "path state" and from there
// it can only go to the "fragment state" and "query state".
func IsSafeTrustedResourceURLPrefix(prefix string) bool {
	return safeTrustedResourceURLPrefixPattern.MatchString(prefix)
}

var safeTrustedResourceURLPrefixPattern = regexp.MustCompile(`(?i)^(?:` +
	`(?:https:)?//[0-9a-z.:\[\]-]+/|` +
	`/[^/\\]|` +
	`about:blank#)`)

// URLContainsDoubleDotSegment returns whether the given URL or URL substring
// contains the double dot-segment ".." (RFC3986 3.3) in its percent-encoded or
// unencoded form.
func URLContainsDoubleDotSegment(url string) bool {
	return urlDoubleDotSegmentPattern.MatchString(url)
}

var urlDoubleDotSegmentPattern = regexp.MustCompile(`(?i)(?:\.|%2e)(?:\.|%2e)`)

// TrustedResourceURLContainsDoubleDotSegment reports whether url contains a ".."
// dot-segment (RFC3986 3.3) in its path component, in either percent-encoded or
// unencoded form.
//
// Unlike URLContainsDoubleDotSegment, this operates on the fully assembled URL rather
// than on the individual, not-yet-substituted values. Checking the assembled result
// enforces the TrustedResourceURL contract at the correct granularity: a ".."
// dot-segment assembled across substitution or append boundaries is rejected just like
// one contained in a single value, while dot characters that remain part of legitimate
// file names or version segments (e.g. "main.html", "v1.2") are left untouched.
//
// The query and fragment components are ignored, since dot-segments there do not affect
// the path hierarchy.
func TrustedResourceURLContainsDoubleDotSegment(url string) bool {
	path := trustedResourceURLPath(url)
	return URLContainsDoubleDotSegment(path)
}

// trustedResourceURLPath returns the path component of url, stripping any scheme and
// authority prefix as well as the query and fragment components.
func trustedResourceURLPath(url string) string {
	// Discard the query and fragment components.
	for i := 0; i < len(url); i++ {
		if url[i] == '?' || url[i] == '#' {
			url = url[:i]
			break
		}
	}
	// Discard the scheme and authority in absolute URLs ("https://example.com/path" or
	// "//example.com/path") so that dots in the host name are not mistaken for path
	// dot-segments.
	if rest, ok := stripSchemeAndAuthority(url); ok {
		return rest
	}
	return url
}

// stripSchemeAndAuthority removes any leading scheme and "//authority" component from
// url. It reports false if url has no authority component.
func stripSchemeAndAuthority(url string) (string, bool) {
	rest := url
	if i := strings.IndexByte(rest, ':'); i != -1 {
		// Only treat the prefix as a scheme if it starts with a letter and contains
		// solely scheme characters, per RFC3986 Section 3.1.
		scheme := rest[:i]
		if len(scheme) != 0 && isSchemeStart(scheme[0]) {
			isScheme := true
			for j := 1; j < len(scheme); j++ {
				if !isSchemeChar(scheme[j]) {
					isScheme = false
					break
				}
			}
			if isScheme {
				rest = rest[i+1:]
			}
		}
	}
	if !strings.HasPrefix(rest, "//") {
		return url, false
	}
	rest = rest[2:]
	if i := strings.IndexByte(rest, '/'); i != -1 {
		return rest[i:], true
	}
	// The URL consists solely of an authority and has no path.
	return "", true
}

func isSchemeStart(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func isSchemeChar(c byte) bool {
	return isSchemeStart(c) || '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'
}

// QueryEscapeURL produces an output that can be embedded in a URL query.
// The output can be embedded in an HTML attribute without further escaping.
func QueryEscapeURL(args ...interface{}) string {
	return urlProcessor(false, Stringify(args...))
}

// NormalizeURL normalizes URL content so it can be embedded in a quote-delimited
// string or parenthesis delimited url(...).
// The normalizer does not encode all HTML specials. Specifically, it does not
// encode '&' so correct embedding in an HTML attribute requires escaping of
// '&' to '&amp;'.
func NormalizeURL(args ...interface{}) string {
	return urlProcessor(true, Stringify(args...))
}

// urlProcessor normalizes (when norm is true) or escapes its input to produce
// a valid hierarchical or opaque URL part.
func urlProcessor(norm bool, s string) string {
	var b bytes.Buffer
	written := 0
	// The byte loop below assumes that all URLs use UTF-8 as the
	// content-encoding. This is similar to the URI to IRI encoding scheme
	// defined in section 3.1 of  RFC 3987, and behaves the same as the
	// EcmaScript builtin encodeURIComponent.
	// It should not cause any misencoding of URLs in pages with
	// Content-type: text/html;charset=UTF-8.
	for i, n := 0, len(s); i < n; i++ {
		c := s[i]
		switch c {
		// Single quote and parens are sub-delims in RFC 3986, but we
		// escape them so the output can be embedded in single
		// quoted attributes and unquoted CSS url(...) constructs.
		// Single quotes are reserved in URLs, but are only used in
		// the obsolete "mark" rule in an appendix in RFC 3986
		// so can be safely encoded.
		case '!', '#', '$', '&', '*', '+', ',', '/', ':', ';', '=', '?', '@', '[', ']':
			if norm {
				continue
			}
		// Unreserved according to RFC 3986 sec 2.3
		// "For consistency, percent-encoded octets in the ranges of
		// ALPHA (%41-%5A and %61-%7A), DIGIT (%30-%39), hyphen (%2D),
		// period (%2E), underscore (%5F), or tilde (%7E) should not be
		// created by URI producers
		case '-', '.', '_', '~':
			continue
		case '%':
			// When normalizing do not re-encode valid escapes.
			if norm && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				continue
			}
		default:
			// Unreserved according to RFC 3986 sec 2.3
			if 'a' <= c && c <= 'z' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
		}
		b.WriteString(s[written:i])
		fmt.Fprintf(&b, "%%%02x", c)
		written = i + 1
	}
	if written == 0 {
		return s
	}
	b.WriteString(s[written:])
	return b.String()
}

// isHex reports whether the given character is a hex digit.
func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// Stringify converts its arguments to a string. It is equivalent to
// fmt.Sprint(args...), except that it deferences all pointers.
func Stringify(args ...interface{}) string {
	// Optimization for simple common case of a single string argument.
	if len(args) == 1 {
		if s, ok := args[0].(string); ok {
			return s
		}
	}
	for i, arg := range args {
		args[i] = indirectToStringerOrError(arg)
	}
	return fmt.Sprint(args...)
}

var (
	errorType       = reflect.TypeOf((*error)(nil)).Elem()
	fmtStringerType = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
)

// indirectToStringerOrError dereferences a as many times
// as necessary to reach the base type, an implementation of fmt.Stringer,
// or an implementation of error, and returns a value of that type. It returns
// nil if a is nil.
func indirectToStringerOrError(a interface{}) interface{} {
	if a == nil {
		return nil
	}
	v := reflect.ValueOf(a)
	for !v.Type().Implements(fmtStringerType) && !v.Type().Implements(errorType) && v.Kind() == reflect.Ptr && !v.IsNil() {
		v = v.Elem()
	}
	return v.Interface()
}

// Indirect returns the value, after dereferencing as many times
// as necessary to reach the base type (or nil).
func Indirect(a interface{}) interface{} {
	if a == nil {
		return nil
	}
	if t := reflect.TypeOf(a); t.Kind() != reflect.Ptr {
		// Avoid creating a reflect.Value if it's not a pointer.
		return a
	}
	v := reflect.ValueOf(a)
	for v.Kind() == reflect.Ptr && !v.IsNil() {
		v = v.Elem()
	}
	return v.Interface()
}
