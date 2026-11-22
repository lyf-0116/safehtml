// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"text/template/parse"

	"github.com/google/safehtml"
	"github.com/google/safehtml/internal/safehtmlutil"
)

// urlPrefixValidators maps URL and TrustedResourceURL sanitization contexts to functions return an error
// if the given string is unsafe to use as a URL prefix in that sanitization context.
var urlPrefixValidators = map[sanitizationContext]func(string) error{
	sanitizationContextURL:                     validateURLPrefix,
	sanitizationContextTrustedResourceURLOrURL: validateURLPrefix,
	sanitizationContextTrustedResourceURL:      validateTrustedResourceURLPrefix,
}

// startsWithFullySpecifiedSchemePattern matches strings that have a fully-specified scheme component.
// See RFC 3986 Section 3.
var startsWithFullySpecifiedSchemePattern = regexp.MustCompile(
	`^[[:alpha:]](?:[[:alnum:]]|[+.-])*:`)

// validateURLPrefix validates if the given non-empty prefix is a safe safehtml.URL prefix.
//
// Prefixes are considered unsafe if they end in an incomplete HTML character reference
// or percent-encoding character triplet.
//
// If the prefix contains a fully-specified scheme component, it is considered safe only if
// it starts with an allowed scheme. See safehtml.URLSanitized for more details.
//
// Otherwise, the prefix is safe only if it contains '/', '?', or '#', since the presence of any
// of these runes ensures that this prefix, when combined with some arbitrary suffix, cannot be
// interpreted as a part of a scheme.
func validateURLPrefix(prefix string) error {
	decoded, err := decodeURLPrefix(prefix)
	if err != nil {
		return err
	}
	switch {
	case startsWithFullySpecifiedSchemePattern.MatchString(decoded):
		if safehtml.URLSanitized(decoded).String() != decoded {
			return fmt.Errorf("URL prefix %q contains an unsafe scheme", prefix)
		}
	case !strings.ContainsAny(decoded, "/?#"):
		// If the URL prefix does not already have a ':' scheme delimiter, and does not contain
		// '/', '?', or '#', any ':' following this prefix will be intepreted as a scheme
		// delimiter, causing this URL prefix to be interpreted as being part of a scheme.
		// e.g. `<a href="java{{ "script:" }}alert(1)>`
		return fmt.Errorf("URL prefix %q is unsafe; it might be interpreted as part of a scheme", prefix)
	}
	return nil
}

// validateTrustedResourceURLPrefix validates if the given non-empty prefix is a safe
// safehtml.TrustedResourceURL prefix.
//
// Prefixes are considered unsafe if they end in an incomplete HTML character reference
// or percent-encoding character triplet.
//
// See safehtmlutil.IsSafeTrustedResourceURLPrefix for details on how the prefix is validated.
func validateTrustedResourceURLPrefix(prefix string) error {
	decoded, err := decodeURLPrefix(prefix)
	if err != nil {
		return err
	}
	if !safehtmlutil.IsSafeTrustedResourceURLPrefix(decoded) {
		return fmt.Errorf("%q is a disallowed TrustedResourceURL prefix", prefix)
	}
	return nil
}

// endsWithPercentEncodingPrefixPattern matches strings that end in an incomplete
// URL percent encoding triplet.
//
// See https://tools.ietf.org/html/rfc3986#section-2.1.
var endsWithPercentEncodingPrefixPattern = regexp.MustCompile(
	`%[[:xdigit:]]?$`)

// containsWhitespaceOrControlPattern matches strings that contain ASCII whitespace
// or control characters.
var containsWhitespaceOrControlPattern = regexp.MustCompile(`[[:space:]]|[[:cntrl:]]`)

// decodeURLPrefix returns the given prefix after it has been HTML-unescaped.
// It returns an error if the prefix:
//   - ends in an incomplete HTML character reference before HTML-unescaping,
//   - ends in an incomplete percent-encoding character triplet after HTML-unescaping, or
//   - contains whitespace before or after HTML-unescaping.
func decodeURLPrefix(prefix string) (string, error) {
	if containsWhitespaceOrControlPattern.MatchString(prefix) {
		return "", fmt.Errorf("URL prefix %q contains whitespace or control characters", prefix)
	}
	if err := validateDoesNotEndsWithCharRefPrefix(prefix); err != nil {
		return "", fmt.Errorf("URL %s", err)
	}
	decoded := html.UnescapeString(prefix)
	// Check again for whitespace that might have previously been masked by a HTML reference,
	// such as in "javascript&NewLine;".
	if containsWhitespaceOrControlPattern.MatchString(decoded) {
		return "", fmt.Errorf("URL prefix %q contains whitespace or control characters", prefix)
	}
	if endsWithPercentEncodingPrefixPattern.MatchString(decoded) {
		return "", fmt.Errorf("URL prefix %q ends with an incomplete percent-encoding character triplet", prefix)
	}
	return decoded, nil
}

func validateTrustedResourceURLSubstitution(args ...interface{}) (string, error) {
	input := safehtmlutil.Stringify(args...)
	if safehtmlutil.URLContainsDoubleDotSegment(input) {
		// Reject substitutions containing the ".." dot-segment to prevent the final TrustedResourceURL from referencing
		// a resource higher up in the path name hierarchy than the path specified in the prefix.
		return "", fmt.Errorf(`cannot substitute %q after TrustedResourceURL prefix: ".." is disallowed`, input)
	}
	return input, nil
}

// validateTrustedResourceURLAction guards against ".." dot-segments assembled across
// adjacent actions in a TrustedResourceURL attribute value. The per-action
// validateTrustedResourceURLSubstitution check only inspects each action value in
// isolation, so two adjacent actions each contributing a single dot (e.g.
// `<link href="/path/{{ "." }}{{ "." }}">`) would otherwise pass validation while their
// concatenated output contains "..".
//
// A string-constant action that ends in "." establishes a pending dot boundary. The next
// adjacent action then fails if it can start with a dot: a string-constant action is known
// exactly, while a non-constant action can produce any runtime value and is therefore
// treated as able to start with a dot. Any static text between actions clears the pending
// boundary, and a fully static ".." in the constant template prefix or ordinary file names
// such as "main.html" are never affected.
func validateTrustedResourceURLAction(c context, n *parse.ActionNode) (context, bool) {
	if c.state != stateAttr || sanitizationContextForAttrValOrError(c) != sanitizationContextTrustedResourceURL {
		return c, true
	}
	// Only actions after a non-empty, validated TrustedResourceURL prefix are
	// query-escaped substitutions. An action that supplies the whole URL value is handled
	// by sanitizeTrustedResourceURL instead.
	if c.attr.value == "" || strings.ContainsAny(c.attr.value, "#?") {
		return c, true
	}
	leadingDot := actionMayStartWithDot(n)
	if c.attr.trURLDotBoundary == trURLDotBoundaryDynamicDot && leadingDot {
		return context{
			state: stateError,
			err:   errorf(ErrEscapeAction, n, n.Line, `cannot escape action %v: adjacent actions in a TrustedResourceURL attribute value must not combine into a ".." dot-segment`, n),
		}, false
	}
	// Only a string-constant action is known to end in a dot. For any other action the
	// runtime value is unknown, so it is not treated as a pending dot boundary: doing so
	// would conservatively reject ordinary adjacent dynamic substitutions such as
	// `{{ .Dir }}{{ .File }}` even though they normally do not produce a ".." dot-segment.
	if s, ok := actionStringConstant(n); ok && strings.HasSuffix(s, ".") {
		c.attr.trURLDotBoundary = trURLDotBoundaryDynamicDot
	} else {
		c.attr.trURLDotBoundary = trURLDotBoundaryNone
	}
	return c, true
}

// sanitizationContextForAttrValOrError returns the sanitization context of the attribute
// in context c, or sanitizationContextNone if it cannot be determined.
func sanitizationContextForAttrValOrError(c context) sanitizationContext {
	sc, err := sanitizationContextForAttrVal(c.element.name, c.attr.name, c.linkRel)
	if err != nil {
		return sanitizationContextNone
	}
	return sc
}

// actionMayStartWithDot reports whether the dynamic value produced by n could start with
// a dot. A non-constant action can produce any value and is therefore assumed to be able
// to start with a dot; a string-constant action is known exactly.
func actionMayStartWithDot(n *parse.ActionNode) bool {
	if s, ok := actionStringConstant(n); ok {
		return strings.HasPrefix(s, ".")
	}
	return true
}

// actionStringConstant returns the value of n if n consists solely of a string-constant
// pipeline command, such as `{{ "." }}`.
func actionStringConstant(n *parse.ActionNode) (string, bool) {
	if n.Pipe == nil || len(n.Pipe.Cmds) != 1 || len(n.Pipe.Decl) != 0 {
		return "", false
	}
	args := n.Pipe.Cmds[0].Args
	if len(args) != 1 {
		return "", false
	}
	s, ok := args[0].(*parse.StringNode)
	if !ok {
		return "", false
	}
	return s.Text, true
}
