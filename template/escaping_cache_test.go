package template

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/safehtml"
)

// executeOnce parses and executes a template a single time and returns its
// output and error.
func executeOnce(t *testing.T, input string, data interface{}) (string, error) {
	t.Helper()
	tmpl := Must(New("").Parse(stringConstant(input)))
	var b bytes.Buffer
	err := tmpl.Execute(&b, data)
	return b.String(), err
}

// TestDerivedTemplateCacheLinkRelIsolation verifies that a callee template
// referenced from two <link> elements with different rel values does not reuse
// the escaping result of the laxer context. A rel that permits safehtml.URL
// values must not cause a stylesheet href (which requires
// safehtml.TrustedResourceURL) to accept a safehtml.URL value.
func TestDerivedTemplateCacheLinkRelIsolation(t *testing.T) {
	const input = `{{define "url"}}{{.URL}}{{end}}` +
		`<link rel="preload" href="{{template "url" .}}">` +
		`<link rel="stylesheet" href="{{template "url" .}}">`
	data := struct{ URL safehtml.URL }{
		URL: safehtml.URLSanitized("https://example.com/style.css"),
	}
	out, err := executeOnce(t, input, data)
	if err == nil {
		t.Fatalf("expected an error for a safehtml.URL value in a stylesheet href, got output %q", out)
	}
	if !strings.Contains(err.Error(), "expected a safehtml.TrustedResourceURL value") {
		t.Fatalf("expected a TrustedResourceURL sanitizer error, got %v", err)
	}
}

// TestDerivedTemplateCacheLinkRelOrderIndependent verifies that the strict
// stylesheet chain is selected regardless of which <link> element is analyzed
// first.
func TestDerivedTemplateCacheLinkRelOrderIndependent(t *testing.T) {
	const input = `{{define "url"}}{{.URL}}{{end}}` +
		`<link rel="stylesheet" href="{{template "url" .}}">` +
		`<link rel="preload" href="{{template "url" .}}">`
	data := struct{ URL safehtml.URL }{
		URL: safehtml.URLSanitized("https://example.com/style.css"),
	}
	out, err := executeOnce(t, input, data)
	if err == nil {
		t.Fatalf("expected an error for a safehtml.URL value in a stylesheet href, got output %q", out)
	}
	if !strings.Contains(err.Error(), "expected a safehtml.TrustedResourceURL value") {
		t.Fatalf("expected a TrustedResourceURL sanitizer error, got %v", err)
	}
}

// TestDerivedTemplateCacheURLPrefixIsolation verifies that a callee used after
// a plain path prefix (URL normalization) and after a query-string prefix
// (query escaping) gets distinct escaping chains. Reserved characters such as
// '=' and '#' must be percent-encoded in the query part.
func TestDerivedTemplateCacheURLPrefixIsolation(t *testing.T) {
	const input = `{{define "p"}}{{.X}}{{end}}` +
		`<a href="/path/{{template "p" .}}"></a>` +
		`<a href="/search?q={{template "p" .}}"></a>`
	data := struct{ X string }{X: "a=b#frag"}
	out, err := executeOnce(t, input, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `<a href="/path/a=b#frag"></a>` +
		`<a href="/search?q=a%3db%23frag"></a>`
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// TestDerivedTemplateCacheURLPrefixIsolationReversedOrder verifies that the
// query-escaping chain is still applied when the query-prefix call site is
// analyzed first.
func TestDerivedTemplateCacheURLPrefixIsolationReversedOrder(t *testing.T) {
	const input = `{{define "p"}}{{.X}}{{end}}` +
		`<a href="/search?q={{template "p" .}}"></a>` +
		`<a href="/path/{{template "p" .}}"></a>`
	data := struct{ X string }{X: "a=b#frag"}
	out, err := executeOnce(t, input, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `<a href="/search?q=a%3db%23frag"></a>` +
		`<a href="/path/a=b#frag"></a>`
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// TestDerivedTemplateCacheAmbiguousValueIsolation verifies that an ambiguous
// URL prefix produced by joining conditional branches is not confused with an
// unambiguous prefix of the same textual value.
func TestDerivedTemplateCacheAmbiguousValueIsolation(t *testing.T) {
	// In the first call site the prefix "/path/" is fixed text, so a URL
	// normalizer is sufficient. In the second the prefix comes from branches
	// that produce different values, which joins into an ambiguous prefix and
	// must reject actions after it.
	const input = `{{define "p"}}{{.X}}{{end}}` +
		`<a href="/path/{{template "p" .}}"></a>` +
		`<a href="{{if .C}}/path/{{else}}/other/{{end}}{{template "p" .}}"></a>`
	out, err := executeOnce(t, input, struct {
		C bool
		X string
	}{C: true, X: "a=b"})
	if err == nil {
		t.Fatalf("expected an ambiguous URL prefix error, got output %q", out)
	}
	if !strings.Contains(err.Error(), "actions must not occur after an ambiguous URL prefix") {
		t.Fatalf("expected an ambiguous URL prefix error, got %v", err)
	}
}

// TestDerivedTemplateCacheScriptTypeIsolation verifies that two script
// elements with different type attributes derive distinct templates, even
// though their state, delimiter, attribute and element names are identical.
func TestDerivedTemplateCacheScriptTypeIsolation(t *testing.T) {
	const input = `{{define "s"}}{{.X}}{{end}}` +
		`<script type="text/javascript">{{template "s" .}}</script>` +
		`<script type="text/template">{{template "s" .}}</script>`
	tmpl := Must(New("").Parse(stringConstant(input)))
	if err := tmpl.Execute(&bytes.Buffer{}, struct{ X string }{X: "alert(1)"}); err == nil {
		t.Fatal("expected a sanitization error for a string in a script element body")
	}
	// The two call sites must produce distinct derived templates rather than
	// sharing a single mangled name.
	var names []string
	for name := range tmpl.esc.derived {
		if strings.HasPrefix(name, "s$htmltemplate_") {
			names = append(names, name)
		}
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 distinct derived script templates, got %v", names)
	}
}
