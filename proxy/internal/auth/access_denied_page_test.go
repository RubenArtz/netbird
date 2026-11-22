package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/geolocation"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
)

// denyPageGeo is a stub restrict.GeoResolver mapping stringified IPs to
// country codes.
type denyPageGeo struct {
	countries map[string]string
}

func (g *denyPageGeo) LookupAddr(addr netip.Addr) geolocation.Result {
	return geolocation.Result{CountryCode: g.countries[addr.Unmap().String()]}
}

func (g *denyPageGeo) Available() bool { return true }

// denyPageCrowdSec is a stub restrict.CrowdSecChecker with canned decisions.
type denyPageCrowdSec struct {
	decisions map[string]restrict.DecisionType
	ready     bool
}

func (m *denyPageCrowdSec) CheckIP(addr netip.Addr) *restrict.CrowdSecDecision {
	if d, ok := m.decisions[addr.Unmap().String()]; ok {
		return &restrict.CrowdSecDecision{Type: d}
	}
	return nil
}

func (m *denyPageCrowdSec) Ready() bool { return m.ready }

// denyPageHandler serves Protect with a flag recording whether the request
// reached the upstream handler.
func denyPageHandler(t *testing.T, mw *Middleware, host string, reached *bool) http.Handler {
	t.Helper()
	return mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))
}

func denyPageRequest(t *testing.T, handler http.Handler, host, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	req.RemoteAddr = remoteAddr
	req.Host = host
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// assertBrandedAccessDenied checks the denial contract: 403, HTML content
// type, the generic branded title, and none of the internal strings.
func assertBrandedAccessDenied(t *testing.T, rec *httptest.ResponseRecorder, forbidden ...string) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"),
		"denial must be HTML, got %q", rec.Header().Get("Content-Type"))
	body := rec.Body.String()
	assert.Contains(t, body, "Access Denied")
	assert.Contains(t, body, "You are not authorized to access this service")
	for _, s := range forbidden {
		assert.NotContains(t, body, s, "denial page must not leak internal details")
	}
}

func TestAccessDeniedPage_CountryRestriction(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, &denyPageGeo{countries: map[string]string{
		"203.0.113.7":  "DE",
		"198.51.100.9": "US",
	}})
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCountries: []string{"US"}})
	require.NoError(t, mw.AddDomain("example.com", nil, "", 0, "acct-1", "svc-1", filter, false, nil))

	var reached bool
	handler := denyPageHandler(t, mw, "example.com", &reached)
	rec := denyPageRequest(t, handler, "example.com", "203.0.113.7:5678")

	assertBrandedAccessDenied(t, rec, "country_restricted", "geo_unavailable", "DE", "203.0.113.7")
	assert.False(t, reached, "denied request must not reach the upstream")
	assert.Empty(t, rec.Header().Get("Connection"), "public denial must not close the connection")

	// An allowed country still passes through to the backend.
	reached = false
	rec = denyPageRequest(t, handler, "example.com", "198.51.100.9:5678")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached, "allowed request must reach the upstream")
}

func TestAccessDeniedPage_CIDRRestriction(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, mw.AddDomain("example.com", nil, "", 0, "acct-1", "svc-1", filter, false, nil))

	var reached bool
	handler := denyPageHandler(t, mw, "example.com", &reached)
	rec := denyPageRequest(t, handler, "example.com", "192.168.1.1:5678")

	assertBrandedAccessDenied(t, rec, "ip_restricted", "192.168.1.1")
	assert.False(t, reached, "denied request must not reach the upstream")
}

func TestAccessDeniedPage_CrowdSecEnforce(t *testing.T) {
	tests := []struct {
		name     string
		decision restrict.DecisionType
		verdict  string
	}{
		{"ban", restrict.DecisionBan, "crowdsec_ban"},
		{"captcha", restrict.DecisionCaptcha, "crowdsec_captcha"},
		{"throttle", restrict.DecisionThrottle, "crowdsec_throttle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewMiddleware(log.StandardLogger(), nil, nil)
			cs := &denyPageCrowdSec{decisions: map[string]restrict.DecisionType{"1.2.3.4": tt.decision}, ready: true}
			filter := restrict.ParseFilter(restrict.FilterConfig{CrowdSec: cs, CrowdSecMode: restrict.CrowdSecEnforce})
			require.NoError(t, mw.AddDomain("example.com", nil, "", 0, "acct-1", "svc-1", filter, false, nil))

			var reached bool
			handler := denyPageHandler(t, mw, "example.com", &reached)
			rec := denyPageRequest(t, handler, "example.com", "1.2.3.4:5678")

			assertBrandedAccessDenied(t, rec, tt.verdict, "crowdsec", "1.2.3.4")
			assert.False(t, reached, "denied request must not reach the upstream")
		})
	}
}

func TestAccessDeniedPage_CrowdSecUnavailableEnforce(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	cs := &denyPageCrowdSec{ready: false}
	filter := restrict.ParseFilter(restrict.FilterConfig{CrowdSec: cs, CrowdSecMode: restrict.CrowdSecEnforce})
	require.NoError(t, mw.AddDomain("example.com", nil, "", 0, "acct-1", "svc-1", filter, false, nil))

	var reached bool
	handler := denyPageHandler(t, mw, "example.com", &reached)
	rec := denyPageRequest(t, handler, "example.com", "1.2.3.4:5678")

	assertBrandedAccessDenied(t, rec, "crowdsec_unavailable", "crowdsec", "1.2.3.4")
	assert.False(t, reached, "denied request must not reach the upstream")
}

func TestAccessDeniedPage_CrowdSecObserveAllows(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	cs := &denyPageCrowdSec{decisions: map[string]restrict.DecisionType{"1.2.3.4": restrict.DecisionBan}, ready: true}
	filter := restrict.ParseFilter(restrict.FilterConfig{CrowdSec: cs, CrowdSecMode: restrict.CrowdSecObserve})
	require.NoError(t, mw.AddDomain("example.com", nil, "", 0, "acct-1", "svc-1", filter, false, nil))

	var reached bool
	handler := denyPageHandler(t, mw, "example.com", &reached)
	rec := denyPageRequest(t, handler, "example.com", "1.2.3.4:5678")

	assert.Equal(t, http.StatusOK, rec.Code, "observe mode must not block")
	assert.True(t, reached, "observed request must reach the upstream")
}

func TestAccessDeniedPage_PrivateDenial(t *testing.T) {
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"100.64.0.0/16"}})
	mw := newPrivateMiddleware(t, &switchableTunnelValidator{valid: true}, filter)
	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://"+testServerHost+"/", nil)
	req.RemoteAddr = "100.65.5.6:5000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertBrandedAccessDenied(t, rec, "ip_restricted", "100.65.5.6")
	assert.Equal(t, "close", rec.Header().Get("Connection"), "private denial must ask the client to drop the connection")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), "private denial must not be cacheable")
}

func TestAccessDeniedPage_CarriesRequestID(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, mw.AddDomain("example.com", nil, "", 0, "acct-1", "svc-1", filter, false, nil))
	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.1:5678"
	req.Host = "example.com"
	cd := proxy.NewCapturedData("test-req-123")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), cd))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertBrandedAccessDenied(t, rec, "ip_restricted")
	assert.Contains(t, rec.Body.String(), "test-req-123", "denial page must carry the request ID for correlation")
}

// TestFailedCredentialsStillRenderLoginPage documents the preserved behavior:
// wrong credentials re-render the login page with 401 instead of the 403
// access-denied page, so the user can retry.
func TestFailedCredentialsStillRenderLoginPage(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	kp := generateTestKeyPair(t)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, 0, "acct-1", "svc-1", nil, false, nil))

	var reached bool
	handler := denyPageHandler(t, mw, "example.com", &reached)

	// Wrong PIN submitted via POST form, the same shape the UI posts.
	form := url.Values{"pin": {"000000"}}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.25:12345"
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "wrong credentials must keep returning 401")
	assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"))
	assert.NotContains(t, rec.Body.String(), "Access Denied", "failed login must not render the access-denied page")
	assert.False(t, reached, "failed login must not reach the upstream")
}

// TestOAuthCallbackErrorDescriptionEscaping guards the error_description
// handling: the value must be rendered escaped exactly once. Double-escaping
// would show entities such as &amp;lt; to the user.
func TestOAuthCallbackErrorDescriptionEscaping(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	kp := generateTestKeyPair(t)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, 0, "acct-1", "svc-1", nil, false, nil))
	handler := mw.Protect(newPassthroughHandler())

	payload := `Bad <thing> & "stuff" 'quoted'`
	q := url.Values{"error": {"access_denied"}, "error_description": {payload}}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/?"+q.Encode(), nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"))
	body := rec.Body.String()
	assert.Contains(t, body, "Access Denied")
	// Go's json.Marshal escapes <, >, & as \u003c, \u003e, \u0026 in the
	// embedded __DATA__ payload; React unescapes the JSON and escapes again
	// on render. Either layer neutralizes the markup exactly once.
	assert.Contains(t, body, `\u003cthing\u003e`, "markup must be neutralized in the embedded payload")
	assert.NotContains(t, body, "<thing>", "raw markup must not reach the page")
	assert.NotContains(t, body, `\u0026lt;`, "value must not be pre-escaped (that would double-escape on render)")
	assert.NotContains(t, body, payload, "raw payload must not reach the page")
}
