package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestAdministrativeLeaseEvictionRequiresAuthentication(t *testing.T) {
	api, _, err := newPolicyAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}
	request := func(auth, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, types.PathPolicyLeaseEvict, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		api.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := request("", "{\"identity_key\":\"evict:0x123\"}"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated eviction = HTTP %d, want 401", rec.Code)
	}
	if rec := request("Bearer admin-test", "{\"identity_key\":\"bad-key\"}"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid eviction identity = HTTP %d, want 400", rec.Code)
	}
	if rec := request("Bearer admin-test", "{\"identity_key\":\"evict:0x123\"}"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing eviction identity = HTTP %d, want 404", rec.Code)
	}
}
