package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestAdminLeaseEvictionAuthorizationAndValidation(t *testing.T) {
	api, _, err := newPolicyAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		method string
		token  bool
		body   string
		status int
	}{
		{name: "unauthorized", method: http.MethodPost, body: `{"identity_key":"service:address"}`, status: http.StatusUnauthorized},
		{name: "malformed identity", method: http.MethodPost, token: true, body: `{"identity_key":"invalid"}`, status: http.StatusBadRequest},
		{name: "unknown lease", method: http.MethodPost, token: true, body: `{"identity_key":"service:address"}`, status: http.StatusNotFound},
		{name: "method not allowed", method: http.MethodGet, token: true, status: http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, types.PathPolicyLeaseEvict, strings.NewReader(tc.body))
			if tc.token {
				req.Header.Set("Authorization", "Bearer admin-test")
			}
			rec := httptest.NewRecorder()
			api.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("response status = %d, want %d; body = %s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}
