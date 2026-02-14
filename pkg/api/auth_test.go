package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestAuthMiddleware(t *testing.T) {
	cfg := AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := authMiddleware(cfg, ok)

	tests := []struct {
		name   string
		path   string
		header map[string]string
		want   int
	}{
		{
			name: "health bypass",
			path: "/health",
			want: http.StatusOK,
		},
		{
			name: "metrics bypass",
			path: "/metrics",
			want: http.StatusOK,
		},
		{
			name: "no auth",
			path: "/api/v1/status",
			want: http.StatusUnauthorized,
		},
		{
			name:   "valid basic auth",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": basicAuth("admin", "secret123")},
			want:   http.StatusOK,
		},
		{
			name:   "invalid basic auth password",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": basicAuth("admin", "wrong")},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "invalid basic auth user",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": basicAuth("nobody", "secret123")},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "valid bearer token",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": "Bearer tok-abc-123"},
			want:   http.StatusOK,
		},
		{
			name:   "invalid bearer token",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": "Bearer bad-token"},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "valid X-API-Key",
			path:   "/api/v1/status",
			header: map[string]string{"X-API-Key": "tok-abc-123"},
			want:   http.StatusOK,
		},
		{
			name:   "invalid X-API-Key",
			path:   "/api/v1/status",
			header: map[string]string{"X-API-Key": "bad-key"},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "malformed basic auth",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": "Basic !!!notbase64"},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "www-authenticate header on 401",
			path:   "/api/v1/security/sessions",
			want:   http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.want {
				t.Errorf("got status %d, want %d", w.Code, tt.want)
			}

			if tt.want == http.StatusUnauthorized {
				if wa := w.Header().Get("WWW-Authenticate"); wa == "" {
					t.Error("expected WWW-Authenticate header on 401")
				}
			}
		})
	}
}
