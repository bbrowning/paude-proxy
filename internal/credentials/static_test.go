package credentials

import (
	"net/http"
	"testing"
)

func TestHeaderInjector_NilRequest(t *testing.T) {
	inj := &HeaderInjector{Header: "X-Custom", Value: "test"}

	// Should handle nil request gracefully
	if inj.Inject(nil) {
		t.Error("nil request should return false")
	}
}

func TestHeaderInjector_NilHeader(t *testing.T) {
	inj := &HeaderInjector{Header: "X-Custom", Value: "test"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) {
		t.Error("request with nil Header should return false")
	}
}

func TestBearerInjector_NilRequest(t *testing.T) {
	inj := &BearerInjector{Token: "test-token"}

	if inj.Inject(nil) {
		t.Error("nil request should return false")
	}
}

func TestBearerInjector_NilHeader(t *testing.T) {
	inj := &BearerInjector{Token: "test-token"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) {
		t.Error("request with nil Header should return false")
	}
}

func TestAPIKeyInjector_NilRequest(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "test-key"}

	if inj.Inject(nil) {
		t.Error("nil request should return false")
	}
}

func TestAPIKeyInjector_NilHeader(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "test-key"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) {
		t.Error("request with nil Header should return false")
	}
}
