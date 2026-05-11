package credentials

import (
	"net/http"
	"testing"
)

func TestGCloudInjector_NilRequest(t *testing.T) {
	// Create injector with non-existent path (will fail init, but that's OK for this test)
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	// Should handle nil request gracefully
	if inj.Inject(nil) {
		t.Error("nil request should return false")
	}
}

func TestGCloudInjector_NilHeader(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) {
		t.Error("request with nil Header should return false")
	}
}

func TestGCloudInjector_InitFailure(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	req := &http.Request{
		Header: make(http.Header),
	}

	// Should return false due to init failure (file doesn't exist)
	if inj.Inject(req) {
		t.Error("inject should fail when ADC file doesn't exist")
	}

	// Authorization header should not be set
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty on init failure, got %q", got)
	}
}

func TestGCloudInjectorFromJSON_NilRequest(t *testing.T) {
	// Invalid JSON will cause init to fail, but nil check comes first
	inj := NewGCloudInjectorFromJSON([]byte("invalid json"))

	if inj.Inject(nil) {
		t.Error("nil request should return false")
	}
}

func TestGCloudInjectorFromJSON_NilHeader(t *testing.T) {
	inj := NewGCloudInjectorFromJSON([]byte("invalid json"))

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) {
		t.Error("request with nil Header should return false")
	}
}
