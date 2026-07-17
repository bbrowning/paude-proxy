package credentials

import (
	"net/http"
	"testing"
)

func TestGCloudInjector_NilRequest(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestGCloudInjector_NilHeader(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestGCloudInjector_InitFailure(t *testing.T) {
	inj := NewGCloudInjector("/nonexistent/path/to/adc.json")

	req := &http.Request{
		Header: make(http.Header),
	}

	if inj.Inject(req) == InjectOK {
		t.Error("inject should fail when ADC file doesn't exist")
	}

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty on init failure, got %q", got)
	}
}

func TestGCloudInjectorFromJSON_NilRequest(t *testing.T) {
	inj := NewGCloudInjectorFromJSON([]byte("invalid json"))

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestGCloudInjectorFromJSON_NilHeader(t *testing.T) {
	inj := NewGCloudInjectorFromJSON([]byte("invalid json"))

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}
