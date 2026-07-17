package credentials

import (
	"net/http"
	"testing"
)

func TestHeaderInjector_NilRequest(t *testing.T) {
	inj := &HeaderInjector{Header: "X-Custom", Value: "test"}

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestHeaderInjector_NilHeader(t *testing.T) {
	inj := &HeaderInjector{Header: "X-Custom", Value: "test"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestBearerInjector_NilRequest(t *testing.T) {
	inj := &BearerInjector{Token: "test-token"}

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestBearerInjector_NilHeader(t *testing.T) {
	inj := &BearerInjector{Token: "test-token"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}

func TestAPIKeyInjector_NilRequest(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "test-key"}

	if inj.Inject(nil) == InjectOK {
		t.Error("nil request should not succeed")
	}
}

func TestAPIKeyInjector_NilHeader(t *testing.T) {
	inj := &APIKeyInjector{HeaderName: "x-api-key", Key: "test-key"}

	req := &http.Request{
		Header: nil,
	}

	if inj.Inject(req) == InjectOK {
		t.Error("request with nil Header should not succeed")
	}
}
