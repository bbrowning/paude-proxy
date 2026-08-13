package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"

	"github.com/bbrowning/paude-proxy/internal/credentials"
)

// errReader is an io.ReadCloser that always fails on Read, simulating a client
// connection that stalls or resets while the proxy is buffering the body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errReader) Close() error             { return nil }

// newRefresherStore returns a store with a single example.com route backed by
// a fresh refreshableInjector — the common setup for the retry-buffer tests.
func newRefresherStore() *credentials.Store {
	store := credentials.NewStore()
	store.AddRoute(credentials.Route{
		ExactDomain: "example.com",
		Injector:    &refreshableInjector{},
	})
	return store
}

// When buffering the request body for a possible retry fails, the body has
// already been partially drained and can't be forwarded intact. The request
// must be aborted with a 502 rather than sent upstream with a truncated body.
func TestPrepareRefreshRetry_BodyBufferFailureReturns502(t *testing.T) {
	store := newRefresherStore()

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/generate", errReader{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := &goproxy.ProxyCtx{}

	resp := prepareRefreshRetry(req, ctx, store)
	if resp == nil {
		t.Fatal("expected a non-nil abort response when body buffering fails")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway, got %d", resp.StatusCode)
	}
	if ctx.UserData != nil {
		t.Error("retry state should not be stashed when buffering fails")
	}
}

// A successful buffer stashes retry state and leaves the body replayable.
func TestPrepareRefreshRetry_BuffersBodyForRetry(t *testing.T) {
	store := newRefresherStore()

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/generate", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &goproxy.ProxyCtx{}

	if resp := prepareRefreshRetry(req, ctx, store); resp != nil {
		t.Fatalf("expected nil response on success, got status %d", resp.StatusCode)
	}
	state, ok := ctx.UserData.(*refreshRetryState)
	if !ok {
		t.Fatal("expected refreshRetryState to be stashed on ctx.UserData")
	}

	// The buffered body must be readable, and getBody must replay it.
	first, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read buffered body: %v", err)
	}
	if string(first) != "payload" {
		t.Errorf("buffered body = %q, want %q", first, "payload")
	}
	replay, err := state.getBody()
	if err != nil {
		t.Fatalf("getBody: %v", err)
	}
	replayed, _ := io.ReadAll(replay)
	if string(replayed) != "payload" {
		t.Errorf("replayed body = %q, want %q", replayed, "payload")
	}
}

// A body larger than the retry buffer cap must be forwarded intact but
// without retry state — the proxy must never truncate it, and must not hold
// the whole body in memory for a retry it won't perform.
func TestPrepareRefreshRetry_OversizedBodyForwardedWithoutRetry(t *testing.T) {
	store := newRefresherStore()

	// One byte over the cap is enough to trip the oversized path.
	payload := strings.Repeat("a", maxRetryBufferBytes+1)
	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/generate", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &goproxy.ProxyCtx{}

	if resp := prepareRefreshRetry(req, ctx, store); resp != nil {
		t.Fatalf("oversized body should be forwarded, not aborted; got status %d", resp.StatusCode)
	}
	if ctx.UserData != nil {
		t.Error("oversized body should not stash retry state")
	}

	// The full body must still be forwardable intact (prefix + remainder).
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read forwarded body: %v", err)
	}
	if len(forwarded) != len(payload) {
		t.Errorf("forwarded body length = %d, want %d (body was truncated)", len(forwarded), len(payload))
	}
	if err := req.Body.Close(); err != nil {
		t.Errorf("closing forwarded body: %v", err)
	}
}

// A body exactly at the cap is still buffered for retry (the cap is inclusive).
func TestPrepareRefreshRetry_BodyAtCapBuffered(t *testing.T) {
	store := newRefresherStore()

	payload := strings.Repeat("a", maxRetryBufferBytes)
	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/generate", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &goproxy.ProxyCtx{}

	if resp := prepareRefreshRetry(req, ctx, store); resp != nil {
		t.Fatalf("expected nil response at cap, got status %d", resp.StatusCode)
	}
	if _, ok := ctx.UserData.(*refreshRetryState); !ok {
		t.Fatal("body at cap should be buffered with retry state stashed")
	}
}

// A non-refresher route is never prepared for retry.
func TestPrepareRefreshRetry_NonRefresherSkipped(t *testing.T) {
	store := credentials.NewStore()
	store.AddRoute(credentials.Route{
		ExactDomain: "example.com",
		Injector:    &credentials.BearerInjector{Token: "x"},
	})

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/generate", errReader{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := &goproxy.ProxyCtx{}

	if resp := prepareRefreshRetry(req, ctx, store); resp != nil {
		t.Errorf("non-refresher route should not abort, got status %d", resp.StatusCode)
	}
	if ctx.UserData != nil {
		t.Error("non-refresher route should not stash retry state")
	}
}
