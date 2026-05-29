# EC-1778: Update CLI Downloader to Use go-gather WithTransport Functional Options

## Summary

Migrate `internal/downloader/downloader.go` from mutating removed `goci.Transport`/`ghttp.Transport` package-level globals to constructing gatherer instances via `goci.NewOCIGatherer(goci.WithTransport(...))` and `ghttp.NewHTTPGatherer(ghttp.WithTransport(...))`. Update `gatherFunc` to dispatch OCI/HTTP sources via configured gatherer instances, falling back to the registry for git/file sources.

**Scope:** 1 production file, 1 test file. No caller changes.

**Dependency:** go-gather v1.2.0 (tagged, available).

## Approach

Package-level gatherer variables with `sync.OnceFunc` (Approach 2). This preserves the existing code structure, test seams (`gatherFunc` swap, `initialize` reset), and avoids competing with the existing `downloadImpl` context injection pattern.

## Production Changes: `internal/downloader/downloader.go`

### New package-level variables

```go
var (
    ociGatherer  *goci.OCIGatherer
    httpGatherer *ghttp.HTTPGatherer
)
```

### `_initialize` function

Replace transport global mutation with gatherer construction. Build a shared base transport (DefaultTransport, optionally wrapped with tracing), create independent retry transports, pass via `WithTransport` to constructors. Assign atomically after both succeed to prevent partial initialization.

```go
var _initialize = func() {
    var base net_http.RoundTripper = net_http.DefaultTransport

    if log.IsLevelEnabled(logrus.TraceLevel) {
        base = http.NewTracingRoundTripperWithLogger(base)
    }

    backoff := retry.ExponentialBackoff(http.DefaultBackoff.Duration, http.DefaultBackoff.Factor, http.DefaultBackoff.Jitter)
    policy := &retry.GenericPolicy{
        Retryable: retry.DefaultPredicate,
        Backoff:   backoff,
        MaxWait:   http.DefaultRetry.MaxWait,
        MaxRetry:  http.DefaultRetry.MaxRetry,
    }
    policyfn := func() retry.Policy {
        return policy
    }

    ociTransport := retry.NewTransport(base)
    ociTransport.Policy = policyfn
    oci := goci.NewOCIGatherer(goci.WithTransport(ociTransport))

    httpTransport := retry.NewTransport(base)
    httpTransport.Policy = policyfn
    h := ghttp.NewHTTPGatherer(ghttp.WithTransport(httpTransport))

    ociGatherer = oci
    httpGatherer = h
}
```

**Design decisions:**
- Shared `base` transport: both old globals defaulted to `net_http.DefaultTransport`. Sharing is equivalent and cleaner. Tracing wrapper is stateless; each retry transport maintains independent state.
- Atomic assignment: build both gatherers into locals first, assign to package-level vars only after both succeed. Prevents nil-pointer panics from partial initialization.

### `gatherFunc` dispatch

Replace single `registry.GetGatherer(source)` call with Matcher-based routing. OCI checked first (more specific patterns), HTTP second, registry fallback for git/file.

```go
var gatherFunc = func(ctx context.Context, source, destination string) (metadata.Metadata, error) {
    initialize()

    switch {
    case ociGatherer.Matcher(source):
        return ociGatherer.Gather(ctx, source, destination)
    case httpGatherer.Matcher(source):
        return httpGatherer.Gather(ctx, source, destination)
    default:
        g, err := registry.GetGatherer(source)
        if err != nil {
            return nil, err
        }
        return g.Gather(ctx, source, destination)
    }
}
```

**Matcher ordering rationale:**
- OCI Matcher: matches `oci://`, `oci::` prefixes, or known registry hostnames (quay.io, gcr.io, localhost, etc.)
- HTTP Matcher: matches `http://`/`https://` schemes, excluding git hosts (github.com, gitlab.com, bitbucket.org). Git hosts fall through to registry as intended.
- No overlap: `oci://` won't match HTTP's scheme check, and known registries without explicit scheme match OCI first.

### Import changes

- Keep `"github.com/conforma/go-gather/registry"` import — still used by the git/file fallback path
- Add `net_http "net/http"` for `net_http.DefaultTransport` reference
- The `goci` and `ghttp` imports remain

### Removals

- Remove all references to `goci.Transport` and `ghttp.Transport` (they no longer exist in v1.2.0)

## Test Changes: `internal/downloader/downloader_test.go`

### `TestDownloader_Download` — unchanged

Still swaps `gatherFunc` with a mock closure and restores in defer.

### `TestOCITracing`

- Reset `initialize = _initialize` as before to force re-execution
- Remove cleanup lines that reset `goci.Transport = http.DefaultTransport` and `ghttp.Transport = http.DefaultTransport` (globals no longer exist)
- The test exercises the full path through `gatherFunc`, which now dispatches via the constructed `ociGatherer`. Tracing verification via `runtime/trace` output remains the same.
- Cleanup resets `ociGatherer = nil` and `httpGatherer = nil` along with `initialize = sync.OnceFunc(_initialize)`

### `TestHTTPTracing`

- Same changes as `TestOCITracing` — remove transport global cleanup, add gatherer var cleanup
- The test creates an httptest server and verifies trace logs appear, confirming the transport stack was wired correctly

### `TestOCIClientConfiguration`

- `OCIGatherer.transport` is private — cannot inspect directly
- **Strategy:** Convert to a behavioral test. Call `_initialize()`, then exercise `ociGatherer.Gather` against an httptest registry. Verify retry behavior by having the server return transient errors and confirming the gatherer retries according to the configured policy. This validates that `WithTransport` wired the retry transport correctly without needing to inspect private fields.
- Alternative: verify `ociGatherer` is non-nil and the correct type, accept that transport-level verification is covered by `TestOCITracing`

### `TestHTTPClientConfiguration`

- `HTTPGatherer.Client` is public — `httpGatherer.Client.Transport` is directly inspectable
- Call `_initialize()`, assert `httpGatherer.Client.Transport` is `*retry.Transport`, inspect `transport.Policy().(*retry.GenericPolicy).MaxRetry` — same pattern as the current test, just reading from the gatherer instead of the removed global

### Import changes in test file

- Remove imports of `goci` and `ghttp` if no longer needed for transport global access (may still be needed for type references)
- Remove `"net/http"` stdlib import alias if only used for `http.DefaultTransport` in cleanup

## go.mod change

Update go-gather dependency from v1.1.0 to v1.2.0:

```
go get github.com/conforma/go-gather@v1.2.0
```

## Acceptance Criteria

- CLI compiles against go-gather v1.2.0
- `gatherFunc` dispatches OCI/HTTP sources to configured gatherers, falls back to registry for git/file
- `_initialize` builds transport stack (tracing + retry) and passes via `WithTransport`
- All existing downloader tests pass
- `make test` passes across the CLI
