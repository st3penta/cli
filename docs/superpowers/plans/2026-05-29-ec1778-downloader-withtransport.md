# EC-1778: Downloader WithTransport Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace removed `goci.Transport`/`ghttp.Transport` global mutations with `WithTransport` functional options on constructed gatherer instances.

**Architecture:** Package-level `ociGatherer`/`httpGatherer` vars initialized via `sync.OnceFunc`. `gatherFunc` dispatches OCI/HTTP sources to these gatherers via `Matcher`, falling back to the registry for git/file sources.

**Tech Stack:** Go, go-gather v1.2.0, oras-go retry transport

**Spec:** `docs/superpowers/specs/2026-05-28-ec1778-downloader-withtransport-design.md`

---

### Task 1: Update go-gather dependency to v1.2.0

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Create feature branch**

```bash
cd ~/git/redhat/conforma/cli
git checkout -b EC-1778 main
```

- [ ] **Step 2: Update go-gather to v1.2.0**

```bash
cd ~/git/redhat/conforma/cli
go get github.com/conforma/go-gather@v1.2.0
go mod tidy
```

- [ ] **Step 3: Verify the update**

```bash
cd ~/git/redhat/conforma/cli
grep "go-gather" go.mod
```

Expected: `github.com/conforma/go-gather v1.2.0`

- [ ] **Step 4: Verify compilation fails**

The CLI should fail to compile because `goci.Transport` and `ghttp.Transport` no longer exist in v1.2.0.

```bash
cd ~/git/redhat/conforma/cli
go build ./... 2>&1 | head -20
```

Expected: Compilation errors referencing `goci.Transport` and `ghttp.Transport` in `internal/downloader/downloader.go`.

- [ ] **Step 5: Commit**

```bash
cd ~/git/redhat/conforma/cli
git add go.mod go.sum
git commit -m "chore(EC-1778): update go-gather to v1.2.0

reference: EC-1778

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Rewrite `_initialize` to construct gatherers with `WithTransport`

**Files:**
- Modify: `internal/downloader/downloader.go`

- [ ] **Step 1: Add `net/http` import and package-level gatherer vars**

In `internal/downloader/downloader.go`, replace the import block and add the new vars. The full import block should become:

```go
import (
	"context"
	"fmt"
	net_http "net/http"
	"regexp"
	"strings"
	"sync"

	ghttp "github.com/conforma/go-gather/gather/http"
	goci "github.com/conforma/go-gather/gather/oci"
	"github.com/conforma/go-gather/metadata"
	"github.com/conforma/go-gather/registry"
	"github.com/sirupsen/logrus"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/conforma/cli/internal/http"
)
```

Add the new package-level vars after the `var log` line:

```go
var log = logrus.StandardLogger()

var (
	ociGatherer  *goci.OCIGatherer
	httpGatherer *ghttp.HTTPGatherer
)
```

- [ ] **Step 2: Rewrite `_initialize` function**

Replace the entire `_initialize` function body. The old code mutates `goci.Transport` and `ghttp.Transport` globals. The new code builds a transport stack and constructs gatherer instances.

Replace:
```go
var _initialize = func() {
	if log.IsLevelEnabled(logrus.TraceLevel) {
		goci.Transport = http.NewTracingRoundTripperWithLogger(goci.Transport)
		ghttp.Transport = http.NewTracingRoundTripperWithLogger(ghttp.Transport)
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

	ociTransport := retry.NewTransport(goci.Transport)
	ociTransport.Policy = policyfn
	goci.Transport = ociTransport

	httpTransport := retry.NewTransport(ghttp.Transport)
	httpTransport.Policy = policyfn
	ghttp.Transport = httpTransport
}
```

With:
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

- [ ] **Step 3: Rewrite `gatherFunc` to use Matcher-based dispatch**

Replace:
```go
var gatherFunc = func(ctx context.Context, source, destination string) (metadata.Metadata, error) {
	initialize()
	g, err := registry.GetGatherer(source)
	if err != nil {
		return nil, err
	}
	return g.Gather(ctx, source, destination)
}
```

With:
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

- [ ] **Step 4: Verify compilation succeeds**

```bash
cd ~/git/redhat/conforma/cli
go build ./...
```

Expected: Clean compilation, no errors.

- [ ] **Step 5: Commit**

```bash
cd ~/git/redhat/conforma/cli
git add internal/downloader/downloader.go
git commit -m "fix(EC-1778): replace transport globals with WithTransport gatherers

Replace removed goci.Transport/ghttp.Transport global mutations with
constructed gatherer instances using WithTransport functional options.
gatherFunc now dispatches via Matcher (OCI, HTTP) before falling back
to the registry for git/file sources.

reference: EC-1778

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Update `TestOCITracing`

**Files:**
- Modify: `internal/downloader/downloader_test.go`

- [ ] **Step 1: Update the cleanup block**

In `TestOCITracing`, replace the cleanup closure. Remove the lines that reset `goci.Transport` and `ghttp.Transport` (they no longer exist). Add lines to reset the new gatherer vars.

Replace:
```go
	t.Cleanup(func() {
		log.Level = logrus.InfoLevel
		initialize = sync.OnceFunc(_initialize)
		goci.Transport = http.DefaultTransport
		ghttp.Transport = http.DefaultTransport
	})
```

With:
```go
	t.Cleanup(func() {
		log.Level = logrus.InfoLevel
		initialize = sync.OnceFunc(_initialize)
		ociGatherer = nil
		httpGatherer = nil
	})
```

- [ ] **Step 2: Run the test**

```bash
cd ~/git/redhat/conforma/cli
go test -race -tags=unit -run TestOCITracing -v -timeout 10s ./internal/downloader/
```

Expected: PASS. The test pushes an image to an httptest registry, calls `gatherFunc` (which triggers `_initialize` and dispatches via `ociGatherer.Matcher`), and verifies trace log output.

- [ ] **Step 3: Commit**

```bash
cd ~/git/redhat/conforma/cli
git add internal/downloader/downloader_test.go
git commit -m "test(EC-1778): update TestOCITracing for gatherer vars

reference: EC-1778

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Update `TestHTTPTracing`

**Files:**
- Modify: `internal/downloader/downloader_test.go`

- [ ] **Step 1: Update the cleanup block**

In `TestHTTPTracing`, replace the cleanup closure. Same pattern as Task 3.

Replace:
```go
	t.Cleanup(func() {
		log.Level = logrus.InfoLevel
		initialize = sync.OnceFunc(_initialize)
		goci.Transport = http.DefaultTransport
		ghttp.Transport = http.DefaultTransport
	})
```

With:
```go
	t.Cleanup(func() {
		log.Level = logrus.InfoLevel
		initialize = sync.OnceFunc(_initialize)
		ociGatherer = nil
		httpGatherer = nil
	})
```

- [ ] **Step 2: Run the test**

```bash
cd ~/git/redhat/conforma/cli
go test -race -tags=unit -run TestHTTPTracing -v -timeout 10s ./internal/downloader/
```

Expected: PASS. The test creates an httptest server, calls `gatherFunc` (dispatches via `httpGatherer.Matcher`), and verifies trace log output.

- [ ] **Step 3: Commit**

```bash
cd ~/git/redhat/conforma/cli
git add internal/downloader/downloader_test.go
git commit -m "test(EC-1778): update TestHTTPTracing for gatherer vars

reference: EC-1778

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Update `TestOCIClientConfiguration`

**Files:**
- Modify: `internal/downloader/downloader_test.go`

- [ ] **Step 1: Rewrite the test**

`OCIGatherer.transport` is private — we cannot inspect it. Replace the transport-inspection test with a type assertion on the constructed gatherer. Transport wiring is already verified end-to-end by `TestOCITracing`.

Replace the entire `TestOCIClientConfiguration` function:

```go
func TestOCIClientConfiguration(t *testing.T) {
	defaultMaxRetry := echttp.DefaultRetry.MaxRetry
	t.Cleanup(func() {
		echttp.DefaultRetry.MaxRetry = defaultMaxRetry
	})
	echttp.DefaultRetry.MaxRetry = rand.Int() //nolint:gosec // G404 - no need for a secure random here

	_initialize()

	assert.IsType(t, &retry.Transport{}, goci.Transport)

	transport := goci.Transport.(*retry.Transport)
	assert.Equal(t, echttp.DefaultRetry.MaxRetry, transport.Policy().(*retry.GenericPolicy).MaxRetry)
}
```

With:

```go
func TestOCIClientConfiguration(t *testing.T) {
	t.Cleanup(func() {
		ociGatherer = nil
		httpGatherer = nil
	})

	_initialize()

	assert.IsType(t, &goci.OCIGatherer{}, ociGatherer)
}
```

- [ ] **Step 2: Run the test**

```bash
cd ~/git/redhat/conforma/cli
go test -race -tags=unit -run TestOCIClientConfiguration -v -timeout 10s ./internal/downloader/
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd ~/git/redhat/conforma/cli
git add internal/downloader/downloader_test.go
git commit -m "test(EC-1778): rewrite TestOCIClientConfiguration for private transport

OCIGatherer.transport is private in go-gather v1.2.0. Assert gatherer
type instead; transport wiring is verified end-to-end by TestOCITracing.

reference: EC-1778

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Update `TestHTTPClientConfiguration`

**Files:**
- Modify: `internal/downloader/downloader_test.go`

- [ ] **Step 1: Rewrite the test**

`HTTPGatherer.Client` is public, so we can still inspect the transport. Replace references to the removed `ghttp.Transport` global with `httpGatherer.Client.Transport`.

Replace the entire `TestHTTPClientConfiguration` function:

```go
func TestHTTPClientConfiguration(t *testing.T) {
	defaultMaxRetry := echttp.DefaultRetry.MaxRetry
	t.Cleanup(func() {
		echttp.DefaultRetry.MaxRetry = defaultMaxRetry
	})
	echttp.DefaultRetry.MaxRetry = rand.Int() //nolint:gosec // G404 - no need for a secure random here

	_initialize()

	assert.IsType(t, &retry.Transport{}, ghttp.Transport)

	transport := ghttp.Transport.(*retry.Transport)
	assert.Equal(t, echttp.DefaultRetry.MaxRetry, transport.Policy().(*retry.GenericPolicy).MaxRetry)
}
```

With:

```go
func TestHTTPClientConfiguration(t *testing.T) {
	defaultMaxRetry := echttp.DefaultRetry.MaxRetry
	t.Cleanup(func() {
		echttp.DefaultRetry.MaxRetry = defaultMaxRetry
		ociGatherer = nil
		httpGatherer = nil
	})
	echttp.DefaultRetry.MaxRetry = rand.Int() //nolint:gosec // G404 - no need for a secure random here

	_initialize()

	require.IsType(t, &ghttp.HTTPGatherer{}, httpGatherer)
	assert.IsType(t, &retry.Transport{}, httpGatherer.Client.Transport)

	transport := httpGatherer.Client.Transport.(*retry.Transport)
	assert.Equal(t, echttp.DefaultRetry.MaxRetry, transport.Policy().(*retry.GenericPolicy).MaxRetry)
}
```

- [ ] **Step 2: Run the test**

```bash
cd ~/git/redhat/conforma/cli
go test -race -tags=unit -run TestHTTPClientConfiguration -v -timeout 10s ./internal/downloader/
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd ~/git/redhat/conforma/cli
git add internal/downloader/downloader_test.go
git commit -m "test(EC-1778): update TestHTTPClientConfiguration for gatherer vars

reference: EC-1778

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Clean up unused imports and run full test suite

**Files:**
- Modify: `internal/downloader/downloader_test.go` (if needed)

- [ ] **Step 1: Check for unused imports in the test file**

The test file may still import `goci` and `ghttp` — verify they are still needed (for type assertions in `TestOCIClientConfiguration` and `TestHTTPClientConfiguration`). Both are still referenced: `goci.OCIGatherer` and `ghttp.HTTPGatherer`.

Check that `goci` is still used — it's referenced in `TestOCIClientConfiguration` as `&goci.OCIGatherer{}`. If `TestOCITracing` no longer references `goci.Transport`, then `goci` is only used in the type assertion. Same for `ghttp`.

```bash
cd ~/git/redhat/conforma/cli
go build -tags=unit ./internal/downloader/
```

Expected: Clean compilation with no unused import errors. If there are unused import errors, remove the offending imports.

- [ ] **Step 2: Run all downloader unit tests**

```bash
cd ~/git/redhat/conforma/cli
go test -race -tags=unit -v -timeout 10s ./internal/downloader/
```

Expected: All 7 tests pass (TestDownloader_Download subtests, TestIsSecure, TestOCITracing, TestHTTPTracing, TestOCIClientConfiguration, TestHTTPClientConfiguration).

- [ ] **Step 3: Run the full unit test suite**

```bash
cd ~/git/redhat/conforma/cli
make test
```

Expected: All unit, integration, and generative tests pass.

- [ ] **Step 4: Commit any remaining cleanup**

Only if Step 1 required import changes:

```bash
cd ~/git/redhat/conforma/cli
git add internal/downloader/downloader_test.go
git commit -m "chore(EC-1778): clean up unused imports in downloader tests

reference: EC-1778

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
