// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	cosign "github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/policy"
)

type mockEvaluator struct {
	mu      sync.Mutex
	results []evaluator.Outcome
	err     error
	target  evaluator.EvaluationTarget
}

func (m *mockEvaluator) Evaluate(_ context.Context, target evaluator.EvaluationTarget) ([]evaluator.Outcome, error) {
	m.mu.Lock()
	m.target = target
	m.mu.Unlock()
	return m.results, m.err
}

func (m *mockEvaluator) Target() evaluator.EvaluationTarget {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.target
}

func (m *mockEvaluator) Destroy() {}

func (m *mockEvaluator) CapabilitiesPath() string { return "" }

type stubPolicy struct{}

func (p *stubPolicy) PublicKeyPEM() ([]byte, error)                           { return nil, nil }
func (p *stubPolicy) CheckOpts() (*cosign.CheckOpts, error)                   { return nil, nil }
func (p *stubPolicy) WithSpec(ecc.EnterpriseContractPolicySpec) policy.Policy { return p }
func (p *stubPolicy) Spec() ecc.EnterpriseContractPolicySpec {
	return ecc.EnterpriseContractPolicySpec{}
}
func (p *stubPolicy) EffectiveTime() time.Time                   { return time.Now() }
func (p *stubPolicy) SkipImageSigCheck() bool                    { return false }
func (p *stubPolicy) SkipAttSigCheck() bool                      { return false }
func (p *stubPolicy) AttestationTime(time.Time)                  {}
func (p *stubPolicy) Identity() cosign.Identity                  { return cosign.Identity{} }
func (p *stubPolicy) Keyless() bool                              { return false }
func (p *stubPolicy) SigstoreOpts() (policy.SigstoreOpts, error) { return policy.SigstoreOpts{}, nil }

func newTestServer(evals ...evaluator.Evaluator) *Server {
	s := &Server{
		cfg: Config{
			ShowWarnings: true,
			Policy:       &stubPolicy{},
		},
	}
	s.evaluators = evals
	s.ready.Store(true)
	return s
}

func TestHandleLive(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/live", nil)

	s.handleLive(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestHandleReady_Ready(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	s.handleReady(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ready"}`, rec.Body.String())
}

func TestHandleReady_NotReady(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	s.handleReady(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.JSONEq(t, `{"status":"not ready"}`, rec.Body.String())
}

func TestHandleValidateInput_EmptyBody(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate/input", nil)

	s.handleValidateInput(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "request body is empty", resp.Error)
}

func TestHandleValidateInput_InvalidInput(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate/input", strings.NewReader("not valid json or yaml map"))

	s.handleValidateInput(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "request body is not valid JSON or YAML", resp.Error)
}

func TestHandleValidateInput_SuccessJSON(t *testing.T) {
	mock := &mockEvaluator{
		results: []evaluator.Outcome{
			{
				FileName:  "input",
				Namespace: "test.main",
				Successes: []evaluator.Result{
					{Message: "check passed", Metadata: map[string]interface{}{"code": "test.check"}},
				},
			},
		},
	}

	s := newTestServer(mock)
	s.cfg.ShowSuccesses = true

	body := `{"kind": "Pipeline", "apiVersion": "v1"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate/input", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	s.handleValidateInput(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	require.Len(t, mock.Target().Inputs, 1)
	assert.Equal(t, ".json", filepath.Ext(mock.Target().Inputs[0]))

	var report map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &report))
	assert.Equal(t, true, report["success"])
}

func TestHandleValidateInput_WithViolations(t *testing.T) {
	mock := &mockEvaluator{
		results: []evaluator.Outcome{
			{
				FileName:  "input",
				Namespace: "test.main",
				Failures: []evaluator.Result{
					{Message: "check failed", Metadata: map[string]interface{}{"code": "test.fail"}},
				},
			},
		},
	}

	s := newTestServer(mock)

	body := `{"kind": "Pipeline"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate/input", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	s.handleValidateInput(rec, req)

	// 200 for completed evaluations, even with violations
	assert.Equal(t, http.StatusOK, rec.Code)

	var report map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &report))
	assert.Equal(t, false, report["success"])
}

func TestHandleValidateInput_EvaluationError(t *testing.T) {
	mock := &mockEvaluator{
		err: assert.AnError,
	}

	s := newTestServer(mock)

	body := `{"kind": "Pipeline"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate/input", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	s.handleValidateInput(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandleValidateInput_YAMLInput(t *testing.T) {
	mock := &mockEvaluator{
		results: []evaluator.Outcome{
			{FileName: "input", Namespace: "test.main"},
		},
	}

	s := newTestServer(mock)

	body := "kind: Pipeline\napiVersion: v1\n"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate/input", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")

	s.handleValidateInput(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	require.Len(t, mock.Target().Inputs, 1)
	assert.Equal(t, ".yaml", filepath.Ext(mock.Target().Inputs[0]))
}

func TestRecoveryMiddleware(t *testing.T) {
	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := recoveryMiddleware(panicking)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "internal server error", resp.Error)
}

type slowEvaluator struct {
	mockEvaluator
}

func (m *slowEvaluator) Evaluate(ctx context.Context, target evaluator.EvaluationTarget) ([]evaluator.Outcome, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestHandleValidateInput_EvaluationTimeout(t *testing.T) {
	orig := evaluationTimeout
	evaluationTimeout = 50 * time.Millisecond
	t.Cleanup(func() { evaluationTimeout = orig })

	s := newTestServer(&slowEvaluator{})

	body := `{"kind": "Pipeline"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/validate/input", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	s.handleValidateInput(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp.Error, "context deadline exceeded")
}

func TestServerLifecycle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	s := &Server{
		cfg: Config{
			Port:   port,
			Policy: &stubPolicy{},
		},
	}
	s.evaluators = []evaluator.Evaluator{&mockEvaluator{}}
	s.ready.Store(true)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		mux := http.NewServeMux()
		s.registerRoutes(mux)
		httpServer := &http.Server{
			Addr:              fmt.Sprintf(":%d", port),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			_ = httpServer.Shutdown(shutdownCtx)
		}()

		errCh <- httpServer.ListenAndServe()
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/live", port))
	if err == nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	cancel()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}
