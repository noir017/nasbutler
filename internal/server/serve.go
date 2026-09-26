// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 noir017

package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServeStdio serves one client over stdin/stdout.
func ServeStdio(ctx context.Context, ms *mcp.Server) error {
	return ms.Run(ctx, &mcp.StdioTransport{})
}

// ServeHTTP serves MCP at /mcp (bearer token required) and a liveness
// probe at /healthz until ctx is cancelled.
func ServeHTTP(ctx context.Context, ms *mcp.Server, addr, token string, log *slog.Logger) error {
	if len(token) < 24 {
		return errors.New("HTTP mode needs a token of at least 24 characters")
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return ms },
		&mcp.StreamableHTTPOptions{SessionTimeout: time.Hour, Logger: log})
	mux := http.NewServeMux()
	mux.Handle("/mcp", RequireToken(token, h))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	hs := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	log.Info("serving MCP over HTTP", "addr", addr, "path", "/mcp")
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// RequireToken rejects requests without "Authorization: Bearer <token>".
func RequireToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="nasbutler"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
