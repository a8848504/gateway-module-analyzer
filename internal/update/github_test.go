package update

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestUpdateDownloadAndVersionCheck(t *testing.T) {
	raw := []byte("test release asset")
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/repos/demo/analyzer/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v1.10.0","assets":[{"id":10,"name":"GatewayModuleAnalyzer-Windows-amd64.exe","size":%d,"digest":"sha256:%s"}]}`, len(raw), digest)
		case "/repos/demo/analyzer/releases/assets/10":
			if r.Header.Get("Accept") != "application/octet-stream" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Write(raw)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	api := NewGitHub("demo/analyzer")
	api.base = server.URL
	ctx := context.Background()
	current, err := api.Latest(ctx, "v1.10.1", "amd64")
	if err != nil || current != nil {
		t.Fatalf("downgrade accepted: %+v %v", current, err)
	}
	release, err := api.Latest(ctx, "v1.9.1", "amd64")
	if err != nil || release == nil {
		t.Fatalf("update missing: %+v %v", release, err)
	}
	directory := t.TempDir()
	path, err := api.Download(ctx, release, directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, digest); err != nil {
		t.Fatal(err)
	}
	release.Digest = fmt.Sprintf("%064x", 1)
	if _, err := api.Download(ctx, release, directory); err == nil {
		t.Fatal("changed EXE accepted")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("failed download was left on disk: %v %v", files, err)
	}
}
