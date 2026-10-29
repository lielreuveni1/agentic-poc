package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestFSServesIndex(t *testing.T) {
	b, err := fs.ReadFile(FS, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "<title>Repo Security Review</title>") {
		t.Error("index.html is not the app page")
	}
}
