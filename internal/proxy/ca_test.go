package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	if ca.Certificate == nil {
		t.Fatal("CA certificate is nil")
	}
	if ca.PrivateKey == nil {
		t.Fatal("CA private key is nil")
	}
	if !ca.Certificate.IsCA {
		t.Error("certificate should be a CA")
	}
	if ca.Certificate.Subject.CommonName != "Auth Proxy CA" {
		t.Errorf("CN = %q, want %q", ca.Certificate.Subject.CommonName, "Auth Proxy CA")
	}
}

func TestCA_WriteToDir(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	dir := t.TempDir()
	subdir := filepath.Join(dir, "certs")

	if err := ca.WriteToDir(subdir); err != nil {
		t.Fatalf("WriteToDir() error: %v", err)
	}

	// Check cert file exists and is non-empty
	certData, err := os.ReadFile(filepath.Join(subdir, "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	if len(certData) == 0 {
		t.Error("ca.crt is empty")
	}

	// Check key file exists and is non-empty
	keyData, err := os.ReadFile(filepath.Join(subdir, "ca.key"))
	if err != nil {
		t.Fatalf("read ca.key: %v", err)
	}
	if len(keyData) == 0 {
		t.Error("ca.key is empty")
	}

	// Check key file permissions (should be 0600)
	info, err := os.Stat(filepath.Join(subdir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("ca.key permissions = %o, want 0600", perm)
	}
}
