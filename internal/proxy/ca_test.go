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
	if ca.Certificate.Subject.CommonName != "Paude Proxy CA" {
		t.Errorf("CN = %q, want %q", ca.Certificate.Subject.CommonName, "Paude Proxy CA")
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

func TestLoadCAFromDir_NonExistent(t *testing.T) {
	ca, err := LoadCAFromDir(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ca != nil {
		t.Error("expected nil CA for nonexistent directory")
	}
}

func TestLoadCAFromDir_RoundTrip(t *testing.T) {
	// Generate, write, load — the loaded CA should produce identical MITM certs
	original, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	dir := t.TempDir()
	if err := original.WriteToDir(dir); err != nil {
		t.Fatalf("WriteToDir() error: %v", err)
	}

	loaded, err := LoadCAFromDir(dir)
	if err != nil {
		t.Fatalf("LoadCAFromDir() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadCAFromDir() returned nil")
	}

	// Verify the loaded CA matches the original
	if loaded.Certificate.Subject.CommonName != original.Certificate.Subject.CommonName {
		t.Errorf("CN = %q, want %q", loaded.Certificate.Subject.CommonName, original.Certificate.Subject.CommonName)
	}
	if !loaded.Certificate.IsCA {
		t.Error("loaded certificate should be a CA")
	}
	if loaded.Certificate.SerialNumber.Cmp(original.Certificate.SerialNumber) != 0 {
		t.Error("serial numbers don't match")
	}
	if !loaded.PrivateKey.Equal(original.PrivateKey) {
		t.Error("private keys don't match")
	}
	if len(loaded.TLSCert.Certificate) != 1 {
		t.Errorf("TLSCert should have 1 cert, got %d", len(loaded.TLSCert.Certificate))
	}
}

func TestLoadCAFromDir_EmptyDir(t *testing.T) {
	// Empty directory — no ca.crt or ca.key
	ca, err := LoadCAFromDir(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ca != nil {
		t.Error("expected nil CA for empty directory")
	}
}
