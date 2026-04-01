package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA holds a generated certificate authority used for MITM.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	TLSCert     tls.Certificate
}

// GenerateCA creates a new self-signed CA certificate and private key.
func GenerateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Paude Proxy CA",
			Organization: []string{"Paude Proxy"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		TLSCert:     tlsCert,
	}, nil
}

// LoadCAFromDir loads an existing CA certificate and key from the given directory.
// Returns nil, nil if the files do not exist. Returns an error if the files
// exist but cannot be parsed.
func LoadCAFromDir(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		TLSCert:     tlsCert,
	}, nil
}

// WriteToDir writes the CA certificate and key to the given directory.
// The certificate is written as ca.crt and the key as ca.key.
func (ca *CA) WriteToDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create CA directory: %w", err)
	}

	// Write certificate
	certPath := filepath.Join(dir, "ca.crt")
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create CA cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Certificate.Raw,
	}); err != nil {
		return fmt.Errorf("encode CA cert: %w", err)
	}

	// Write private key
	keyPath := filepath.Join(dir, "ca.key")
	keyDER, err := x509.MarshalECPrivateKey(ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create CA key file: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	}); err != nil {
		return fmt.Errorf("encode CA key: %w", err)
	}

	return nil
}
