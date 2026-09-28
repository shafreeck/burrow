package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestRootValidationBeforeTrustChanges(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		isCA    bool
		expired bool
		bundle  bool
		wantErr bool
	}{
		{name: "current root", isCA: true},
		{name: "website certificate", wantErr: true},
		{name: "expired root", isCA: true, expired: true, wantErr: true},
		{name: "ambiguous bundle", isCA: true, bundle: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				IsCA: tc.isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			if tc.expired {
				tpl.NotAfter = time.Now().Add(-time.Minute)
			}
			der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			if tc.bundle {
				data = append(data, data...)
			}
			_, err = validateRoot(data)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validation error: %v", err)
			}
		})
	}
}

func TestEmbeddedRootIsValid(t *testing.T) {
	if _, err := validateRoot(PEM()); err != nil {
		t.Fatal(err)
	}
}
