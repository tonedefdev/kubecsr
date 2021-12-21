package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// CSR describes an x509 Certificate Signing Request
type CSR struct {
	Country  []string `json:"country,omitempty"`
	Locality []string `json:"locality,omitempty"`
	// This is used as the groups identifier for the Kubernetes CSR and its user
	Organization     []string `json:"organization,omitempty"`
	OrganizationUnit []string `json:"organizationUnit,omitempty"`
	PostalCode       []string `json:"postalCode,omitempty"`
	Province         []string `json:"province,omitempty"`
	StreetAddress    []string `json:"streetAddress,omitempty"`
	// This is used as the CommonName/CN and Kubernetes username for the CSR
	User string `json:"user" binding:"required"`
}

// CreateCSR creates an x509 Certificate Request
func (c *CSR) CreateCSR(key *rsa.PrivateKey) ([]byte, error) {
	subject := pkix.Name{
		CommonName:         c.User,
		Country:            c.Country,
		Locality:           c.Locality,
		Organization:       c.Organization,
		OrganizationalUnit: c.OrganizationUnit,
		PostalCode:         c.PostalCode,
		Province:           c.Province,
		StreetAddress:      c.StreetAddress,
	}

	req := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, err
	}

	pemCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	return pemCSR, err
}

// CreatePrivateKey generates an RSA Private Key with a 2048 bit length
func (c *CSR) CreatePrivateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	return key, err
}

// PEMEncodePrivateKey encodes an RSA private key into PEM encoded format returned as a byte slice
func (c *CSR) PEMEncodePrivateKey(key *rsa.PrivateKey) []byte {
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return pemKey
}
