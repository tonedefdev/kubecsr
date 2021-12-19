package api

import (
	"time"

	"github.com/tonedefdev/kubecsr/pkg/csr"
)

type KubeCSR struct {
	CertificateRequest *csr.CSR        `json:"certificateRequest" binding:"required"`
	ExpirationSeconds  *int32          `json:"expirationSeconds,omitempty"`
	Kubeconfig         string          `json:"kubeconfig" binding:"required"`
	RequestMetadata    RequestMetadata `json:"requestMetadata"`
}

type RequestMetadata struct {
	Timestamp   time.Time `json:"timestamp"`
	RequesterIP string    `json:"requesterIP"`
}
