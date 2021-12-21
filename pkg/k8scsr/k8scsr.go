package k8scsr

import (
	"context"

	"github.com/tonedefdev/kubecsr/api"
	cert "k8s.io/api/certificates/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesCSR struct {
	// An x509 Certificate Request byte slice
	CertificateRequest []byte
	// The expiration time of the generated Kubernetes certificate
	ExpirationSeconds *int32
}

var ctx = context.Background()

// NewKubernetesClient creates a Kubernetes client by reading the Kubeconfig
// that is provided
func NewKubernetesClient(kubeConfig string) (*kubernetes.Clientset, error) {
	// Use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		return nil, err
	}

	// Create the Kubernetes Client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, err
}

// ApproveKubernetesCSR approves a Kubernetes CSR and returns any errors encountered during
// the approval process
func (k8scsr *KubernetesCSR) ApproveKubernetesCSR(client *kubernetes.Clientset, csr *cert.CertificateSigningRequest) error {
	conditions := make([]cert.CertificateSigningRequestCondition, 0)
	condition := cert.CertificateSigningRequestCondition{
		Message: "Automatically approved by KubeCSR",
		Status:  core.ConditionTrue,
		Type:    cert.CertificateApproved,
	}

	conditions = append(conditions, condition)
	csr.Status.Conditions = conditions

	typeMeta := meta.TypeMeta{
		APIVersion: "certificates.k8s.io/v1",
		Kind:       "CertificateSigningRequest",
	}

	update := meta.UpdateOptions{
		TypeMeta: typeMeta,
	}
	_, err := client.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, update)
	return err
}

// CreateKubernetesCSR submits a CSR request to the Kubernetes cluster defined in the supplied Kubeconfig
func (k8scsr *KubernetesCSR) CreateKubernetesCSR(client *kubernetes.Clientset, kubeCSR api.KubeCSR) (*cert.CertificateSigningRequest, error) {
	objectMeta := meta.ObjectMeta{
		Name: kubeCSR.CertificateRequest.User,
	}

	typeMeta := meta.TypeMeta{
		APIVersion: "certificates.k8s.io/v1",
		Kind:       "CertificateSigningRequest",
	}

	usage := make([]cert.KeyUsage, 1)
	usage[0] = cert.UsageClientAuth

	csrSpec := cert.CertificateSigningRequestSpec{
		ExpirationSeconds: k8scsr.ExpirationSeconds,
		Request:           k8scsr.CertificateRequest,
		SignerName:        "kubernetes.io/kube-apiserver-client",
		Usages:            usage,
	}

	csr := &cert.CertificateSigningRequest{
		ObjectMeta: objectMeta,
		TypeMeta:   typeMeta,
		Spec:       csrSpec,
	}

	create := meta.CreateOptions{
		TypeMeta: typeMeta,
	}

	req, err := client.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, create)
	return req, err
}

// GetKubernetesCSR returns a Kubernetes CSR if found but does not return any errors encountered
func (k8scsr *KubernetesCSR) GetKubernetesCSR(client *kubernetes.Clientset, kubeCSR api.KubeCSR) *cert.CertificateSigningRequest {
	typeMeta := meta.TypeMeta{
		APIVersion: "certificates.k8s.io/v1",
		Kind:       "CertificateSigningRequest",
	}

	get := meta.GetOptions{
		TypeMeta: typeMeta,
	}

	csr, _ := client.CertificatesV1().CertificateSigningRequests().Get(ctx, kubeCSR.CertificateRequest.User, get)
	return csr
}
