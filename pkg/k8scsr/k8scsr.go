package k8scsr

import (
	"context"

	"github.com/tonedefdev/kubecsr/api"
	cert "k8s.io/api/certificates/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesCSR struct {
	CertificateRequest []byte
	ExpirationSeconds  *int32
}

var ctx = context.Background()

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

func (k8scsr *KubernetesCSR) CreateKubernetesCSR(client *kubernetes.Clientset, kubeCSR api.KubeCSR) (*cert.CertificateSigningRequest, error) {
	objectMeta := meta.ObjectMeta{
		Name: kubeCSR.User,
	}

	typeMeta := meta.TypeMeta{
		APIVersion: "certificates.k8s.io/v1",
		Kind:       "CertificateSigningRequest",
	}

	usage := make([]cert.KeyUsage, 1)
	usage[0] = "client auth"

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

func (k8scsr *KubernetesCSR) GetKubernetesCSR(client *kubernetes.Clientset, kubeCSR api.KubeCSR) *cert.CertificateSigningRequest {
	typeMeta := meta.TypeMeta{
		APIVersion: "certificates.k8s.io/v1",
		Kind:       "CertificateSigningRequest",
	}

	get := meta.GetOptions{
		TypeMeta: typeMeta,
	}

	csr, _ := client.CertificatesV1().CertificateSigningRequests().Get(ctx, kubeCSR.User, get)
	return csr
}
