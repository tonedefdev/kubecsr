package kubeconfig

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path"

	"github.com/ghodss/yaml"
	"github.com/tonedefdev/kubecsr/api"
	kc "k8s.io/kops/pkg/kubeconfig"
)

type Kubeconfig struct {
	// The certificate generated via the approved Kubernetes CSR
	Certifcate []byte
	// The private key that was originally generated for the request and Kubernetes CSR
	PrivateKey []byte
	// The user name that should be leveraged by the Kubeconfig
	User string
}

// Base64DecodeString takes in a base64 encoded string and returns a byte slice
func Base64DecodeString(kubeconfig string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(kubeconfig)
	return decoded, err
}

// Base64EncodeStr takes a string and returns a base64 encoded string
func Base64EncodeStr(str string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(str))
	return encoded
}

// Base64EncodeByte takes a byte slice and returns a base64 encoded string
func Base64EncodeByte(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	return encoded
}

// UnmarshalKubeconfig unmarshals a Kubeconfig byte slice and returns a KubectlConfig
func UnmarshalKubeconfig(kubeconfig []byte) (*kc.KubectlConfig, error) {
	var unmarshalKubeconfig *kc.KubectlConfig = &kc.KubectlConfig{}
	newJson, err := yaml.YAMLToJSON(kubeconfig)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(newJson, unmarshalKubeconfig)
	return unmarshalKubeconfig, err
}

// NewDirectory verifies if a path exists and creates the path if an error is encountered
func NewDirectory(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir(path, 0755)
			return err
		}
	}
	return nil
}

// NewKubeconfig creates a Kubeconfig from the approved Kubernetes CSR certificate and the private key
// initially used to generate the certificate request
func (newKubeconfig *Kubeconfig) NewKubeconfig(adminKubeconfig *kc.KubectlConfig) (string, error) {
	cluster := kc.KubectlCluster{
		CertificateAuthorityData: adminKubeconfig.Clusters[0].Cluster.CertificateAuthorityData,
		Server:                   adminKubeconfig.Clusters[0].Cluster.Server,
	}

	clusterName := &kc.KubectlClusterWithName{
		Cluster: cluster,
		Name:    adminKubeconfig.Clusters[0].Name,
	}

	clusters := append(make([]*kc.KubectlClusterWithName, 1), clusterName)

	context := kc.KubectlContext{
		Cluster: adminKubeconfig.Contexts[0].Context.Cluster,
		User:    newKubeconfig.User,
	}

	contextName := &kc.KubectlContextWithName{
		Name:    newKubeconfig.User,
		Context: context,
	}

	contexts := append(make([]*kc.KubectlContextWithName, 1), contextName)

	user := kc.KubectlUser{
		ClientCertificateData: newKubeconfig.Certifcate,
		ClientKeyData:         newKubeconfig.PrivateKey,
	}

	userName := &kc.KubectlUserWithName{
		Name: newKubeconfig.User,
		User: user,
	}

	users := append(make([]*kc.KubectlUserWithName, 1), userName)

	kubeconfig := &kc.KubectlConfig{
		ApiVersion:     "v1",
		Kind:           "Config",
		CurrentContext: newKubeconfig.User,
		Clusters:       clusters,
		Contexts:       contexts,
		Users:          users,
	}

	yamlKube, err := yaml.Marshal(kubeconfig)
	if err != nil {
		return "", err
	}

	yamlConfig := Base64EncodeByte(yamlKube)
	return yamlConfig, err
}

// ReadKubeconfig reads the Kubeconfig provided and returns a byte slice
func ReadKubeconfig(filename string) ([]byte, error) {
	file, err := os.ReadFile(filename)
	return file, err
}

// WriteKubeconfigToFile decodes a base64 encoded Kubeconfig and writes it to file
// so that it can be used later on by the Kubernetes client to make requests
func WriteKubeconfigToFile(kubeCSR api.KubeCSR, filename string) error {
	kubeconfig, err := Base64DecodeString(kubeCSR.Kubeconfig)
	if err != nil {
		return err
	}

	kubePath := path.Join(os.Getenv("HOME"), ".kube")
	err = NewDirectory(kubePath)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, string(kubeconfig))
	if err != nil {
		return err
	}

	return file.Sync()
}
