package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tonedefdev/kubecsr/api"
	"github.com/tonedefdev/kubecsr/pkg/csr"
	"github.com/tonedefdev/kubecsr/pkg/k8scsr"
	"github.com/tonedefdev/kubecsr/pkg/kubeconfig"
)

var kubecsrs = []api.KubeCSR{}
var requiredToken string

// createKubconfig adds a request to create a Kubernetes CSR and approve it
func createKubeCSR(c *gin.Context) {
	var attempts = 0
	var crt []byte
	var newKubeCSR api.KubeCSR

	// Bind the request to the kubecsr struct
	if err := c.ShouldBindJSON(&newKubeCSR); err != nil {
		c.ShouldBindJSON(http.StatusBadRequest)
		return
	}

	csr := csr.CSR{
		User: newKubeCSR.CertificateRequest.User,
	}

	// Generate the RSA private key for the CSR
	key, err := csr.CreatePrivateKey()
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR unable to generate RSA private key")
		return
	}

	// Create the CSR passing in the previously created RSA private key
	newCSR, err := csr.CreateCSR(key)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR unable to create CSR")
		return
	}

	// Set the name and path of the admin Kubeconfig file
	filename := fmt.Sprintf("%s_admin_config", uuid.New().String())
	kubeConfigPath := path.Join(os.Getenv("HOME"), ".kube", filename)

	// From the request body decode the Kubeconfig and write it to disk
	// so it can be used to create a Kubernetes client
	err = kubeconfig.WriteKubeconfigToFile(newKubeCSR, kubeConfigPath)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR unable to write kubeconfig to file")
		return
	}

	// Pass in the Kubeconfig's path and create the Kubernetes client
	client, err := k8scsr.NewKubernetesClient(kubeConfigPath)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR unable to create a Kubernetes client")
		return
	}

	kubernetesCSR := k8scsr.KubernetesCSR{
		CertificateRequest: newCSR,
		ExpirationSeconds:  newKubeCSR.ExpirationSeconds,
	}

	// Create the Kubernetes CSR and pass in the Kubernetes client to make the request
	// and the KubeCSR struct
	req, err := kubernetesCSR.CreateKubernetesCSR(client, newKubeCSR)
	print(err)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR unable to create the Kubernetes CSR")
		return
	}

	// Approve the Kubernetes CSR
	err = kubernetesCSR.ApproveKubernetesCSR(client, req)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR unable to approve the Kubernetes CSR")
		return
	}

	// Check every 100ms to see if the Kubernetes cluster has generated the certificate
	// by checking the CSR's status field. This is required as a single pass is often too
	// fast resulting in the certificate being nil. After five attempts break out of the loop
	// and respond with an error
	for {
		if attempts > 4 {
			break
		}

		time.Sleep(100 * time.Millisecond)
		crtCheck := kubernetesCSR.GetKubernetesCSR(client, newKubeCSR)

		if crtCheck.Status.Certificate != nil {
			crt = crtCheck.Status.Certificate
			break
		}

		attempts++
	}

	if attempts > 4 {
		respondWithError(c, 400, errors.New("Unable to locate approved Kubernetes CSR"))
		return
	}

	// Pem encode the RSA private key
	pemKey := csr.PEMEncodePrivateKey(key)

	// Read the admin kubeconfig so we can load into memory
	readKubeconfig, err := kubeconfig.ReadKubeconfig(kubeConfigPath)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR was unable to read the admin Kubeconfig from file")
	}

	// Umarshal the Kubeconfig into a KubectlConfig struct so we can extract some of its data
	// to be used for the new user's Kubeconfig
	unmarshalAdminKube, err := kubeconfig.UnmarshalKubeconfig(readKubeconfig)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR was unable to unmarshal the admin Kubeconfig")
		return
	}

	kubeconfig := kubeconfig.Kubeconfig{
		Certifcate: crt,
		PrivateKey: pemKey,
		User:       newKubeCSR.CertificateRequest.User,
	}

	// Create the user's new Kubeconfig and return it as a base64 encoded string
	newKubeconfig, err := kubeconfig.NewKubeconfig(unmarshalAdminKube)
	if err != nil {
		log.Print(err)
		respondWithError(c, 400, "KubeCSR was unable to create a new Kubeconfig")
	}

	metadata := api.RequestMetadata{
		Timestamp:   time.Now(),
		RequesterIP: c.Request.RemoteAddr,
	}

	// Set the response body to include base64 encoded Kubeconfig
	newKubeCSR.Kubeconfig = newKubeconfig
	// Add the request metadata struct
	newKubeCSR.RequestMetadata = metadata

	// Add the new kubecsr to the slice
	kubecsrs = append(kubecsrs, newKubeCSR)
	c.JSON(http.StatusCreated, newKubeCSR)
}

// getKubeCSR responds with the list of all kubeconfigs requested as JSON
func getKubeCSR(c *gin.Context) {
	c.JSON(http.StatusOK, kubecsrs)
}

// initToken creates the initial token if one is not provided and outputs it to the server log
func initToken() string {
	token := uuid.New().String()
	encodedToken := kubeconfig.Base64EncodeStr(token)
	log.Printf("KubeCSR automatitcally generated the authorization bearer token as '%s'", encodedToken)
	return encodedToken
}

// Return a JSON formatted error response
func respondWithError(c *gin.Context, code int, message interface{}) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

// tokenAuthorization is middleware that validates that the request header bearer token matches the
// token used to initialize the service
func tokenAuthorization() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Get the Bearer token from the request header
		token := c.Request.Header.Get("Authorization")

		// Validate token isn't empty
		if token == "" {
			respondWithError(c, 401, "API token required")
			return
		}

		// Validate that token is expected token
		bearerToken := fmt.Sprintf("Bearer %s", requiredToken)
		if bearerToken != token {
			respondWithError(c, 401, "Invalid API token")
			return
		}
	}
}

func main() {
	// Set and parse startup flags
	flagCustomToken := flag.String("custom-token", "", "The custom token to use for authorizing API requests")
	flagEnableTLS := flag.Bool("enable-tls", false, "Enable TLS on the server. Requires that a TLS cert and key path are provided")
	flagHostname := flag.String("hostname", "localhost", "The hostname of the service. Defaults to localhost if not specified")
	flagPort := flag.Int("port", 8080, "The port to listen on. Defaults to 8080 if not provided")
	flagTLSCert := flag.String("tls-crt", "", "The path of the .crt file to initialize server with TLS")
	flagTLSKey := flag.String("tls-key", "", "The path of the .key file to initialize server with TLS")
	flagUseCustomToken := flag.Bool("use-custom-token", false, "When true this starts the service with a user generated token instead of automatically generating a token")
	flag.Parse()

	// Verify a TLS Cert and Key path have been provided if TLS is enabled
	if *flagEnableTLS {
		switch {
		case *flagTLSCert == "":
			log.Fatal("A cert must be provided to enable TLS")
			return
		case *flagTLSKey == "":
			log.Fatal("A private key must be provided to enable TLS")
			return
		}
	}

	// Set API token used for authorizing API a
	if *flagUseCustomToken {
		requiredToken = kubeconfig.Base64EncodeStr(*flagCustomToken)
	} else {
		requiredToken = initToken()
	}

	// Setup gin router
	router := gin.Default()

	// Setup token authorization middleware
	router.Use(tokenAuthorization())

	// Setup routes
	router.GET("/kubecsr", getKubeCSR)
	router.POST("/kubecsr", createKubeCSR)

	// Setup server
	server := http.Server{
		Addr:           fmt.Sprintf("%s:%d", *flagHostname, *flagPort),
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Log startup hostname and port
	log.Printf("KubeCSR server is starting up with hostname '%s' over port '%d'", *flagHostname, *flagPort)

	// Listen and serve with TLS if enabled
	if *flagEnableTLS {
		if err := server.ListenAndServeTLS(*flagTLSCert, *flagTLSKey); err != nil {
			log.Fatal(err)
		}
	}

	// If TLS disabled listen and serve without TLS
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
