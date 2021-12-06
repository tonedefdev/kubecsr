package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type kubecsr struct {
	ClusterName string    `json:"clusterName" binding:"required"`
	Timestamp   time.Time `json:"timestamp"`
	RequesterIP string    `json:"requesterIP"`
	User        string    `json:"user,required" binding:"required"`
}

var kubecsrs = []kubecsr{}
var requiredToken string

// base64EncodeStr takes a string and returns a base64 encoded string
func base64EncodeStr(str string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(str))
	return encoded
}

// createKubconfig adds a request to create a Kubernetes CSR and approve it
func createkubecsr(c *gin.Context) {
	var newkubecsr kubecsr

	// Bind the request to the kubecsr struct
	if err := c.ShouldBindJSON(&newkubecsr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Add timestamp to request
	newkubecsr.Timestamp = time.Now()

	// Add requester's IP
	newkubecsr.RequesterIP = c.Request.RemoteAddr

	// Add the new kubecsr to the slice
	kubecsrs = append(kubecsrs, newkubecsr)
	c.JSON(http.StatusCreated, newkubecsr)
}

// getkubecsr responds with the list of all kubeeconfigs requested as JSON
func getkubecsr(c *gin.Context) {
	c.JSON(http.StatusOK, kubecsrs)
}

// initToken creates the initial token if one is not provided and outputs it to the server log
func initToken() string {
	token := uuid.New().String()
	encodedToken := base64EncodeStr(token)
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
		token := c.Request.Header.Get("Bearer")

		// Validate token isn't empty
		if token == "" {
			respondWithError(c, 401, "API token required")
			return
		}

		// Validate that token is expected token
		if requiredToken != token {
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
		requiredToken = base64EncodeStr(*flagCustomToken)
	} else {
		requiredToken = initToken()
	}

	// Setup gin router
	router := gin.Default()

	// Setup token authorization middleware
	router.Use(tokenAuthorization())

	// Setup routes
	router.GET("/kubecsr", getkubecsr)
	router.POST("/kubecsr", createkubecsr)

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
