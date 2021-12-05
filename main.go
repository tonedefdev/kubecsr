package main

import (
	"encoding/base64"
	"flag"
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
	c.IndentedJSON(http.StatusCreated, newkubecsr)
}

// getkubecsr responds with the list of all kubeeconfigs requested as JSON
func getkubecsr(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, kubecsrs)
}

// initToken creates the initial token if one is not provided and outputs it to the server log
func initToken() string {
	token := uuid.New().String()
	encodedToken := base64EncodeStr(token)
	log.Printf("The automatitcally generated authorization bearer token is '%s'", encodedToken)
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
	flagCustomToken := flag.Bool("use-custom-token", false, "When true this starts the service with a user generated token instead of automatically generating a token")
	flagToken := flag.String("custom-token", "", "The custom token to use for authorizing API requests")
	flag.Parse()

	// Set API token used for authorizing API calls
	if *flagCustomToken == true {
		requiredToken = base64EncodeStr(*flagToken)
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
		Addr:           "localhost:443",
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Listen and serve with TLS
	if err := server.ListenAndServeTLS("localhost.crt", "localhost.key"); err != nil {
		log.Fatal(err)
	}
}
