package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type kubeconfig struct {
	ClusterName string    `json:"clusterName,required"`
	Timestamp   time.Time `json:"timestamp"`
	RequesterIP string    `json:"requesterIP"`
	User        string    `json:"user,required"`
}

var kubeconfigs = []kubeconfig{}
var requiredToken string

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

		c.Next()
	}
}

// getKubeconfig responds with the list of all kubeeconfigs requested as JSON
func getKubeconfig(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, kubeconfigs)
}

// initToken creates the initial token if one is not provided and outputs it to the server log
func initToken() string {
	token := uuid.New().String()
	log.Printf("The automatitcally generated API authorization token is '%s'", token)
	return token
}

// createKubconfig adds a request to create a Kubernetes CSR and approve it
func createKubeconfig(c *gin.Context) {
	var newKubeconfig kubeconfig

	// Bind the request to the kubeconfig struct
	if err := c.BindJSON(&newKubeconfig); err != nil {
		return
	}

	// Validate that required fields aren't empty
	switch {
	case newKubeconfig.ClusterName == "":
		respondWithError(c, 400, "ClusterName is required")
		return
	case newKubeconfig.User == "":
		respondWithError(c, 400, "User is required")
		return
	}

	// Add timestamp to request
	newKubeconfig.Timestamp = time.Now()

	// Add requester's IP
	newKubeconfig.RequesterIP = c.Request.RemoteAddr

	// Add the new kubeconfig to the slice
	kubeconfigs = append(kubeconfigs, newKubeconfig)
	c.IndentedJSON(http.StatusCreated, newKubeconfig)
}

func main() {
	// Set and parse startup flags
	flagCustomToken := flag.Bool("use-custom-token", false, "When true this starts the service with a user generated token instead of automatically generating a token")
	flagToken := flag.String("custom-token", "", "The custom token to use for authorizing API requests")
	flag.Parse()

	// Set API token used for authorizing API calls
	if *flagCustomToken == true {
		requiredToken = *flagToken
	} else {
		requiredToken = initToken()
	}

	// Setup gin router
	router := gin.Default()
	router.Use(tokenAuthorization())
	router.GET("/kubeconfig", getKubeconfig)
	router.POST("/kubeconfig", createKubeconfig)
	router.Run("localhost:8080")
}
