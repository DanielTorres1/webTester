package main

import (
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
	"strings"
)

func extractPasswords(bodyString string) {
	passwordRegexps := []*regexp.Regexp{
		regexp.MustCompile(`"password":"([^"]*)"`), // Captures everything after "password":
		regexp.MustCompile(`'password':\{([^}]*)\}`), // Captures everything inside the 'password' object
	}

	for _, re := range passwordRegexps {
		matches := re.FindAllStringSubmatch(bodyString, -1)
		for _, match := range matches {
			if len(match) > 1 {
				password := match[1]
				lowerPassword := strings.ToLower(password)
				// Verifica si password contiene "required" o "password"
				if strings.Contains(lowerPassword, "required") || strings.Contains(lowerPassword, "password") || strings.Contains(lowerPassword, "http") {
					continue
				}
				fmt.Println("Contraseña encontrada:", password)
			}
		}
	}
}

func extractIPInterna(bodyString string) {
	ipRegexps := []*regexp.Regexp{
		regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),    // Matches 10.x.x.x
		regexp.MustCompile(`\b172\.16\.\d{1,3}\.\d{1,3}\b`),        // Matches 172.16.x.x
		regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`),       // Matches 192.168.x.x
	}

	for _, re := range ipRegexps {
		matches := re.FindAllString(bodyString, -1)
		for _, match := range matches {
			fmt.Println("IP interna encontrada:", match)
		}
	}
}

func main() {
	// Define the URL and type as command-line parameters
	url := flag.String("url", "", "URL to make the request")
	extractType := flag.String("type", "", "Type of extraction: 'password' or 'IPinterna'")
	flag.Parse()

	// Verify that the URL and type are not empty
	if *url == "" || *extractType == "" {
		fmt.Println("Usage: script -url https://example.com -type password|IPinterna")
		os.Exit(1)
	}

	// Create an HTTP client that doesn't verify TLS certificates and has a timeout of 10 seconds
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	// Create a new GET request
	req, err := http.NewRequest("GET", *url, nil)
	if err != nil {
		fmt.Println("Error creating the request")
		os.Exit(1)
	}

	// Set the request headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")

	// Make the GET request
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	// Check if the status code has more than 3 characters
	statusCode := strconv.Itoa(resp.StatusCode)
	if len(statusCode) > 3 {
		fmt.Println("Network error")
	} else {
		var bodyReader io.ReadCloser
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			bodyReader, err = gzip.NewReader(resp.Body)
			if err != nil {
				fmt.Println("Error decompressing the gzip response")
				os.Exit(1)
			}
			defer bodyReader.Close()
		default:
			bodyReader = resp.Body
		}

		// Read the response body
		bodyBytes, err := ioutil.ReadAll(bodyReader)
		if err != nil {
			fmt.Println("Error reading the response body")
			os.Exit(1)
		}
		bodyString := string(bodyBytes)

		// Call the appropriate extraction function based on the type parameter
		switch *extractType {
		case "password":
			extractPasswords(bodyString)
		case "IPinterna":
			extractIPInterna(bodyString)
		default:
			fmt.Println("Invalid type. Use 'password' or 'IPinterna'")
			os.Exit(1)
		}
	}
}
