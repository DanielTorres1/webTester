package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var myURL string

func init() {
	flag.StringVar(&myURL, "url", "", "URL to make a request to")
	flag.Parse()
}

func main() {
	if myURL == "" {
		fmt.Println("Usage: go run main.go -url=https://example.com")
		return
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionSSL30,
			MaxVersion:         tls.VersionTLS13,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(myURL)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	xPoweredBy := resp.Header.Get("X-Powered-By")

	if server != "" {
		splitServer := strings.Split(server, "/")
		if len(splitServer) > 1 {
			fmt.Printf("Server version: %s (Vulnerable)\n", splitServer[1])		
		}
	}

	if xPoweredBy != "" {
		fmt.Printf("X-Powered-By: %s (Vulnerable)\n", xPoweredBy)
	}
}

