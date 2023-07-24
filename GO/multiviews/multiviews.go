package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"time"
)

func main() {
	url := flag.String("url", "", "URL to send request to")
	flag.Parse()

	if *url == "" {
		fmt.Println("Usage: go run script.go -url=<URL>")
		return
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionTLS13,
	}

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	req, _ := http.NewRequest("GET", *url+"index", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0")
	req.Header.Set("Accept", "application/whatever; q=1.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	alternates := resp.Header.Get("Alternates")
	result := "ok"
	if alternates != "" {
		result = "vulnerable"
	}

	if alternates != "" {
		fmt.Printf("%d|%s|Alternates: %s\n", resp.StatusCode, result, alternates)
	} else {
		fmt.Printf("%d|%s|\n", resp.StatusCode, result)
	}
}
