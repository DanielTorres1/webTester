package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	addr = flag.String("addr", "", "IP address or domain to check")
	logs = flag.Bool("logs", false, "Save responses to .txt files")
)

func main() {
	flag.Parse()

	if *addr == "" {
		fmt.Println("Usage: go run main.go -addr=<ip_or_domain> [-logs]")
		os.Exit(1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
	}

	client := &http.Client{Transport: tr}

	resp1, err1 := client.Get("https://" + *addr)
	resp2, err2 := client.Get("http://" + *addr)

	var body1, body2 []byte
	var len1, len2 int

	if err1 != nil {
		fmt.Println("Error making request to port 443:", err1)
	} else {
		defer resp1.Body.Close()
		body1, _ = ioutil.ReadAll(resp1.Body)
		len1 = len(body1)
	}

	if err2 != nil {
		fmt.Println("Error making request to port 80:", err2)
	} else {
		defer resp2.Body.Close()
		body2, _ = ioutil.ReadAll(resp2.Body)
		len2 = len(body2)
	}

	result := "OK"
	if err1 != nil && err2 == nil {
		result = "vulnerable"
	} else if float64(len1) >= float64(len2)*0.9 && float64(len1) <= float64(len2)*1.1 {
		result = "vulnerable"
	}

	fmt.Printf("respuesta puerto 443 | respuesta puerto 80 | resultado\n")
	fmt.Printf("%d bytes| %d bytes| %s\n", len1, len2, result)

	if *logs {
		ioutil.WriteFile("response1.txt", body1, 0644)
		ioutil.WriteFile("response2.txt", body2, 0644)
	}
}
