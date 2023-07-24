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
	target = flag.String("target", "", "Target IP or domain")
	logs   = flag.Bool("logs", false, "Save the response to a log file")
)

func main() {
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: go run main.go -target=[target] [-logs]")
		os.Exit(1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ExpectContinueTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	responses := make(map[int]string)
	for _, port := range []int{443, 80} {
		url := fmt.Sprintf("http://%s:%d", *target, port)
		if port == 443 {
			url = fmt.Sprintf("https://%s:%d", *target, port)
		}

		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		body, _ := ioutil.ReadAll(resp.Body)
		responses[port] = string(body)

		if *logs {
			ioutil.WriteFile(fmt.Sprintf("%s_%d.txt", *target, port), body, 0644)
		}
	}

	len443 := len(responses[443])
	len80 := len(responses[80])

	var result string
	switch {
	case len443 == 0 && len80 == 0:
		result = "OK"
	case len80 > 0 && len443 == 0:
		result = "vulnerable"
	case float64(len443)*0.9 <= float64(len80) && float64(len80)*0.9 <= float64(len443):
		result = "vulnerable"
	default:
		result = "OK"
	}

	fmt.Printf("Longitud respuesta puerto 443 | Longitud respuesta puerto 80 | Resultado\n")
	fmt.Printf("%d | %d | %s\n", len443, len80, result)
}
