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
	target = flag.String("target", "", "Target IP or domain to scan")
	logs   = flag.Bool("logs", false, "Save responses to txt files")
)

func main() {
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: go run script.go -target=<ip or domain> [-logs]")
		os.Exit(1)
	}

	fmt.Println("longitud respuesta puerto 443 | longitud respuesta puerto 80 | resultado")

	resp443, err443 := makeRequest(*target, 443)
	resp80, err80 := makeRequest(*target, 80)

	result := compareResponses(len(resp443), len(resp80), err443, err80)

	fmt.Printf("%d | %d | %s\n", len(resp443), len(resp80), result)

	if *logs {
		ioutil.WriteFile("resp443.txt", []byte(resp443), 0644)
		ioutil.WriteFile("resp80.txt", []byte(resp80), 0644)
	}
}

func makeRequest(target string, port int) (string, error) {
	timeout := time.Duration(10 * time.Second)
	url := fmt.Sprintf("https://%s:%d", target, port)
	if port == 80 {
		url = fmt.Sprintf("http://%s", target)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	return string(body), nil
}

func compareResponses(lenResp443, lenResp80 int, err443, err80 error) string {
	if err443 != nil && err80 != nil {
		return "OK"
	}
	if lenResp80 > 0 && lenResp443 == 0 {
		return "vulnerable"
	}
	ratio := float64(lenResp443) / float64(lenResp80)
	if ratio >= 0.9 && ratio <= 1.1 {
		return "vulnerable"
	}
	return "OK"
}
