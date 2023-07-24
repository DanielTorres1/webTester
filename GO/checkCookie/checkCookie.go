package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"time"
)

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) != 1 {
		fmt.Println("Forma de uso: go run main.go [url]")
		return
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionSSL30,
				MaxVersion:         tls.VersionTLS13,
			},
		},
		CheckRedirect: nil,
		Timeout:       10 * time.Second,
	}

	req, _ := http.NewRequest("GET", args[0], nil)

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			req.Header.Add("Connection", "close")
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)

	if err != nil {
		fmt.Printf("Hubo un error al hacer la solicitud: %v", err)
		return
	}

	defer resp.Body.Close()	

	for _, c := range resp.Cookies() {
		fmt.Printf("%s HttpOnly=%s\n", c.Name, check(c.HttpOnly))
		fmt.Printf("%s SameSite=%s\n", c.Name, check(c.SameSite != 0))
		fmt.Printf("%s Secure=%s\n", c.Name, check(c.Secure))
	}
}

func check(b bool) string {
	if b {
		return "OK"
	} else {
		return "NO OK"
	}
}

