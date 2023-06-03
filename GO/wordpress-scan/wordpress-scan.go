package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Route struct {
	Name string
	Path string
}

var routes = []Route{
	{"loginizer", "wp-content/plugins/loginizer/"},
	{"smart-recent-posts-widget", "wp-content/plugins/smart-recent-posts-widget/"},
	{"WooCommerce abandoned cart", "wp-content/plugins/abandoned-cart/"},
}

func main() {
	url := flag.String("url", "", "URL to check")
	flag.Parse()

	if *url == "" {
		fmt.Println("Usage: go run script.go -url=<url>")
		os.Exit(1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(10 * time.Second)}

	fmt.Println("Nombre | Status Code | Resultado")
	for _, route := range routes {
		resp, err := client.Head(*url + route.Path)
		if err != nil {
			fmt.Printf("%s | Error | %v\n", route.Name, err)
			continue
		}
		defer resp.Body.Close()

		result := "OK"
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			result = "Vulnerable"
		}

		fmt.Printf("%s | %d | %s\n", route.Name, resp.StatusCode, result)
	}
}
