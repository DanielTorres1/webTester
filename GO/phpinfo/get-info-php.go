package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	url := os.Args[1]

	// Create a custom HTTP client that skips certificate verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error fetching URL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	content := string(body)
	content = strings.ReplaceAll(content, "'", "\"")

	if !regexp.MustCompile(`PHP Version`).MatchString(content) {
		fmt.Printf("%s is not a PHPinfo file\n", url)
		return
	}

	printValue(content, "System", `System <\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "COMPUTERNAME", `COMPUTERNAME <\/td><td class="v">(.*?)<\/td>`, `SERVER\["COMPUTERNAME"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "USERNAME", `USERNAME <\/td><td class="v">(.*?)<\/td>`, `SERVER\["USERNAME"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "USERDOMAIN", `USERDOMAIN <\/td><td class="v">(.*?)<\/td>`, `SERVER\["USERDOMAIN"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "HTTP_X_FORWARDED_SERVER", `SERVER\["HTTP_X_FORWARDED_SERVER"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "APPL_PHYSICAL_PATH", `SERVER\["APPL_PHYSICAL_PATH"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "SCRIPT_FILENAME", `SERVER\["SCRIPT_FILENAME"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "DOCUMENT_ROOT", `SERVER\["DOCUMENT_ROOT"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "SERVER_SOFTWARE", `SERVER\["SERVER_SOFTWARE"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "REMOTE_ADDR", `SERVER\["REMOTE_ADDR"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "REMOTE_HOST", `SERVER\["REMOTE_HOST"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "LOCAL_ADDR", `SERVER\["LOCAL_ADDR"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "SERVER_ADDR", `SERVER\["SERVER_ADDR"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "HTTP_X_FORWARDED_HOST", `SERVER\["HTTP_X_FORWARDED_HOST"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "HTTP_HOST", `SERVER\["HTTP_HOST"\]<\/td><td class="v">(.*?)<\/td>`)
	printValue(content, "SERVER_ADMIN", `SERVER\["SERVER_ADMIN"\]<\/td><td class="v">(.*?)<\/td>`)
}

func printValue(content, label, pattern string, extraPatterns ...string) {
	value := extractValue(content, pattern)
	if value == "" {
		for _, p := range extraPatterns {
			value = extractValue(content, p)
			if value != "" {
				break
			}
		}
	}
	if value != "" {
		fmt.Printf("%s: %s\n", label, value)
	}
}

func extractValue(content, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("Author: Daniel Torres Sandi")
	fmt.Println("phpinfo.go http://192.168.2.1:80/?phpinfo")
}
