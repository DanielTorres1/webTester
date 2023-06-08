package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/html"
)

func getHtml(url string) (*html.Node, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return html.Parse(resp.Body)
}

func checkAttr(t html.Token, key string, value string) (ok bool) {
	for _, a := range t.Attr {
		if a.Key == key {
			if a.Val == value {
				return true
			}
		}
	}
	return false
}

func printNode(n *html.Node) {
	fmt.Print("<a ")
	for _, a := range n.Attr {
		fmt.Print(a.Key, "=\"", a.Val, "\" ")
	}
	fmt.Print(">")
	if n.FirstChild != nil {
		fmt.Print(n.FirstChild.Data)
	}
	fmt.Println("</a>")
}

func main() {
	flag.Parse()
	arg := flag.Arg(0)
	if arg == "" {
		fmt.Println("Usage: go run script.go <url>")
		return
	}
	doc, err := getHtml(arg)
	if err != nil {
		fmt.Println(err)
		return
	}
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			t := html.Token{Type: html.StartTagToken, Data: n.Data, Attr: n.Attr}
			if checkAttr(t, "target", "_blank") && !(checkAttr(t, "rel", "noopener noreferrer") || checkAttr(t, "rel", "noreferrer noopener")) {
				printNode(n)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
}
