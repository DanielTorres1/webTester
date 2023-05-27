package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

func usage() {
	fmt.Println("Uso: ./script <URL>")
}

func getHTML(url string) (*goquery.Document, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: tr,
	}

	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("estado de respuesta: %d %s", res.StatusCode, res.Status)
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

func outerHTML(n *html.Node) string {
	var buf bytes.Buffer
	w := strings.NewReplacer("\n", "", "\t", "", "\r", "")
	html.Render(&buf, n)
	return w.Replace(buf.String())
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	doc, err := getHTML(os.Args[1])
	if err != nil {
		fmt.Println("Error al obtener el HTML:", err)
		os.Exit(1)
	}

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		target, exists := s.Attr("target")
		if exists && target == "_blank" {
			rel, exists := s.Attr("rel")
			if !exists || rel != "noopener noreferrer" {
				fmt.Println(outerHTML(s.Nodes[0]))
			}
		}
	})
}
