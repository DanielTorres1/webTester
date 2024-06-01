package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"io/ioutil"
	"golang.org/x/net/html"
)

func main() {
	// Define la URL como un parámetro
	url := flag.String("url", "", "URL para obtener los nombres de los archivos")
	flag.Parse()

	// Muestra cómo usar el script si no se proporciona la URL
	if *url == "" {
		fmt.Println("Por favor, proporciona una URL. Uso: listDir -url=<tu_url>")
		os.Exit(1)
	}

	// Configura el cliente HTTP para ignorar la validación del certificado TLS y establece el timeout
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(10 * time.Second)}

	// Realiza la petición GET a la URL
	resp, err := client.Get(*url)
	if err != nil {
		//fmt.Println("Error al hacer la petición:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error al leer el cuerpo de la respuesta:", err)
		os.Exit(1)
	}

	htmlContent := string(body)
	results := parseDirectoryListing(htmlContent)
	for _, result := range results {
		fmt.Println(result)
	}
}



func parseDirectoryListing(htmlContent string) []string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		panic(err)
	}

	var results []string
	var walkFunc func(*html.Node)

	walkFunc = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			var cells []string
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && c.Data == "td" {
					cell := strings.TrimSpace(extractText(c))
					cells = append(cells, cell)
				}
			}

			if len(cells) >= 5 {
				//fileType := cells[0]
				fileName := cells[1]
				modifiedDate := cells[2]
				fileSize := cells[3]

				entryType := "[FILE]"
				if fileSize == "-" {
					entryType = "[DIR]"
				}

				result := fmt.Sprintf("%s| %s | %s| %s", entryType, fileName, modifiedDate, fileSize)
				results = append(results, result)
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkFunc(c)
		}
	}

	walkFunc(doc)
	return results
}

func extractText(n *html.Node) string {
	var text strings.Builder
	var extractTextHelper func(*html.Node)

	extractTextHelper = func(n *html.Node) {
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractTextHelper(c)
		}
	}

	extractTextHelper(n)
	return text.String()
}