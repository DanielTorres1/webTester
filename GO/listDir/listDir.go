package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

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
		fmt.Println("Error al hacer la petición:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Parsea el HTML de la respuesta
	doc, err := html.Parse(resp.Body)
	if err != nil {
		fmt.Println("Error al parsear el HTML:", err)
		os.Exit(1)
	}

	// Busca los nombres de los archivos en el HTML
	var f func(*html.Node)
	tdCount := 0
	trCount := 0
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "td" {
			tdCount++
		}
		if n.Type == html.ElementNode && n.Data == "tr" {
			trCount++
			tdCount = 0
		}
		if tdCount == 2 && trCount >= 3 && n.Type == html.TextNode && strings.TrimSpace(n.Data) != "" {
			fmt.Println(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
}
