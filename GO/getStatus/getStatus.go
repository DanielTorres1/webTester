package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

func main() {
	// Define la URL como un parámetro de línea de comandos
	url := flag.String("url", "", "URL para hacer la petición")
	flag.Parse()

	// Verifica que la URL no esté vacía
	if *url == "" {
		fmt.Println("Uso: script -url https://ejemplo.com")
		os.Exit(1)
	}

	// Crea un cliente HTTP que no verifica los certificados TLS y tiene un timeout de 10 segundos
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   3 * time.Second,
	}

	// Crea una nueva petición GET
	req, err := http.NewRequest("GET", *url, nil)
	if err != nil {
		fmt.Println("Error al crear la petición")
		os.Exit(1)
	}

	// Configura las cabeceras de la petición
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")

	// Realiza la petición GET
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Network error")
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Comprueba si el código de estado tiene más de 3 caracteres
	statusCode := strconv.Itoa(resp.StatusCode)
	if len(statusCode) > 3 {
		fmt.Println("Network error")
	} else {
		// Lee el cuerpo de la respuesta
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error al leer el cuerpo de la respuesta")
			os.Exit(1)
		}
		bodyString := string(bodyBytes)

		// Define las expresiones regulares
		errorRegexps := []*regexp.Regexp{
			regexp.MustCompile(`(?i)404\s+not\s+found`),
			regexp.MustCompile(`(?i)404\s+no\s+encontrado`),
		}

		// Busca las cadenas en el cuerpo
		errorMsg := ""
		for _, re := range errorRegexps {
			matches := re.FindStringSubmatch(bodyString)
			if len(matches) > 0 {
				errorMsg = matches[0]
				break
			}
		}

		// Imprime el código de estado HTTP final junto con el mensaje de error, si se encuentra alguno
		if errorMsg != "" {
			fmt.Printf("%d:%s\n", resp.StatusCode, errorMsg)
		} else {
			fmt.Println(resp.StatusCode)
		}
	}
}
