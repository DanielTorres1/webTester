package main

import (
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
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
		Timeout:   10 * time.Second,
		// Eliminamos la configuración CheckRedirect para permitir redirecciones
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
		var bodyReader io.ReadCloser
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			bodyReader, err = gzip.NewReader(resp.Body)
			if err != nil {
				fmt.Println("Error al descomprimir la respuesta gzip")
				os.Exit(1)
			}
			defer bodyReader.Close()
		default:
			bodyReader = resp.Body
		}

		// Lee el cuerpo de la respuesta
		bodyBytes, err := ioutil.ReadAll(bodyReader)
		if err != nil {
			fmt.Println("Error al leer el cuerpo de la respuesta")
			os.Exit(1)
		}
		bodyString := string(bodyBytes)

		// Extrae contraseñas del cuerpo de la respuesta
		extractPasswords(bodyString)
	}
}

// Función para extraer contraseñas del cuerpo de la respuesta
func extractPasswords(bodyString string) {
	passwordRegexps := []*regexp.Regexp{
		regexp.MustCompile(`"password":"([^"]*)"`), // Captura todo después de "password":
		regexp.MustCompile(`'password':\{([^}]*)\}`), // Captura todo dentro del objeto de 'password'
	}

	for _, re := range passwordRegexps {
		matches := re.FindAllStringSubmatch(bodyString, -1)
		for _, match := range matches {
			if len(match) > 1 {
				fmt.Println("Contraseña encontrada:", match[1])
			}
		}
	}
}
