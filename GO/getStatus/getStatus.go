package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
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
	}

	// Realiza la petición GET
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Println("Error al hacer la petición:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Imprime el código de estado HTTP final
	fmt.Println(resp.StatusCode)
}
