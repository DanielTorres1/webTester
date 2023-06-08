package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const payload = `<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>`

func main() {
	urlArg := flag.String("url", "", "La URL a la que se va a hacer la petición POST")

	flag.Parse()

	if *urlArg == "" {
		fmt.Println("Uso: go run main.go -url=[url]")
		os.Exit(1)
	}

	// Configura el proxy
	//proxyURL, _ := url.Parse("http://127.0.0.1:8083")

	// Ignora la verificación del certificado TLS y establece el proxy
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	//http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)

	client := &http.Client{
		Timeout: time.Duration(10 * time.Second),
	}

	req, _ := http.NewRequest("POST", *urlArg+"/xmlrpc.php", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Content-Type", "text/xml")

	// Establece el User-Agent para el más común en Windows
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("El request falló con error: %s\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	fmt.Println("Respuesta:")
	fmt.Printf("%s\n", body)
}
