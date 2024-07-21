package main

import (
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"strings"
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

	// Crea un cliente HTTP que no verifica los certificados TLS, tiene un timeout de 10 segundos y no sigue redirecciones
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
		//fmt.Printf("%s \n", bodyString)

		/////////////////// buscar Full Path Disclosure /////
		FPD:= ""
		FPDStrings := []string{
			"/var/www/html",
			"/usr/local/apache2/htdocs/",
			"C:/xampp/htdocs/",
			"C:/wamp64/www/",
			"/var/www/nginx-default",
			"/usr/share/nginx/html",
		}

		// Search for each string in the bodyString
		for _, searchString := range FPDStrings {
			if strings.Contains(bodyString, searchString) {
				FPD = searchString
			}
		}
		///////////////////////////////////////

		/////////// busca de errores 404 cuando devuelve 200 OK///////
		// Define las expresiones regulares
		errorRegexps := []*regexp.Regexp{
			regexp.MustCompile(`(?i)404\s+not\s+found`),
			regexp.MustCompile(`(?i)404\s+no\s+encontrado`),
			regexp.MustCompile(`(?i)not found`),
			regexp.MustCompile(`(?i)You need to enable JavaScript to run this app`),
			regexp.MustCompile(`(?i)not-found`),
			regexp.MustCompile(`<app-root>`),
			regexp.MustCompile(`Log In to Payara Administration Console`),
			regexp.MustCompile(`Internal error`),
			regexp.MustCompile(`(?i)<div id="app">`),
			regexp.MustCompile(`(?i)<div class="wrapper" id="app">`),
			regexp.MustCompile(`(?i)page.not_found`),
			regexp.MustCompile(`(?i)<div id="root">`),
			regexp.MustCompile(`(?i)<body class="mat-typography">`),
			regexp.MustCompile(`ENTEL S.A.`), 
			regexp.MustCompile(`No existe el archivo`),
			regexp.MustCompile(`Request Rejected`),
			regexp.MustCompile(`Error de servidor`),
			regexp.MustCompile(`Unexpected end of document`),
			regexp.MustCompile(`This page can't be displayed`),
			regexp.MustCompile(`ALIVE FROM DJANGO`),
			regexp.MustCompile(`Uncaught Error`),
			regexp.MustCompile(`error Page`),
			regexp.MustCompile(`WordPress`),
			regexp.MustCompile(`Joomla`),
			regexp.MustCompile(`<body onload="startTime()">`),
			regexp.MustCompile(`<body class=" login">`),
			regexp.MustCompile(`Access denied`),
			regexp.MustCompile(`Parent Directory`),
			regexp.MustCompile(`<div id="back">`),
			regexp.MustCompile(`startTime`),
			regexp.MustCompile(`error-container`),
			regexp.MustCompile(`<div class="login-page">`),
			regexp.MustCompile(`BOOTSTRAP`),
			regexp.MustCompile(`script src`),
			regexp.MustCompile(`<div class="container">`),
			regexp.MustCompile(`__VIEWSTATE`),
			regexp.MustCompile(`Cannot modify header information`),
			regexp.MustCompile(`Cannot declare class`),
			regexp.MustCompile(`ajax_response_xml_root`),
			regexp.MustCompile(`An attack was detected`),
			regexp.MustCompile(`<body id="admin-login-wrapper">`),
			regexp.MustCompile(`<canvas id="canvas">`),
			regexp.MustCompile(`<div class="login-box">`),
			regexp.MustCompile(`name="generator"`),

			
			
			
			
			
			
		}

		//fmt.Println(bodyString)
		errorMsg := ""
		for _, re := range errorRegexps {
			matches := re.FindStringSubmatch(bodyString)
			if len(matches) > 0 {
				errorMsg = matches[0]
				break
			}
		}

		returnString := fmt.Sprintf("%d", resp.StatusCode)

		if resp.StatusCode != 404 && errorMsg != "" {
			returnString += ":" + errorMsg
		}

		if FPD != "" {
			returnString += ";" +  FPD
		}

		fmt.Println(returnString)

		
	}
}
