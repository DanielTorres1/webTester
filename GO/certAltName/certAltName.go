package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Uso: go run main.go [IP] [PUERTO (opcional, por defecto 443)]")
		os.Exit(1)
	}

	ip := os.Args[1]
	port := "443"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	dialer := &net.Dialer{
		Timeout: time.Second * 10,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%s", ip, port), &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		fmt.Println("Error al establecer la conexión:", err)
		os.Exit(1)
	}
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		fmt.Println("Error en el handshake:", err)
		os.Exit(1)
	}

	certificates := conn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		fmt.Println("No se encontraron certificados")
		os.Exit(1)
	}

	cert := certificates[0]

	if len(cert.DNSNames) > 0 {
		for _, altName := range cert.DNSNames {
			fmt.Println("altName:", altName)
		}
	} else {
		fmt.Println("No se encontró el campo 'Subject Alternative Name'")
	}
}
