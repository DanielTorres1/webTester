package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type CertificateData struct {
	BusinessCategory        string   `json:"businessCategory,omitempty"`
	JurisdictionCountryName string   `json:"jurisdictionCountryName,omitempty"`
	CountryName             string   `json:"countryName,omitempty"`
	StateOrProvinceName     string   `json:"stateOrProvinceName,omitempty"`
	LocalityName            string   `json:"localityName,omitempty"`
	StreetAddress           string   `json:"streetAddress,omitempty"`
	OrganizationName        string   `json:"organizationName,omitempty"`
	CommonName              string   `json:"commonName,omitempty"`
	Subdomains              []string `json:"subdomains,omitempty"`
}

func getFirst(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: get_ssl_cert <ip> <port>")
		os.Exit(1)
	}

	ip := os.Args[1]
	port := os.Args[2]

	addr := net.JoinHostPort(ip, port)

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		fmt.Println("Failed to connect:", err)
		os.Exit(1)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = conn.HandshakeContext(ctx)
	if err != nil {
		fmt.Println("Failed to complete TLS handshake:", err)
		os.Exit(1)
	}

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Println("No certificates presented by server.")
		os.Exit(1)
	}

	cert := certs[0]

	certificateData := CertificateData{
		CountryName:         getFirst(cert.Subject.Country),
		StateOrProvinceName: getFirst(cert.Subject.Province),
		LocalityName:        getFirst(cert.Subject.Locality),
		StreetAddress:       getFirst(cert.Subject.StreetAddress),
		OrganizationName:    getFirst(cert.Subject.Organization),
		CommonName:          cert.Subject.CommonName,
		Subdomains:          cert.DNSNames,
	}

	certificateDataJson, _ := json.Marshal(certificateData)
	fmt.Println(string(certificateDataJson))
}
