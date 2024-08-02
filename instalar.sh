function print_ascii_art {
cat << "EOF"
WEB TESTER
			daniel.torres@owasp.org
			https://github.com/DanielTorres1

EOF
}


print_ascii_art

RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

echo -e "${GREEN} [+] Copiando archivos ${RESET}"
cp webTester.sh /usr/bin
cp -r pentest/* /usr/bin/pentest/
cp vhost-non-exist.txt /usr/share/lanscanner/vhost-non-exist.txt

echo -e "${RED}[+]${BLUE} Instalando librerias ${RESET}"
apt install -y httrack webhttrack

echo -e "${RED}[+]${BLUE} Instalando dalfox ${RESET}"
go install github.com/hahwul/dalfox/v2@latest
mv ~/go/bin/dalfox /usr/bin

echo -e "${RED}[+]${BLUE} Copiando ejecutables GO ${RESET}"

cp GO/checkHeadersServer/checkHeadersServer /usr/bin/pentest
cp GO/headi/headi /usr/bin/pentest
cp GO/checkCookie/checkCookie /usr/bin/pentest
cp GO/getStatus/getStatus /usr/bin/pentest
cp GO/phpinfo/get-info-php /usr/bin/pentest

cd GO/listDir
go mod download golang.org/x/net
go build listDir.go 
cp listDir /usr/bin/pentest
cd ../../

cp GO/SAP-scan/SAP-scan /usr/bin/pentest
cp GO/getCert/get_ssl_cert /usr/bin/pentest
cp GO/allow-http/allow-http /usr/bin/pentest
cp GO/multiviews/multiviews /usr/bin/pentest
cp GO/certAltName/certAltName /usr/bin/pentest
cp GO/wordpress-scan/wordpress-scan /usr/bin/pentest
cp GO/xml-rpc-test/xml-rpc-test /usr/bin/pentest
cp GO/xml-rpc-test/xml-rpc-login /usr/bin/pentest
cp GO/check_blank_target/check_blank_target /usr/bin/pentest
cp GO/validate-wordpress-user/validate-wordpress-user /usr/bin/pentest
cp GO/getExtract/getExtract /usr/bin/pentest


echo -e "${GREEN} [+] Instalar dependencias ${RESET}"
pip install sri-check  fake_useragent rich_click alive_progress faker hexdump --break-system-package
pip install droopescan  --break-system-package


echo -e "${RED}[+]${BLUE} katana ${RESET}"
go install github.com/projectdiscovery/katana/cmd/katana@latest
mv ~/go/bin/katana /usr/bin/katana

echo -e "${GREEN} [+] Instalar blackwidow ${RESET}"
cd BlackWidow
bash install.sh
cd ..

# echo -e "${GREEN} [+] Instalar DumpsterDiver ${RESET}"
# cd DumpsterDiver
# docker build -t dumpster-diver .  
# cd ..

