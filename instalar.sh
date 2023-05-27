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

echo -e "${RED}[+]${BLUE} Copiando ejecutables GO ${RESET}"
cp GO/getStatus/getStatus /usr/bin/pentest
cp GO/listDir/listDir /usr/bin/pentest
cp GO/SAP-scan/SAP-scan /usr/bin/pentest
cp GO/getCert/get_ssl_cert /usr/bin/pentest
cp GO/allow-http/allow-http /usr/bin/pentest
cp GO/multiviews/multiviews /usr/bin/pentest
cp GO/check_blank_target/check_blank_target /usr/bin/pentest

echo -e "${GREEN} [+] Copiando archivos ${RESET}"
cp webTester.sh /usr/bin