function print_ascii_art {
cat << "EOF"
AD TESTER
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


pip3 install pycryptodome pycrypto --break-system-packages #error
cp ADtester.sh /usr/bin/

echo -e "${RED}[+]${BLUE} Instalar librerias ${RESET}"
apt-get install bloodhound neo4j rdate krb5-config libkrb5-dev wmi-client

echo -e "${RED}[+]${BLUE} Instalar bloodhound ${RESET}"
pip3 install bloodhound future ldap3 dnspython
pip3 install certipy-ad

echo -e "${RED}[+]${BLUE} Instalar Certipy ${RESET}"
cd Certipy
python3 setup.py install 
cd ..

echo -e "${RED}[+]${BLUE} Instalar pywerview ${RESET}"
cd pywerview
docker build -t pywerview .
cd ..

cp -r ADTestBin /usr/bin/
chmod a+x /usr/bin/ADTestBin/*

echo -e "${GREEN} [+] Modificando PATH ${RESET}"
egrep -iq 'ADTestBin' ~/.bashrc
greprc=$?
if [[ $greprc -eq 1 ]] ; then #Si no tiene adicionado PATH    
	echo export PATH="$PATH:/usr/bin/ADTestBin" >> ~/.bashrc
	echo export PATH="$PATH:/usr/bin/ADTestBin" >> ~/.zshrc
fi

egrep -iq 'ADTestBin' ~/.zshrc
greprc=$?
if [[ $greprc -eq 1 ]] ; then #Si no tiene adicionado PATH    
	echo export PATH="$PATH:/usr/bin/ADTestBin" >> ~/.zshrc
	echo export PATH="$PATH:/usr/bin/ADTestBin" >> ~/.zshrc
fi

echo -e "${RED}[+]${BLUE} Instalar ItWasAllADream ${RESET}"
cd ItWasAllADream
	docker build -t itwasalladream . 
cd ..


#pip3 install wrapper wmi-client-wrapper barcodenumber