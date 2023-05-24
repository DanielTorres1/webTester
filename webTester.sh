#!/bin/bash

OKBLUE='\033[94m'
THREADS="30"
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

while getopts ":t:d:h:u:p:" OPTIONS
do
            case $OPTIONS in
            t)     TARGET=$OPTARG;;
            d)     DOMAIN=$OPTARG;;
            h)     HOSTNAME=$OPTARG;;
            u)     USER=$OPTARG;;            
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TARGET=${TARGET:=NULL}
DOMAIN=${DOMAIN:=NULL}
HOSTNAME=${HOSTNAME:=NULL}
USER=${USER:=NULL}

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}
	
    

if [ "$TARGET" = NULL ] || [ "$DOMAIN" = NULL ]; then

cat << "EOF"

Opciones: 

-t : Target
-d : domain
-u : usuario
-h : DNS host name
-p : password

webTester.sh -t 192.168.0.1 -p 80 -w http
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
	mkdir -p logs/enumeracion
	mkdir -p logs/vulnerabilidades	
    mkdir responder
	cp /usr/share/lanscanner/.resultados.db .
fi	 



insert_data