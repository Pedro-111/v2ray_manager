#!/bin/bash
# ╔═══════════════════════════════════════════════════════════════════╗
# ║                V2RAY ADVANCED MANAGER v3.1                       ║
# ║              Script de Gestión Completa - FIXED                  ║
# ╚═══════════════════════════════════════════════════════════════════╝

# Colores y símbolos para mejor experiencia visual
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Símbolos Unicode
SUCCESS="✅"
ERROR="❌"
WARNING="⚠️"
INFO="ℹ️"
ROCKET="🚀"
GEAR="⚙️"
SHIELD="🛡️"
LINK="🔗"
CERTIFICATE="📜"

# Variables globales - CONFIGURACIÓN MEJORADA
V2RAY_USER="v2ray"
V2RAY_GROUP="v2ray"
V2RAY_CONFIG_PATH="/etc/v2ray/config.json"
V2RAY_LOG_DIR="/var/log/v2ray"
CERT_PATH="/etc/v2ray/certs"
LOG_FILE="/var/log/v2ray_manager.log"
SYSTEMD_SERVICE_PATH="/etc/systemd/system/v2ray.service"

# Función de logging
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Función para mostrar banners elegantes
show_banner() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                    V2RAY ADVANCED MANAGER v3.1                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}                     Gestión Completa de V2Ray                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${GREEN}                      FIXED - PERMISOS CORREGIDOS                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Función para mostrar mensaje de carga
show_loading() {
    local message="$1"
    local duration=${2:-3}
    echo -ne "${YELLOW}${GEAR} $message"
    for i in $(seq 1 $duration); do
        sleep 1
        echo -ne "."
    done
    echo -e " ${GREEN}¡Completado!${NC}"
}

# Función para verificar si el script se ejecuta como root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${ERROR} ${RED}Este script debe ejecutarse como root${NC}"
        echo -e "${INFO} ${YELLOW}Usa: sudo $0${NC}"
        exit 1
    fi
}

# Función para crear usuario y grupo V2Ray
create_v2ray_user() {
    echo -e "${INFO} ${YELLOW}Configurando usuario y permisos del sistema...${NC}"

    # Verificar si el grupo ya existe
    if ! getent group "$V2RAY_GROUP" >/dev/null 2>&1; then
        groupadd --system "$V2RAY_GROUP"
        echo -e "${SUCCESS} ${GREEN}Grupo '$V2RAY_GROUP' creado${NC}"
    else
        echo -e "${INFO} ${CYAN}Grupo '$V2RAY_GROUP' ya existe${NC}"
    fi

    # Verificar si el usuario ya existe
    if ! getent passwd "$V2RAY_USER" >/dev/null 2>&1; then
        useradd --system --gid "$V2RAY_GROUP" --home-dir /var/lib/v2ray \
                --shell /usr/sbin/nologin --comment "V2Ray Daemon" "$V2RAY_USER"
        echo -e "${SUCCESS} ${GREEN}Usuario '$V2RAY_USER' creado${NC}"
    else
        echo -e "${INFO} ${CYAN}Usuario '$V2RAY_USER' ya existe${NC}"
    fi

    # Crear directorios necesarios con permisos correctos
    mkdir -p /var/lib/v2ray
    mkdir -p "$(dirname "$V2RAY_CONFIG_PATH")"
    mkdir -p "$V2RAY_LOG_DIR"
    mkdir -p "$CERT_PATH"

    # Establecer propietarios y permisos correctos
    chown "$V2RAY_USER:$V2RAY_GROUP" /var/lib/v2ray
    chown -R "$V2RAY_USER:$V2RAY_GROUP" "$(dirname "$V2RAY_CONFIG_PATH")"
    chown -R "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_LOG_DIR"
    chown -R "$V2RAY_USER:$V2RAY_GROUP" "$CERT_PATH"

    # Permisos de directorios
    chmod 755 /var/lib/v2ray
    chmod 755 "$(dirname "$V2RAY_CONFIG_PATH")"
    chmod 755 "$V2RAY_LOG_DIR"
    chmod 750 "$CERT_PATH"

    log_message "Usuario y grupo V2Ray configurados correctamente"
}

# Función automática para corregir permisos (sin interfaz de usuario)
fix_permissions_auto() {
    # 1. Verificar y crear usuario v2ray si no existe
    if ! getent passwd "$V2RAY_USER" >/dev/null 2>&1; then
        create_v2ray_user
    fi
    
    # 2. Crear y corregir directorio de logs
    mkdir -p "$V2RAY_LOG_DIR"
    chown -R "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_LOG_DIR"
    chmod 755 "$V2RAY_LOG_DIR"
    
    # Crear archivos de log si no existen
    touch "$V2RAY_LOG_DIR/access.log" "$V2RAY_LOG_DIR/error.log"
    chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_LOG_DIR/access.log" "$V2RAY_LOG_DIR/error.log"
    chmod 644 "$V2RAY_LOG_DIR/access.log" "$V2RAY_LOG_DIR/error.log"
    
    # 3. Corregir permisos del directorio de configuración
    mkdir -p "$(dirname "$V2RAY_CONFIG_PATH")"
    chown -R "$V2RAY_USER:$V2RAY_GROUP" "$(dirname "$V2RAY_CONFIG_PATH")"
    chmod 755 "$(dirname "$V2RAY_CONFIG_PATH")"
    
    # 4. Corregir archivo de configuración
    if [ -f "$V2RAY_CONFIG_PATH" ]; then
        chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
        chmod 644 "$V2RAY_CONFIG_PATH"
    fi
    
    # 5. Corregir directorio home de v2ray
    mkdir -p /var/lib/v2ray
    chown "$V2RAY_USER:$V2RAY_GROUP" /var/lib/v2ray
    chmod 755 /var/lib/v2ray
    
    # 6. Corregir permisos de certificados
    if [ -d "$CERT_PATH" ]; then
        chown -R "$V2RAY_USER:$V2RAY_GROUP" "$CERT_PATH"
        chmod 750 "$CERT_PATH"
        if [ -f "$CERT_PATH/v2ray.crt" ]; then
            chmod 644 "$CERT_PATH/v2ray.crt"
        fi
        if [ -f "$CERT_PATH/v2ray.key" ]; then
            chmod 600 "$CERT_PATH/v2ray.key"
        fi
    fi
    
    # 7. Verificar permisos del binario v2ray
    if [ -f "/usr/local/bin/v2ray" ]; then
        chmod +x /usr/local/bin/v2ray
    fi
    
    # 8. Recargar servicio systemd
    if [ -f "$SYSTEMD_SERVICE_PATH" ]; then
        systemctl daemon-reload
    fi
    
    log_message "Permisos del sistema corregidos automáticamente durante la instalación"
}

# Función para diagnosticar problemas de V2Ray
diagnose_v2ray() {
    echo -e "${INFO} ${YELLOW}Diagnosticando V2Ray...${NC}"
    echo ""
    
    # 1. Verificar estado del servicio
    echo -e "${INFO} ${CYAN}Estado del servicio:${NC}"
    systemctl status v2ray --no-pager -l
    echo ""
    
    # 2. Verificar configuración
    echo -e "${INFO} ${CYAN}Validando configuración:${NC}"
    if /usr/local/bin/v2ray test -config "$V2RAY_CONFIG_PATH"; then
        echo -e "${SUCCESS} ${GREEN}Configuración válida${NC}"
    else
        echo -e "${ERROR} ${RED}Configuración inválida${NC}"
    fi
    echo ""
    
    # 3. Verificar permisos
    echo -e "${INFO} ${CYAN}Verificando permisos:${NC}"
    echo -e "  ${WHITE}Usuario v2ray:${NC} $(id v2ray 2>/dev/null || echo 'No existe')"
    echo -e "  ${WHITE}Directorio logs:${NC} $(ls -ld $V2RAY_LOG_DIR 2>/dev/null || echo 'No existe')"
    echo -e "  ${WHITE}Archivo config:${NC} $(ls -l $V2RAY_CONFIG_PATH 2>/dev/null || echo 'No existe')"
    echo -e "  ${WHITE}Binario v2ray:${NC} $(ls -l /usr/local/bin/v2ray 2>/dev/null || echo 'No existe')"
    echo ""
    
    # 4. Verificar conectividad de puertos
    echo -e "${INFO} ${CYAN}Puertos en uso por V2Ray:${NC}"
    if [ -f "$V2RAY_CONFIG_PATH" ]; then
        jq -r '.inbounds[]?.port' "$V2RAY_CONFIG_PATH" 2>/dev/null | while read port; do
            if [ -n "$port" ]; then
                if netstat -tlnp 2>/dev/null | grep ":$port " > /dev/null; then
                    echo -e "  ${GREEN}✓ Puerto $port: En uso${NC}"
                else
                    echo -e "  ${RED}✗ Puerto $port: No está escuchando${NC}"
                fi
            fi
        done
    fi
    echo ""
    
    # 5. Intentar ejecutar manualmente
    echo -e "${INFO} ${CYAN}Probando ejecución manual:${NC}"
    echo -e "${YELLOW}Ejecutando: sudo -u v2ray /usr/local/bin/v2ray test -config $V2RAY_CONFIG_PATH${NC}"
    if sudo -u v2ray /usr/local/bin/v2ray test -config "$V2RAY_CONFIG_PATH" 2>&1; then
        echo -e "${SUCCESS} ${GREEN}Ejecución manual exitosa${NC}"
    else
        echo -e "${ERROR} ${RED}Error en ejecución manual${NC}"
    fi
    echo ""
    
    # 6. Mostrar últimos logs del sistema
    echo -e "${INFO} ${CYAN}Últimos logs del sistema:${NC}"
    journalctl -u v2ray -n 15 --no-pager
    echo ""
    
    # 7. Sugerencias automáticas
    echo -e "${INFO} ${YELLOW}Sugerencias de solución:${NC}"
    echo -e "  ${WHITE}1.${NC} Verificar que el usuario v2ray tenga permisos de escritura en logs"
    echo -e "  ${WHITE}2.${NC} Verificar que no haya conflictos de puertos"
    echo -e "  ${WHITE}3.${NC} Verificar que la configuración JSON sea válida"
    echo -e "  ${WHITE}4.${NC} Verificar que los certificados TLS tengan permisos correctos"
}

# Función mejorada para obtener IPs
get_local_ip() {
    ip route get 8.8.8.8 | grep -oP 'src \K[^ ]+' | head -n1 2>/dev/null || \
    ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1 2>/dev/null || \
    hostname -I | awk '{print $1}' 2>/dev/null
}

get_public_ip() {
    curl -s --max-time 10 ifconfig.me 2>/dev/null || \
    curl -s --max-time 10 ipinfo.io/ip 2>/dev/null || \
    curl -s --max-time 10 api.ipify.org 2>/dev/null || \
    echo "No disponible"
}

# Función para mostrar información del sistema con estilo mejorado
show_system_info() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                       INFORMACIÓN DEL SISTEMA                    ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    
    # Información de CPU
    local cpu_cores=$(nproc)
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2 | sed 's/^ *//' | cut -c1-40)
    echo -e "${CYAN}║${WHITE} ${GEAR} CPU:              ${YELLOW}$cpu_cores cores${NC}                                ${CYAN}║${NC}"
    [ -n "$cpu_model" ] && echo -e "${CYAN}║${WHITE}     Modelo:        ${YELLOW}$cpu_model...${NC}              ${CYAN}║${NC}"
    
    # Información de memoria
    local ram_total=$(free -h | awk '/^Mem:/ {print $2}')
    local ram_used=$(free -h | awk '/^Mem:/ {print $3}')
    local ram_percent=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
    echo -e "${CYAN}║${WHITE} ${INFO} RAM Total:        ${YELLOW}$ram_total${NC}                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE}     RAM Usada:      ${YELLOW}$ram_used ($ram_percent%)${NC}                           ${CYAN}║${NC}"
    
    # Información de almacenamiento
    local disk_total=$(df -h / | awk 'NR==2 {print $2}')
    local disk_used=$(df -h / | awk 'NR==2 {print $3}')
    local disk_free=$(df -h / | awk 'NR==2 {print $4}')
    local disk_percent=$(df -h / | awk 'NR==2 {print $5}')
    echo -e "${CYAN}║${WHITE} ${SHIELD} Disco Total:      ${YELLOW}$disk_total${NC}                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE}     Usado/Libre:    ${YELLOW}$disk_used / $disk_free ($disk_percent usado)${NC}           ${CYAN}║${NC}"
    
    # Sistema operativo
    local os_info=""
    if command -v lsb_release > /dev/null 2>&1; then
        os_info=$(lsb_release -d 2>/dev/null | cut -f2 | cut -c1-35)
    elif [ -f /etc/os-release ]; then
        os_info=$(grep "PRETTY_NAME" /etc/os-release | cut -d'"' -f2 | cut -c1-35)
    else
        os_info="Linux $(uname -r | cut -c1-20)"
    fi
    echo -e "${CYAN}║${WHITE} ${ROCKET} Sistema:          ${YELLOW}$os_info...${NC}                ${CYAN}║${NC}"
    
    # Kernel
    local kernel_version=$(uname -r | cut -c1-25)
    echo -e "${CYAN}║${WHITE}     Kernel:         ${YELLOW}$kernel_version${NC}                    ${CYAN}║${NC}"
    
    # Uptime
    local uptime_info=$(uptime -p 2>/dev/null | sed 's/up //' | cut -c1-30 || echo "N/A")
    echo -e "${CYAN}║${WHITE} ${INFO} Tiempo activo:    ${YELLOW}$uptime_info${NC}                       ${CYAN}║${NC}"
    
    # Estado de V2Ray con más detalles
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    if systemctl is-active --quiet v2ray 2>/dev/null; then
        echo -e "${CYAN}║${WHITE} ${SUCCESS} V2Ray:            ${GREEN}Activo y ejecutándose${NC}                      ${CYAN}║${NC}"
        
        # Mostrar puertos activos si hay configuración
        if [ -f "$V2RAY_CONFIG_PATH" ]; then
            local ports=$(jq -r '.inbounds[]?.port' "$V2RAY_CONFIG_PATH" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
            if [ -n "$ports" ]; then
                echo -e "${CYAN}║${WHITE}     Puertos:        ${GREEN}$ports${NC}                                  ${CYAN}║${NC}"
            fi
            
            # Contar cuentas
            local account_count=$(jq '[.inbounds[]?.settings.clients[]?] | length' "$V2RAY_CONFIG_PATH" 2>/dev/null || echo 0)
            echo -e "${CYAN}║${WHITE}     Cuentas:        ${GREEN}$account_count configuradas${NC}                        ${CYAN}║${NC}"
        fi
        
        # Tiempo de ejecución del servicio
        local service_uptime=$(systemctl show v2ray --property=ActiveEnterTimestamp 2>/dev/null | cut -d'=' -f2)
        if [ -n "$service_uptime" ] && [ "$service_uptime" != "n/a" ]; then
            local start_time=$(date -d "$service_uptime" +%s 2>/dev/null || echo 0)
            local current_time=$(date +%s)
            local runtime=$((current_time - start_time))
            if [ $runtime -gt 0 ]; then
                local runtime_formatted=""
                if [ $runtime -ge 86400 ]; then
                    runtime_formatted="${runtime_formatted}$((runtime / 86400))d "
                    runtime=$((runtime % 86400))
                fi
                if [ $runtime -ge 3600 ]; then
                    runtime_formatted="${runtime_formatted}$((runtime / 3600))h "
                    runtime=$((runtime % 3600))
                fi
                if [ $runtime -ge 60 ]; then
                    runtime_formatted="${runtime_formatted}$((runtime / 60))m"
                fi
                [ -n "$runtime_formatted" ] && echo -e "${CYAN}║${WHITE}     Ejecutándose:    ${GREEN}$runtime_formatted${NC}                               ${CYAN}║${NC}"
            fi
        fi
    else
        echo -e "${CYAN}║${WHITE} ${ERROR} V2Ray:            ${RED}Inactivo o no instalado${NC}                   ${CYAN}║${NC}"
        if [ -f "/usr/local/bin/v2ray" ]; then
            echo -e "${CYAN}║${WHITE}     Estado:         ${YELLOW}Instalado pero detenido${NC}                    ${CYAN}║${NC}"
        else
            echo -e "${CYAN}║${WHITE}     Estado:         ${RED}No instalado${NC}                              ${CYAN}║${NC}"
        fi
    fi
    
    # Información de red
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    local local_ip=$(get_local_ip)
    local public_ip=$(get_public_ip)
    echo -e "${CYAN}║${WHITE} ${LINK} IP Local:         ${YELLOW}$local_ip${NC}                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE}     IP Pública:     ${YELLOW}${public_ip:-"No disponible"}${NC}                        ${CYAN}║${NC}"
    
    # Conexiones de red activas (solo V2Ray si está activo)
    if systemctl is-active --quiet v2ray 2>/dev/null && [ -f "$V2RAY_CONFIG_PATH" ]; then
        local connections=$(netstat -tn 2>/dev/null | grep ":$(jq -r '.inbounds[0]?.port' "$V2RAY_CONFIG_PATH" 2>/dev/null || echo "NONE")" | wc -l)
        if [ "$connections" -gt 0 ]; then
            echo -e "${CYAN}║${WHITE}     Conexiones:     ${GREEN}$connections activas${NC}                            ${CYAN}║${NC}"
        fi
    fi
    
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
}

# Función para instalar dependencias con indicador de progreso
install_dependencies() {
    echo -e "${INFO} ${YELLOW}Verificando dependencias del sistema...${NC}"
    local packages=(curl wget openssl jq qrencode figlet)
    local missing_packages=()

    # Verificar qué paquetes faltan (excepto lolcat, que se instala aparte)
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            missing_packages+=("$pkg")
        fi
    done

    # Instalar paquetes faltantes desde apt
    if [ ${#missing_packages[@]} -gt 0 ]; then
        echo -e "${INFO} ${YELLOW}Instalando paquetes faltantes: ${missing_packages[*]}${NC}"
        if [ -f /etc/debian_version ]; then
            apt-get update -qq
            apt-get install -y "${missing_packages[@]}" > /dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y "${missing_packages[@]}" > /dev/null 2>&1 || dnf install -y "${missing_packages[@]}" > /dev/null 2>&1
        else
            echo -e "${ERROR} ${RED}Sistema no soportado. Instale manualmente: ${missing_packages[*]}${NC}"
            return 1
        fi
    else
        echo -e "${SUCCESS} ${GREEN}Todas las dependencias están instaladas${NC}"
    fi

    # Instalar lolcat con gem (para Ruby) y asegurarse de que esté en /usr/local/bin
    if ! command -v lolcat &> /dev/null; then
        echo -e "${INFO} ${YELLOW}Instalando lolcat...${NC}"
        if command -v gem &> /dev/null; then
            gem install lolcat --no-user-install > /dev/null 2>&1
            # Asegurarse de que el binario esté en /usr/local/bin
            if [ -f "/usr/local/bin/lolcat" ]; then
                echo -e "${SUCCESS} ${GREEN}lolcat instalado correctamente${NC}"
            else
                # Si no está en /usr/local/bin, buscarlo y copiarlo
                lolcat_path=$(gem contents lolcat | grep bin/lolcat | head -n1)
                if [ -n "$lolcat_path" ]; then
                    sudo cp "$lolcat_path" /usr/local/bin/
                    echo -e "${SUCCESS} ${GREEN}lolcat copiado a /usr/local/bin${NC}"
                else
                    echo -e "${WARNING} ${YELLOW}No se pudo instalar lolcat. Se omitirá el uso de colores en el banner.${NC}"
                fi
            fi
        else
            echo -e "${WARNING} ${YELLOW}Ruby o gem no están instalados. lolcat no se instaló.${NC}"
        fi
    else
        echo -e "${SUCCESS} ${GREEN}lolcat ya está instalado${NC}"
    fi

    log_message "Dependencias instaladas: ${missing_packages[*]}"
}

# Función mejorada para verificar certificados existentes
check_existing_certificates() {
    if [ -f "$CERT_PATH/v2ray.crt" ] && [ -f "$CERT_PATH/v2ray.key" ]; then
        echo -e "${INFO} ${YELLOW}Se encontraron certificados TLS existentes${NC}"
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${WHITE} Certificado: ${GREEN}$CERT_PATH/v2ray.crt${CYAN}                    ║${NC}"
        echo -e "${CYAN}║${WHITE} Clave privada: ${GREEN}$CERT_PATH/v2ray.key${CYAN}                  ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"

        # Mostrar información del certificado
        cert_info=$(openssl x509 -in "$CERT_PATH/v2ray.crt" -noout -dates 2>/dev/null)
        if [ -n "$cert_info" ]; then
            echo -e "${INFO} ${CYAN}Información del certificado:${NC}"
            echo "$cert_info" | sed 's/^/  /'
        fi

        echo ""
        echo -e "${YELLOW}¿Desea utilizar los certificados existentes?${NC}"
        echo -e "  ${WHITE}1.${NC} Usar certificados existentes"
        echo -e "  ${WHITE}2.${NC} Generar nuevos certificados"
        echo ""

        while true; do
            echo -ne "${INFO} ${CYAN}Seleccione una opción (1-2): ${NC}"
            read -r cert_choice
            case $cert_choice in
                1)
                    echo -e "${SUCCESS} ${GREEN}Usando certificados existentes${NC}"
                    # Verificar y corregir permisos
                    chown "$V2RAY_USER:$V2RAY_GROUP" "$CERT_PATH/v2ray.crt" "$CERT_PATH/v2ray.key"
                    chmod 644 "$CERT_PATH/v2ray.crt"
                    chmod 600 "$CERT_PATH/v2ray.key"
                    return 0
                    ;;
                2)
                    echo -e "${WARNING} ${YELLOW}Los certificados existentes serán reemplazados${NC}"
                    return 1
                    ;;
                *)
                    echo -e "${ERROR} ${RED}Opción inválida${NC}"
                    ;;
            esac
        done
    else
        return 1
    fi
}

# Función mejorada para generar certificados TLS
generate_tls_certificates() {
    echo -e "${SHIELD} ${YELLOW}Configurando certificados TLS...${NC}"
    mkdir -p "$CERT_PATH"

    # Verificar certificados existentes
    if check_existing_certificates; then
        return 0
    fi

    echo -e "${INFO} ${YELLOW}Generando nuevos certificados TLS seguros...${NC}"

    # Crear archivo de configuración temporal para openssl
    temp_config=$(mktemp)
    cat > "$temp_config" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req
[dn]
C=US
ST=State
L=City
O=V2Ray
OU=V2Ray Server
CN=v2ray.local
[v3_req]
subjectAltName = @alt_names
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
[alt_names]
DNS.1 = v2ray.local
DNS.2 = localhost
DNS.3 = *.v2ray.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    # Obtener IPs locales para incluir en el certificado
    local local_ip=$(get_local_ip)
    if [ -n "$local_ip" ] && [ "$local_ip" != "127.0.0.1" ]; then
        echo "IP.3 = $local_ip" >> "$temp_config"
    fi

    # Generar clave privada
    if openssl genrsa -out "$CERT_PATH/v2ray.key" 4096 > /dev/null 2>&1; then
        echo -e "${SUCCESS} ${GREEN}Clave privada generada${NC}"
    else
        echo -e "${ERROR} ${RED}Error al generar clave privada${NC}"
        rm -f "$temp_config"
        return 1
    fi

    # Generar certificado
    if openssl req -new -x509 -key "$CERT_PATH/v2ray.key" -out "$CERT_PATH/v2ray.crt" \
        -days 3650 -config "$temp_config" -extensions v3_req > /dev/null 2>&1; then
        echo -e "${SUCCESS} ${GREEN}Certificado TLS generado exitosamente${NC}"
    else
        echo -e "${ERROR} ${RED}Error al generar certificado TLS${NC}"
        rm -f "$temp_config" "$CERT_PATH/v2ray.key" "$CERT_PATH/v2ray.crt"
        return 1
    fi

    # Establecer permisos correctos
    chown "$V2RAY_USER:$V2RAY_GROUP" "$CERT_PATH/v2ray.crt" "$CERT_PATH/v2ray.key"
    chmod 644 "$CERT_PATH/v2ray.crt"
    chmod 600 "$CERT_PATH/v2ray.key"

    # Mostrar información del certificado generado
    echo -e "${INFO} ${CYAN}Información del certificado generado:${NC}"
    openssl x509 -in "$CERT_PATH/v2ray.crt" -noout -subject -dates 2>/dev/null | sed 's/^/  /'

    rm -f "$temp_config"
    log_message "Certificados TLS generados y permisos establecidos"
    return 0
}

# Configuración básica corregida para V2Ray con logging mejorado
create_basic_config() {
    echo -e "${INFO} ${YELLOW}Creando configuración base de V2Ray...${NC}"

    cat > "$V2RAY_CONFIG_PATH" << 'EOL'
{
  "log": {
    "loglevel": "info",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "blocked"
      }
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 2,
        "downlinkOnly": 5,
        "statsUserUplink": false,
        "statsUserDownlink": false,
        "bufferSize": 10240
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false,
      "statsOutboundUplink": false,
      "statsOutboundDownlink": false
    }
  }
}
EOL

    # Establecer permisos correctos para el archivo de configuración
    chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
    chmod 644 "$V2RAY_CONFIG_PATH"

    echo -e "${SUCCESS} ${GREEN}Configuración base creada${NC}"
}

# Función para corregir el servicio systemd de V2Ray
fix_systemd_service() {
    echo -e "${INFO} ${YELLOW}Corrigiendo servicio systemd...${NC}"
    
    # Detener el servicio si está corriendo
    systemctl stop v2ray > /dev/null 2>&1
    
    # Crear servicio systemd corregido (sin Type=notify)
    cat > "$SYSTEMD_SERVICE_PATH" << EOF
[Unit]
Description=V2Ray Service
Documentation=https://www.v2ray.com/ https://guide.v2fly.org/
After=network.target network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=$V2RAY_USER
Group=$V2RAY_GROUP
ExecStart=/usr/local/bin/v2ray run -config $V2RAY_CONFIG_PATH
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=23
LimitNOFILE=1000000

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$V2RAY_LOG_DIR
ReadOnlyPaths=/etc/v2ray
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes

# Timeout settings
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Eliminar archivos de configuración conflictivos
    rm -f /etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf
    rm -rf /etc/systemd/system/v2ray.service.d/
    
    # Recargar systemd
    systemctl daemon-reload
    
    echo -e "${SUCCESS} ${GREEN}Servicio systemd corregido${NC}"
    log_message "Servicio systemd corregido - cambio de notify a simple"
}

# Función para crear servicio systemd personalizado (CORREGIDA)
create_systemd_service() {
    echo -e "${INFO} ${YELLOW}Creando servicio systemd personalizado...${NC}"

    cat > "$SYSTEMD_SERVICE_PATH" << EOF
[Unit]
Description=V2Ray Service
Documentation=https://www.v2ray.com/ https://guide.v2fly.org/
After=network.target network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=$V2RAY_USER
Group=$V2RAY_GROUP
ExecStart=/usr/local/bin/v2ray run -config $V2RAY_CONFIG_PATH
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=23
LimitNOFILE=1000000

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$V2RAY_LOG_DIR
ReadOnlyPaths=/etc/v2ray
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes

# Timeout settings
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Eliminar configuraciones conflictivas del script oficial
    rm -f /etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf
    rm -rf /etc/systemd/system/v2ray.service.d/

    # Recargar systemd
    systemctl daemon-reload
    echo -e "${SUCCESS} ${GREEN}Servicio systemd creado y configurado${NC}"
    log_message "Servicio systemd personalizado creado (Type=simple)"
}

# Función principal de instalación mejorada con corrección automática de permisos
install_v2ray() {
    show_banner
    echo -e "${ROCKET} ${BOLD}INICIANDO INSTALACIÓN DE V2RAY${NC}"
    echo ""

    # Instalar dependencias
    install_dependencies

    # Crear usuario y grupo
    create_v2ray_user

    # Verificar si V2Ray ya está instalado
    if [ -f "/usr/local/bin/v2ray" ]; then
        echo -e "${WARNING} ${YELLOW}V2Ray ya está instalado${NC}"
        echo -e "${INFO} ${CYAN}¿Desea reinstalar? (s/N): ${NC}"
        read -r reinstall
        if [[ ! $reinstall =~ ^[sS]$ ]]; then
            echo -e "${INFO} Instalación cancelada"
            read -p "Presiona Enter para continuar..."
            return 0
        fi
    fi

    # Generar certificados TLS
    generate_tls_certificates

    echo -e "${INFO} ${YELLOW}Descargando e instalando V2Ray...${NC}"

    # Descargar script de instalación oficial
    if curl -L -o /tmp/install-release.sh https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh; then
        chmod +x /tmp/install-release.sh
        echo -e "${SUCCESS} ${GREEN}Script de instalación descargado${NC}"
    else
        echo -e "${ERROR} ${RED}Error al descargar script de instalación${NC}"
        return 1
    fi

    # Instalar V2Ray
    if bash /tmp/install-release.sh > /dev/null 2>&1; then
        echo -e "${SUCCESS} ${GREEN}V2Ray instalado exitosamente${NC}"
    else
        echo -e "${ERROR} ${RED}Error durante la instalación de V2Ray${NC}"
        return 1
    fi

    # Crear configuración básica
    create_basic_config

    # Crear servicio systemd personalizado
    create_systemd_service

    # NUEVO: Corregir permisos automáticamente después de la instalación
    echo -e "${INFO} ${YELLOW}Corrigiendo permisos del sistema automáticamente...${NC}"
    fix_permissions_auto

    # Habilitar y iniciar servicio
    systemctl enable v2ray > /dev/null 2>&1

    if systemctl start v2ray; then
        echo -e "${SUCCESS} ${GREEN}Servicio V2Ray iniciado correctamente${NC}"
    else
        echo -e "${ERROR} ${RED}Error al iniciar V2Ray. Diagnosticando...${NC}"
        diagnose_v2ray
        return 1
    fi

    # Verificar estado final
    sleep 2
    if systemctl is-active --quiet v2ray; then
        echo ""
        echo -e "${SUCCESS} ${GREEN}${BOLD}INSTALACIÓN COMPLETADA EXITOSAMENTE${NC}"
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${WHITE} ✓ V2Ray instalado y ejecutándose                               ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ✓ Usuario y permisos configurados correctamente                ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ✓ Certificados TLS generados                                   ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ✓ Servicio systemd configurado                                 ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ✓ Configuración base lista                                     ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ✓ Permisos del sistema corregidos                              ${CYAN}║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        log_message "V2Ray instalado exitosamente con permisos corregidos automáticamente"
    else
        echo -e "${ERROR} ${RED}V2Ray instalado pero no está ejecutándose correctamente${NC}"
        echo -e "${INFO} ${YELLOW}Ejecutando diagnóstico automático...${NC}"
        diagnose_v2ray
        return 1
    fi

    # Limpiar archivos temporales
    rm -f /tmp/install-release.sh

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para desinstalar V2Ray
uninstall_v2ray() {
    show_banner
    echo -e "${WARNING} ${YELLOW}DESINSTALACIÓN DE V2RAY${NC}"
    echo ""
    echo -e "${RED}Esta acción eliminará completamente V2Ray y todas las configuraciones${NC}"
    echo -e "${YELLOW}Elementos que serán eliminados:${NC}"
    echo -e "  • Binarios de V2Ray"
    echo -e "  • Configuraciones"
    echo -e "  • Certificados TLS"
    echo -e "  • Logs"
    echo -e "  • Usuario y grupo del sistema"
    echo -e "  • Servicio systemd"
    echo ""
    echo -e "${YELLOW}¿Estás seguro de que deseas continuar? (s/N): ${NC}"
    read -r confirm

    if [[ ! $confirm =~ ^[sS]$ ]]; then
        echo -e "${INFO} Operación cancelada"
        read -p "Presiona Enter para continuar..."
        return 0
    fi

    echo -e "${INFO} ${YELLOW}Deteniendo y deshabilitando servicios...${NC}"
    systemctl stop v2ray > /dev/null 2>&1
    systemctl disable v2ray > /dev/null 2>&1

    echo -e "${INFO} ${YELLOW}Eliminando servicio systemd...${NC}"
    rm -f "$SYSTEMD_SERVICE_PATH"
    systemctl daemon-reload

    echo -e "${INFO} ${YELLOW}Eliminando binarios y archivos...${NC}"
    if [ -f /tmp/install-release.sh ]; then
        bash /tmp/install-release.sh --remove > /dev/null 2>&1
    else
        # Descarga y ejecuta script de desinstalación
        curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh | bash -s -- --remove > /dev/null 2>&1
    fi

    echo -e "${INFO} ${YELLOW}Eliminando configuraciones y certificados...${NC}"
    rm -rf "$(dirname "$V2RAY_CONFIG_PATH")"
    rm -rf "$V2RAY_LOG_DIR"
    rm -rf "$CERT_PATH"
    rm -rf /var/lib/v2ray

    echo -e "${INFO} ${YELLOW}Eliminando usuario y grupo del sistema...${NC}"
    if getent passwd "$V2RAY_USER" >/dev/null 2>&1; then
        userdel "$V2RAY_USER" > /dev/null 2>&1
        echo -e "${SUCCESS} ${GREEN}Usuario '$V2RAY_USER' eliminado${NC}"
    fi

    if getent group "$V2RAY_GROUP" >/dev/null 2>&1; then
        groupdel "$V2RAY_GROUP" > /dev/null 2>&1
        echo -e "${SUCCESS} ${GREEN}Grupo '$V2RAY_GROUP' eliminado${NC}"
    fi

    echo ""
    echo -e "${SUCCESS} ${GREEN}${BOLD}V2RAY DESINSTALADO COMPLETAMENTE${NC}"
    log_message "V2Ray desinstalado completamente"

    read -p "Presiona Enter para continuar..."
}

# Función para generar URLs de configuración con allowInsecure
generate_config_url() {
   local protocol="$1"
   local uuid="$2"
   local ip="$3"
   local port="$4"
   local account_name="$5"
   local use_tls="$6"
   local ws_path="$7"
   local network="${8:-tcp}"
   local allow_insecure="$9"
   local reverse_host="${10}"
   local reverse_sni="${11}"

   local url=""
   local encoded_name=$(echo -n "$account_name" | sed 's/ /%20/g' | sed 's/[^a-zA-Z0-9%_-]//g')

   case $protocol in
       "vmess")
           local vmess_config="{
               \"v\": \"2\",
               \"ps\": \"$account_name\",
               \"add\": \"$ip\",
               \"port\": \"$port\",
               \"id\": \"$uuid\",
               \"aid\": \"0\",
               \"scy\": \"auto\",
               \"net\": \"$network\",
               \"type\": \"none\",
               \"host\": \"$reverse_host\",
               \"path\": \"${ws_path:-""}\",
               \"tls\": \"$([ "$use_tls" == "true" ] && echo 'tls' || echo '')\",
               \"sni\": \"$reverse_sni\",
               \"alpn\": \"\"
           }"
           encoded_config=$(echo -n "$vmess_config" | base64 -w 0 2>/dev/null || echo -n "$vmess_config" | base64 | tr -d '\n')
           url="vmess://$encoded_config"
           ;;
       "vless")
           url="vless://$uuid@$ip:$port"
           local params=()
           
           if [ "$network" != "tcp" ]; then
               params+=("type=$network")
               if [ -n "$ws_path" ]; then
                   case "$network" in
                       "ws")
                           params+=("path=$(echo -n "$ws_path" | sed 's|^/*|/|')")
                           ;;
                       "httpupgrade")
                           params+=("path=$(echo -n "$ws_path" | sed 's|^/*|/|')")
                           ;;
                       "xhttp")
                           params+=("path=$(echo -n "$ws_path" | sed 's|^/*|/|')")
                           ;;
                       "grpc")
                           params+=("serviceName=$(echo -n "$ws_path" | sed 's|^/*||')")
                           ;;
                   esac
               fi
           fi
           
           if [ "$use_tls" == "true" ]; then
               params+=("security=tls")
               if [ "$allow_insecure" == "true" ]; then
                   params+=("allowInsecure=true")
               fi
               [ -n "$reverse_sni" ] && params+=("sni=$reverse_sni")
               [ -n "$reverse_host" ] && params+=("host=$reverse_host")
           fi
           
           if [ ${#params[@]} -gt 0 ]; then
               local param_string=$(IFS='&'; echo "${params[*]}")
               url="${url}?${param_string}"
           fi
           
           url="${url}#${encoded_name}"
           ;;
       "trojan")
           url="trojan://$uuid@$ip:$port"
           local params=()
           
           if [ "$network" != "tcp" ]; then
               params+=("type=$network")
               if [ -n "$ws_path" ]; then
                   case "$network" in
                       "ws")
                           params+=("path=$(echo -n "$ws_path" | sed 's|^/*|/|')")
                           ;;
                       "httpupgrade")
                           params+=("path=$(echo -n "$ws_path" | sed 's|^/*|/|')")
                           ;;
                       "xhttp")
                           params+=("path=$(echo -n "$ws_path" | sed 's|^/*|/|')")
                           ;;
                       "grpc")
                           params+=("serviceName=$(echo -n "$ws_path" | sed 's|^/*||')")
                           ;;
                   esac
               fi
           fi
           
           if [ "$use_tls" == "true" ]; then
               params+=("security=tls")
               if [ "$allow_insecure" == "true" ]; then
                   params+=("allowInsecure=true")
               fi
               [ -n "$reverse_sni" ] && params+=("sni=$reverse_sni")
               [ -n "$reverse_host" ] && params+=("host=$reverse_host")
           fi
           
           if [ ${#params[@]} -gt 0 ]; then
               local param_string=$(IFS='&'; echo "${params[*]}")
               url="${url}?${param_string}"
           fi
           
           url="${url}#${encoded_name}"
           ;;
       "shadowsocks")
           local ss_method=$(jq -r --arg name "$account_name" '.inbounds[] | select(.settings.email == $name) | .settings.method' "$V2RAY_CONFIG_PATH" 2>/dev/null || echo "chacha20-ietf-poly1305")
           local ss_password=$(jq -r --arg name "$account_name" '.inbounds[] | select(.settings.email == $name) | .settings.password' "$V2RAY_CONFIG_PATH" 2>/dev/null || echo "$uuid")
           
           local userinfo=$(echo -n "${ss_method}:${ss_password}" | base64 -w 0 2>/dev/null || echo -n "${ss_method}:${ss_password}" | base64 | tr -d '\n')
           url="ss://${userinfo}@${ip}:${port}#${encoded_name}"
           ;;
   esac

   echo "$url"
}

# Función para mostrar estadísticas detalladas de cuentas
show_detailed_account_stats() {
   show_banner
   echo -e "${INFO} ${BOLD}ESTADÍSTICAS DETALLADAS DE CUENTAS${NC}"
   echo ""

   local all_accounts
   all_accounts=$(extract_all_accounts)
   
   if [ -z "$all_accounts" ]; then
       echo -e "${WARNING} ${YELLOW}No hay cuentas configuradas${NC}"
       read -p "Presiona Enter para continuar..."
       return
   fi

   echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
   echo -e "${CYAN}║${WHITE}                     ESTADÍSTICAS DE CUENTAS                      ${CYAN}║${NC}"
   echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"

   local total_accounts=0
   local vmess_count=0
   local vless_count=0
   local trojan_count=0
   local shadowsocks_count=0
   local tls_count=0
   local tcp_count=0
   local ws_count=0
   local grpc_count=0

   while IFS= read -r line; do
       if [ -n "$line" ]; then
           total_accounts=$((total_accounts + 1))
           IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$line"
           
           case "$protocol" in
               "vmess") vmess_count=$((vmess_count + 1)) ;;
               "vless") vless_count=$((vless_count + 1)) ;;
               "trojan") trojan_count=$((trojan_count + 1)) ;;
               "shadowsocks") shadowsocks_count=$((shadowsocks_count + 1)) ;;
           esac
           
           [ "$security" == "tls" ] && tls_count=$((tls_count + 1))
           
           case "$network" in
               "tcp") tcp_count=$((tcp_count + 1)) ;;
               "ws") ws_count=$((ws_count + 1)) ;;
               "grpc") grpc_count=$((grpc_count + 1)) ;;
           esac
       fi
   done <<< "$all_accounts"

   echo -e "${CYAN}║${WHITE} 📊 Total de cuentas:      ${YELLOW}$total_accounts${CYAN}                             ║${NC}"
   echo -e "${CYAN}║${WHITE}                                                                 ${CYAN}║${NC}"
   echo -e "${CYAN}║${WHITE} 📡 Por protocolo:                                              ${CYAN}║${NC}"
   echo -e "${CYAN}║${WHITE}     VMess:               ${YELLOW}$vmess_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE}     VLESS:               ${YELLOW}$vless_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE}     Trojan:              ${YELLOW}$trojan_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE}     Shadowsocks:         ${YELLOW}$shadowsocks_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE}                                                                 ${CYAN}║${NC}"
   echo -e "${CYAN}║${WHITE} 🌐 Por transporte:                                             ${CYAN}║${NC}"
   echo -e "${CYAN}║${WHITE}     TCP:                 ${YELLOW}$tcp_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE}     WebSocket:           ${YELLOW}$ws_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE}     gRPC:                ${YELLOW}$grpc_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE}                                                                 ${CYAN}║${NC}"
   echo -e "${CYAN}║${WHITE} 🔒 Con TLS:               ${YELLOW}$tls_count${CYAN}                               ║${NC}"
   echo -e "${CYAN}║${WHITE} 🔓 Sin TLS:               ${YELLOW}$((total_accounts - tls_count))${CYAN}                               ║${NC}"
   echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"

   echo ""
   echo -e "${INFO} ${YELLOW}Puertos utilizados:${NC}"
   while IFS= read -r line; do
       if [ -n "$line" ]; then
           IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$line"
           local status="${RED}Inactivo${NC}"
           if netstat -tlnp 2>/dev/null | grep ":$port " > /dev/null; then
               status="${GREEN}Activo${NC}"
           fi
           echo -e "  ${WHITE}Puerto $port:${NC} $status ${CYAN}($protocol - $email)${NC}"
       fi
   done <<< "$all_accounts"

   echo ""
   read -p "Presiona Enter para continuar..."
}

# Función mejorada para crear cuentas con todos los protocolos de transporte y allowInsecure
create_account() {
    show_banner
    echo -e "${ROCKET} ${BOLD}CREAR NUEVA CUENTA V2RAY${NC}"
    echo ""

    # Verificar que V2Ray esté instalado y ejecutándose
    if ! systemctl is-active --quiet v2ray; then
        echo -e "${ERROR} ${RED}V2Ray no está ejecutándose${NC}"
        echo -e "${INFO} ${YELLOW}Por favor, instale e inicie V2Ray primero${NC}"
        read -p "Presiona Enter para continuar..."
        return 1
    fi

    # Verificar y reparar configuración
    if [ ! -f "$V2RAY_CONFIG_PATH" ]; then
        echo -e "${ERROR} ${RED}Configuración de V2Ray no encontrada${NC}"
        read -p "Presiona Enter para continuar..."
        return 1
    fi

    # Generar UUID
    local uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(..\)/\1-/g; s/-$//' | sed 's/^\(.\{8\}\)-\(.\{4\}\)-\(.\{4\}\)-\(.\{4\}\)-/\1-\2-\3-\4-/')

    # Solicitar nombre de cuenta
    while true; do
        echo -ne "${INFO} ${CYAN}Nombre de la cuenta: ${NC}"
        read -r account_name

        if [ -z "$account_name" ]; then
            echo -e "${ERROR} ${RED}El nombre no puede estar vacío${NC}"
            continue
        fi

        # Verificar que el nombre no contenga caracteres especiales
        if [[ ! "$account_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo -e "${ERROR} ${RED}Use solo letras, números, guiones y guiones bajos${NC}"
            continue
        fi

        if jq -e --arg name "$account_name" '.inbounds[] | select(.settings.clients[]?.email == $name)' "$V2RAY_CONFIG_PATH" > /dev/null 2>&1; then
            echo -e "${ERROR} ${RED}Ya existe una cuenta con ese nombre${NC}"
            continue
        fi
        break
    done

    # Duración de la cuenta
    while true; do
        echo -ne "${INFO} ${CYAN}Duración en días (1-365, Enter para 30): ${NC}"
        read -r duration
        duration=${duration:-30}
        if [[ "$duration" =~ ^[0-9]+$ ]] && [ "$duration" -ge 1 ] && [ "$duration" -le 365 ]; then
            break
        else
            echo -e "${ERROR} ${RED}Ingrese un número válido entre 1 y 365${NC}"
        fi
    done

    local expiry_date=$(date -d "+$duration days" +"%Y-%m-%d" 2>/dev/null || date -v+${duration}d +"%Y-%m-%d" 2>/dev/null)

    # Menú de protocolos expandido con todos los transportes
    echo ""
    echo -e "${GEAR} ${BOLD}SELECCIONAR PROTOCOLO Y CONFIGURACIÓN${NC}"
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                    PROTOCOLOS Y TRANSPORTES DISPONIBLES           ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${WHITE}                        VMESS PROTOCOLOS                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 1.${NC}  VMess + TCP                  ${CYAN}║${WHITE} 2.${NC}  VMess + TCP + TLS         ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 3.${NC}  VMess + KCP                  ${CYAN}║${WHITE} 4.${NC}  VMess + KCP + TLS         ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 5.${NC}  VMess + WebSocket            ${CYAN}║${WHITE} 6.${NC}  VMess + WebSocket + TLS   ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 7.${NC}  VMess + gRPC + TLS           ${CYAN}║${WHITE} 8.${NC}  VMess + HTTPUpgrade       ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 9.${NC}  VMess + HTTPUpgrade + TLS    ${CYAN}║${WHITE} 10.${NC} VMess + XHTTP             ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 11.${NC} VMess + XHTTP + TLS          ${CYAN}║${WHITE} 12.${NC} VMess + HTTP/2 + TLS      ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${WHITE}                        VLESS PROTOCOLOS                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 13.${NC} VLESS + TCP                  ${CYAN}║${WHITE} 14.${NC} VLESS + TCP + TLS         ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 15.${NC} VLESS + KCP                  ${CYAN}║${WHITE} 16.${NC} VLESS + KCP + TLS         ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 17.${NC} VLESS + WebSocket            ${CYAN}║${WHITE} 18.${NC} VLESS + WebSocket + TLS   ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 19.${NC} VLESS + gRPC + TLS           ${CYAN}║${WHITE} 20.${NC} VLESS + HTTPUpgrade       ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 21.${NC} VLESS + HTTPUpgrade + TLS    ${CYAN}║${WHITE} 22.${NC} VLESS + XHTTP             ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 23.${NC} VLESS + XHTTP + TLS          ${CYAN}║${WHITE} 24.${NC} VLESS + HTTP/2 + TLS      ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${WHITE}                       TROJAN PROTOCOLOS                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 25.${NC} Trojan + TCP + TLS           ${CYAN}║${WHITE} 26.${NC} Trojan + WebSocket + TLS  ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 27.${NC} Trojan + gRPC + TLS          ${CYAN}║${WHITE} 28.${NC} Trojan + HTTPUpgrade+TLS  ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 29.${NC} Trojan + XHTTP + TLS         ${CYAN}║${WHITE} 30.${NC} Trojan + HTTP/2 + TLS     ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${WHITE}                      SHADOWSOCKS PROTOCOLOS                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 31.${NC} Shadowsocks + TCP            ${CYAN}║${WHITE} 32.${NC} Shadowsocks + KCP         ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE} 33.${NC} Shadowsocks + WebSocket      ${CYAN}║${WHITE} 34.${NC} Shadowsocks + HTTPUpgrade ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"

    while true; do
        echo -ne "${INFO} ${CYAN}Elija una opción (1-34): ${NC}"
        read -r protocol_choice
        if [[ "$protocol_choice" =~ ^([1-9]|[1-2][0-9]|3[0-4])$ ]]; then
            break
        else
            echo -e "${ERROR} ${RED}Opción inválida. Elija un número del 1 al 34${NC}"
        fi
    done

    # Puerto - buscar puerto disponible o usar uno específico
    local current_port=8080
    if [ -f "$V2RAY_CONFIG_PATH" ] && jq -e '.inbounds[0].port' "$V2RAY_CONFIG_PATH" > /dev/null 2>&1; then
        current_port=$(jq -r '.inbounds[-1].port' "$V2RAY_CONFIG_PATH" 2>/dev/null || echo 8080)
        current_port=$((current_port + 1))
    fi

    echo -ne "${INFO} ${CYAN}Puerto (Enter para usar $current_port): ${NC}"
    read -r port
    port=${port:-$current_port}

    # Validar puerto
    while [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; do
        echo -e "${ERROR} ${RED}Puerto inválido. Use un número entre 1024 y 65535${NC}"
        echo -ne "${INFO} ${CYAN}Puerto: ${NC}"
        read -r port
    done

    # Verificar si el puerto ya está en uso
    if jq -e --arg port "$port" '.inbounds[] | select(.port == ($port|tonumber))' "$V2RAY_CONFIG_PATH" > /dev/null 2>&1; then
        echo -e "${WARNING} ${YELLOW}El puerto $port ya está en uso por otra configuración${NC}"
        echo -e "${INFO} ${CYAN}¿Desea continuar de todos modos? (s/N): ${NC}"
        read -r continue_port
        if [[ ! $continue_port =~ ^[sS]$ ]]; then
            echo -e "${INFO} Operación cancelada"
            read -p "Presiona Enter para continuar..."
            return 1
        fi
    fi

    # Selección de IP
    echo ""
    echo -e "${LINK} ${YELLOW}Seleccionar dirección IP:${NC}"
    local local_ip=$(get_local_ip)
    local public_ip=$(get_public_ip)

    echo -e "  ${WHITE}1.${NC} IP local: ${GREEN}$local_ip${NC}"
    echo -e "  ${WHITE}2.${NC} IP pública: ${GREEN}$public_ip${NC}"
    echo -e "  ${WHITE}3.${NC} IP personalizada"

    local ip_address=""
    while true; do
        echo -ne "${INFO} ${CYAN}Opción (1-3): ${NC}"
        read -r ip_choice
        case $ip_choice in
            1)
                ip_address="$local_ip"
                break
                ;;
            2)
                ip_address="$public_ip"
                break
                ;;
            3)
                echo -ne "${INFO} ${CYAN}Ingrese la IP personalizada: ${NC}"
                read -r ip_address
                if [[ $ip_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo -e "${ERROR} ${RED}Formato de IP inválido${NC}"
                    ip_address=""
                fi
                ;;
            *)
                echo -e "${ERROR} ${RED}Opción inválida${NC}"
                ;;
        esac
    done

    # Solicitar reverse host para protocolos compatibles
    local reverse_host=""
    local reverse_sni=""
    if [[ "$protocol_choice" =~ ^(2|4|6|7|9|11|12|14|16|18|19|21|23|24|25|26|27|28|29|30)$ ]]; then
        echo -e "${INFO} ${YELLOW}Configuración de reverse host:${NC}"
        echo -ne "${CYAN}Ingrese el SNI (Server Name Indication, ej: netflix.com): ${NC}"
        read -r reverse_sni
        
        echo -ne "${CYAN}Ingrese el Host Header (ej: $reverse_sni, Enter para usar el mismo): ${NC}"
        read -r reverse_host
        reverse_host=${reverse_host:-$reverse_sni}
    fi

    # Configurar según protocolo elegido
    local protocol settings stream_settings use_tls="false" ws_path="" network="tcp" allow_insecure="false"

    case $protocol_choice in
        # VMess Protocolos (1-12)
        1)  # VMess + TCP
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            stream_settings="{\"network\": \"tcp\"}"
            network="tcp"
            ;;
        2)  # VMess + TCP + TLS
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            use_tls="true"
            network="tcp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}}"
            ;;
        3)  # VMess + KCP
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            network="kcp"
            stream_settings="{\"network\": \"kcp\", \"kcpSettings\": {\"mtu\": 1350, \"tti\": 50, \"uplinkCapacity\": 100, \"downlinkCapacity\": 100, \"congestion\": false, \"readBufferSize\": 2, \"writeBufferSize\": 2, \"header\": {\"type\": \"none\"}}}"
            ;;
        4)  # VMess + KCP + TLS
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            use_tls="true"
            network="kcp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"kcp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"kcpSettings\": {\"mtu\": 1350, \"tti\": 50, \"uplinkCapacity\": 100, \"downlinkCapacity\": 100, \"congestion\": false, \"readBufferSize\": 2, \"writeBufferSize\": 2, \"header\": {\"type\": \"none\"}}}"
            ;;
        5)  # VMess + WebSocket
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            ws_path="/ws-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            stream_settings="{\"network\": \"ws\", \"wsSettings\": {\"path\": \"$ws_path\", \"headers\": {\"Host\": \"\"}}}"
            network="ws"
            ;;
        6)  # VMess + WebSocket + TLS
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            ws_path="/ws-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="ws"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"ws\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"wsSettings\": {\"path\": \"$ws_path\", \"headers\": {\"Host\": \"$reverse_host\"}}}"
            ;;
        7)  # VMess + gRPC + TLS
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            use_tls="true"
            network="grpc"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"grpc\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"grpcSettings\": {\"serviceName\": \"grpc-$account_name\", \"multiMode\": false}}"
            ;;
        8)  # VMess + HTTPUpgrade
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            ws_path="/httpupgrade-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            network="httpupgrade"
            stream_settings="{\"network\": \"httpupgrade\", \"httpupgradeSettings\": {\"path\": \"$ws_path\", \"host\": \"\"}}"
            ;;
        9)  # VMess + HTTPUpgrade + TLS
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            ws_path="/httpupgrade-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="httpupgrade"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"httpupgrade\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"httpupgradeSettings\": {\"path\": \"$ws_path\", \"host\": \"$reverse_host\"}}"
            ;;
        10) # VMess + XHTTP
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            ws_path="/xhttp-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            network="xhttp"
            stream_settings="{\"network\": \"xhttp\", \"xhttpSettings\": {\"path\": \"$ws_path\", \"host\": \"\"}}"
            ;;
        11) # VMess + XHTTP + TLS
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            ws_path="/xhttp-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="xhttp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"xhttp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"xhttpSettings\": {\"path\": \"$ws_path\", \"host\": \"$reverse_host\"}}"
            ;;
        12) # VMess + HTTP/2 + TLS
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            use_tls="true"
            network="h2"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"h2\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"httpSettings\": {\"host\": [\"$reverse_host\"], \"path\": \"/h2-$account_name\"}}"
            ;;
        
        # VLESS Protocolos (13-24)
        13) # VLESS + TCP
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            stream_settings="{\"network\": \"tcp\"}"
            network="tcp"
            ;;
        14) # VLESS + TCP + TLS
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            use_tls="true"
            network="tcp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}}"
            ;;
        15) # VLESS + KCP
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            network="kcp"
            stream_settings="{\"network\": \"kcp\", \"kcpSettings\": {\"mtu\": 1350, \"tti\": 50, \"uplinkCapacity\": 100, \"downlinkCapacity\": 100, \"congestion\": false, \"readBufferSize\": 2, \"writeBufferSize\": 2, \"header\": {\"type\": \"none\"}}}"
            ;;
        16) # VLESS + KCP + TLS
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            use_tls="true"
            network="kcp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"kcp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"kcpSettings\": {\"mtu\": 1350, \"tti\": 50, \"uplinkCapacity\": 100, \"downlinkCapacity\": 100, \"congestion\": false, \"readBufferSize\": 2, \"writeBufferSize\": 2, \"header\": {\"type\": \"none\"}}}"
            ;;
        17) # VLESS + WebSocket
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            ws_path="/vless-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            network="ws"
            stream_settings="{\"network\": \"ws\", \"wsSettings\": {\"path\": \"$ws_path\", \"headers\": {\"Host\": \"\"}}}"
            ;;
        18) # VLESS + WebSocket + TLS
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            ws_path="/vless-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="ws"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"ws\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"wsSettings\": {\"path\": \"$ws_path\", \"headers\": {\"Host\": \"$reverse_host\"}}}"
            ;;
        19) # VLESS + gRPC + TLS
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            use_tls="true"
            network="grpc"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"grpc\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"grpcSettings\": {\"serviceName\": \"grpc-$account_name\", \"multiMode\": false}}"
            ;;
        20) # VLESS + HTTPUpgrade
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            ws_path="/vless-httpupgrade-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            network="httpupgrade"
            stream_settings="{\"network\": \"httpupgrade\", \"httpupgradeSettings\": {\"path\": \"$ws_path\", \"host\": \"\"}}"
            ;;
        21) # VLESS + HTTPUpgrade + TLS
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            ws_path="/vless-httpupgrade-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="httpupgrade"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"httpupgrade\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"httpupgradeSettings\": {\"path\": \"$ws_path\", \"host\": \"$reverse_host\"}}"
            ;;
        22) # VLESS + XHTTP
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            ws_path="/vless-xhttp-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            network="xhttp"
            stream_settings="{\"network\": \"xhttp\", \"xhttpSettings\": {\"path\": \"$ws_path\", \"host\": \"\"}}"
            ;;
        23) # VLESS + XHTTP + TLS
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            ws_path="/vless-xhttp-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="xhttp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"xhttp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"xhttpSettings\": {\"path\": \"$ws_path\", \"host\": \"$reverse_host\"}}"
            ;;
        24) # VLESS + HTTP/2 + TLS
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            use_tls="true"
            network="h2"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"h2\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"httpSettings\": {\"host\": [\"$reverse_host\"], \"path\": \"/vless-h2-$account_name\"}}"
            ;;

        # Trojan Protocolos (25-30)
        25) # Trojan + TCP + TLS
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            use_tls="true"
            network="tcp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}}"
            ;;
        26) # Trojan + WebSocket + TLS
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            ws_path="/trojan-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="ws"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"ws\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"wsSettings\": {\"path\": \"$ws_path\", \"headers\": {\"Host\": \"$reverse_host\"}}}"
            ;;
        27) # Trojan + gRPC + TLS
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            use_tls="true"
            network="grpc"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"grpc\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"grpcSettings\": {\"serviceName\": \"trojan-grpc-$account_name\", \"multiMode\": false}}"
            ;;
        28) # Trojan + HTTPUpgrade+TLS
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            ws_path="/trojan-httpupgrade-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="httpupgrade"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"httpupgrade\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"httpupgradeSettings\": {\"path\": \"$ws_path\", \"host\": \"$reverse_host\"}}"
            ;;
        29) # Trojan + XHTTP + TLS
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            ws_path="/trojan-xhttp-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            use_tls="true"
            network="xhttp"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"xhttp\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"xhttpSettings\": {\"path\": \"$ws_path\", \"host\": \"$reverse_host\"}}"
            ;;
        30) # Trojan + HTTP/2 + TLS
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            use_tls="true"
            network="h2"
            
            echo -ne "${INFO} ${CYAN}¿Permitir conexiones inseguras? (s/N): ${NC}"
            read -r insecure_choice
            if [[ $insecure_choice =~ ^[sS]$ ]]; then
                allow_insecure="true"
            fi
            
            stream_settings="{\"network\": \"h2\", \"security\": \"tls\", \"tlsSettings\": {\"allowInsecure\": $allow_insecure, \"serverName\": \"$reverse_sni\", \"certificates\": [{\"certificateFile\": \"$CERT_PATH/v2ray.crt\", \"keyFile\": \"$CERT_PATH/v2ray.key\"}]}, \"httpSettings\": {\"host\": [\"$reverse_host\"], \"path\": \"/trojan-h2-$account_name\"}}"
            ;;

        # Shadowsocks Protocolos (31-34)
        31) # Shadowsocks + TCP
            protocol="shadowsocks"
            local ss_method="chacha20-ietf-poly1305"
            local ss_password=$(openssl rand -base64 16)
            settings="{\"method\": \"$ss_method\", \"password\": \"$ss_password\", \"email\": \"$account_name\"}"
            stream_settings="{\"network\": \"tcp\"}"
            network="tcp"
            ;;
        32) # Shadowsocks + KCP
            protocol="shadowsocks"
            local ss_method="chacha20-ietf-poly1305"
            local ss_password=$(openssl rand -base64 16)
            settings="{\"method\": \"$ss_method\", \"password\": \"$ss_password\", \"email\": \"$account_name\"}"
            network="kcp"
            stream_settings="{\"network\": \"kcp\", \"kcpSettings\": {\"mtu\": 1350, \"tti\": 50, \"uplinkCapacity\": 100, \"downlinkCapacity\": 100, \"congestion\": false, \"readBufferSize\": 2, \"writeBufferSize\": 2, \"header\": {\"type\": \"none\"}}}"
            ;;
        33) # Shadowsocks + WebSocket
            protocol="shadowsocks"
            local ss_method="chacha20-ietf-poly1305"
            local ss_password=$(openssl rand -base64 16)
            settings="{\"method\": \"$ss_method\", \"password\": \"$ss_password\", \"email\": \"$account_name\"}"
            ws_path="/ss-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            network="ws"
            stream_settings="{\"network\": \"ws\", \"wsSettings\": {\"path\": \"$ws_path\", \"headers\": {\"Host\": \"\"}}}"
            ;;
        34) # Shadowsocks + HTTPUpgrade
            protocol="shadowsocks"
            local ss_method="chacha20-ietf-poly1305"
            local ss_password=$(openssl rand -base64 16)
            settings="{\"method\": \"$ss_method\", \"password\": \"$ss_password\", \"email\": \"$account_name\"}"
            ws_path="/ss-httpupgrade-$(echo -n "$account_name" | tr '[:upper:]' '[:lower:]')"
            network="httpupgrade"
            stream_settings="{\"network\": \"httpupgrade\", \"httpupgradeSettings\": {\"path\": \"$ws_path\", \"host\": \"\"}}"
            ;;
        *)
            # Configuración básica para opciones no especificadas
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\", \"alterId\": 0}]}"
            stream_settings="{\"network\": \"tcp\"}"
            network="tcp"
            ;;
    esac

    # Crear configuración de inbound
    local new_inbound=$(jq -n \
    --arg protocol "$protocol" \
    --arg port "$port" \
    --argjson settings "$settings" \
    --argjson stream_settings "$stream_settings" \
    '{protocol: $protocol, port: ($port|tonumber), settings: $settings, streamSettings: $stream_settings}')

    echo -e "${INFO} ${YELLOW}Agregando configuración a V2Ray...${NC}"

    # Crear backup de la configuración actual
    cp "$V2RAY_CONFIG_PATH" "${V2RAY_CONFIG_PATH}.backup.$(date +%s)"

    # Agregar a configuración
    if jq --argjson new_inbound "$new_inbound" '.inbounds += [$new_inbound]' "$V2RAY_CONFIG_PATH" > /tmp/v2ray_config_temp.json; then
        mv /tmp/v2ray_config_temp.json "$V2RAY_CONFIG_PATH"
        chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
        chmod 644 "$V2RAY_CONFIG_PATH"
        echo -e "${SUCCESS} ${GREEN}Configuración actualizada${NC}"
    else
        echo -e "${ERROR} ${RED}Error al actualizar configuración${NC}"
        return 1
    fi

    # Establecer permisos correctos para el archivo de configuración
    chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
    chmod 644 "$V2RAY_CONFIG_PATH"

    echo -e "${INFO} ${YELLOW}Verificando permisos automáticamente...${NC}"
    fix_permissions_auto

    # Validar configuración
    echo -e "${INFO} ${YELLOW}Validando configuración...${NC}"
    if /usr/local/bin/v2ray test -c "$V2RAY_CONFIG_PATH" > /dev/null 2>&1; then
        echo -e "${SUCCESS} ${GREEN}Configuración válida${NC}"
    else
        echo -e "${ERROR} ${RED}Configuración inválida. Restaurando backup...${NC}"
        mv "${V2RAY_CONFIG_PATH}.backup.$(ls -t ${V2RAY_CONFIG_PATH}.backup.* | head -n1 | cut -d'.' -f4)" "$V2RAY_CONFIG_PATH"
        return 1
    fi

    # Reiniciar V2Ray
    echo -e "${INFO} ${YELLOW}Reiniciando V2Ray...${NC}"
    if systemctl restart v2ray; then
        sleep 2
        if systemctl is-active --quiet v2ray; then
            echo -e "${SUCCESS} ${GREEN}V2Ray reiniciado correctamente${NC}"
        else
            echo -e "${ERROR} ${RED}V2Ray no se inició correctamente${NC}"
            journalctl -u v2ray -n 5 --no-pager
            return 1
        fi
    else
        echo -e "${ERROR} ${RED}Error al reiniciar V2Ray${NC}"
        return 1
    fi

    # Mostrar información de la cuenta
    echo ""
    echo -e "${SUCCESS} ${GREEN}${BOLD}CUENTA CREADA EXITOSAMENTE${NC}"
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE} Nombre:           ${YELLOW}$account_name${CYAN}                           ║${NC}"
    echo -e "${CYAN}║${WHITE} UUID/Password:    ${YELLOW}$uuid${CYAN} ║${NC}"
    echo -e "${CYAN}║${WHITE} Protocolo:        ${YELLOW}$protocol${CYAN}                              ║${NC}"
    echo -e "${CYAN}║${WHITE} Red:              ${YELLOW}$network${CYAN}                               ║${NC}"
    echo -e "${CYAN}║${WHITE} IP:               ${YELLOW}$ip_address${CYAN}                         ║${NC}"
    echo -e "${CYAN}║${WHITE} Puerto:           ${YELLOW}$port${CYAN}                                  ║${NC}"
    echo -e "${CYAN}║${WHITE} Expiración:       ${YELLOW}$expiry_date${CYAN}                       ║${NC}"
    [ -n "$ws_path" ] && echo -e "${CYAN}║${WHITE} Path:             ${YELLOW}$ws_path${CYAN}                    ║${NC}"
    [ "$use_tls" == "true" ] && echo -e "${CYAN}║${WHITE} TLS:              ${GREEN}Activado${CYAN}                          ║${NC}"
    [ "$use_tls" == "true" ] && echo -e "${CYAN}║${WHITE} AllowInsecure:    ${YELLOW}$allow_insecure${CYAN}                             ║${NC}"
    [ -n "$reverse_sni" ] && echo -e "${CYAN}║${WHITE} SNI:              ${YELLOW}$reverse_sni${CYAN}                             ║${NC}"
    [ -n "$reverse_host" ] && echo -e "${CYAN}║${WHITE} Host Header:      ${YELLOW}$reverse_host${CYAN}                             ║${NC}"

    # Mostrar información adicional para Shadowsocks
    if [ "$protocol" == "shadowsocks" ]; then
        echo -e "${CYAN}║${WHITE} Método:           ${YELLOW}$ss_method${CYAN}              ║${NC}"
        echo -e "${CYAN}║${WHITE} Password SS:      ${YELLOW}$ss_password${CYAN}                 ║${NC}"
    fi

    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"

    # Generar URL de configuración
    local config_url=$(generate_config_url "$protocol" "$uuid" "$ip_address" "$port" "$account_name" "$use_tls" "$ws_path" "$network" "$allow_insecure" "$reverse_host" "$reverse_sni")

    if [ -n "$config_url" ] && [ "$config_url" != "vmess://" ] && [ "$config_url" != "vless://" ] && [ "$config_url" != "trojan://" ]; then
        echo ""
        echo -e "${LINK} ${BOLD}URL DE CONFIGURACIÓN:${NC}"
        echo -e "${GREEN}$config_url${NC}"
        echo ""

        # Generar código QR
        if command -v qrencode > /dev/null 2>&1; then
            echo -e "${INFO} ${YELLOW}Generando código QR...${NC}"
            echo ""
            if qrencode -t ANSIUTF8 -s 1 -m 1 "$config_url" 2>/dev/null; then
                echo ""
                # Guardar QR como imagen
                local qr_file="/tmp/qr_${account_name}_$(date +%s).png"
                if qrencode -o "$qr_file" "$config_url" 2>/dev/null; then
                    echo -e "${SUCCESS} ${GREEN}Código QR guardado: ${WHITE}$qr_file${NC}"
                fi
            else
                echo -e "${WARNING} ${YELLOW}No se pudo generar el código QR${NC}"
            fi
        fi

        # Guardar configuración en archivo
        local config_file="/tmp/config_${account_name}_$(date +%s).txt"
        cat > "$config_file" << EOF
# Configuración V2Ray - $account_name
# Creada: $(date)
# Expira: $expiry_date
Protocolo: $protocol
Transporte: $network
IP: $ip_address
Puerto: $port
UUID: $uuid
TLS: $([ "$use_tls" == "true" ] && echo "Sí" || echo "No")
AllowInsecure: $([ "$use_tls" == "true" ] && echo "$allow_insecure" || echo "No aplica")
$([ -n "$ws_path" ] && echo "Path: $ws_path")
$([ -n "$reverse_sni" ] && echo "SNI: $reverse_sni")
$([ -n "$reverse_host" ] && echo "Host Header: $reverse_host")
$([ "$protocol" == "shadowsocks" ] && echo -e "Método: $ss_method\nPassword: $ss_password")

URL de configuración:
$config_url
EOF

        echo -e "${SUCCESS} ${GREEN}Configuración guardada: ${WHITE}$config_file${NC}"
    else
        echo -e "${INFO} ${CYAN}Configuración creada. Use los datos mostrados para configurar manualmente.${NC}"
    fi

    # Guardar información de la cuenta en metadata (para gestión futura)
    local metadata_file="/etc/v2ray/accounts_metadata.json"
    if [ ! -f "$metadata_file" ]; then
        echo '[]' > "$metadata_file"
        chown "$V2RAY_USER:$V2RAY_GROUP" "$metadata_file"
        chmod 644 "$metadata_file"
    fi

    local account_metadata="{
        \"name\": \"$account_name\",
        \"uuid\": \"$uuid\",
        \"protocol\": \"$protocol\",
        \"transport\": \"$network\",
        \"port\": $port,
        \"created\": \"$(date -Iseconds)\",
        \"expires\": \"$expiry_date\",
        \"tls\": $([[ "$use_tls" == "true" ]] && echo "true" || echo "false"),
        \"allowInsecure\": $allow_insecure,
        \"path\": \"${ws_path:-""}\",
        \"sni\": \"${reverse_sni:-""}\",
        \"host\": \"${reverse_host:-""}\",
        \"ip\": \"$ip_address\"
    }"

    jq --argjson account "$account_metadata" '. += [$account]' "$metadata_file" > /tmp/metadata_temp.json && \
    mv /tmp/metadata_temp.json "$metadata_file"

    log_message "Cuenta creada: $account_name ($protocol + $network, puerto $port, allowInsecure: $allow_insecure, sni: $reverse_sni, host: $reverse_host)"

    # Limpiar archivos backup antiguos (mantener solo los 5 más recientes)
    find "$(dirname "$V2RAY_CONFIG_PATH")" -name "config.json.backup.*" -type f | sort -r | tail -n +6 | xargs rm -f 2>/dev/null

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para extraer todas las cuentas con allowInsecure
extract_all_accounts() {
    if [ ! -f "$V2RAY_CONFIG_PATH" ]; then
        return 1
    fi

    # Extraer cuentas usando un solo comando jq robusto
    jq -r '
        .inbounds[]? | 
        .protocol as $protocol |
        .port as $port |
        .settings as $settings |
        .streamSettings as $ss |
        ($ss.network // "tcp") as $network |
        ($ss.security // "none") as $security |
        (
            if $ss.wsSettings? then $ss.wsSettings.path
            elif $ss.httpupgradeSettings? then $ss.httpupgradeSettings.path
            elif $ss.xhttpSettings? then $ss.xhttpSettings.path
            else "" end
        ) as $path |
        ($ss.tlsSettings?.allowInsecure // false) as $allowInsecure |
        
        if $protocol == "shadowsocks" then
            "\($settings.email)|\($settings.password)|\($protocol)|\($port)|\($network)|\($security)|\($path)|\($allowInsecure)"
        elif $protocol == "trojan" then
            $settings.clients[]? | 
            "\(.email)|\(.password)|\($protocol)|\($port)|\($network)|\($security)|\($path)|\($allowInsecure)"
        else
            $settings.clients[]? | 
            "\(.email)|\(.id)|\($protocol)|\($port)|\($network)|\($security)|\($path)|\($allowInsecure)"
        end
    ' "$V2RAY_CONFIG_PATH" 2>/dev/null
}

# Función mejorada para listar cuentas
list_accounts() {
    show_banner
    echo -e "${INFO} ${BOLD}GESTIÓN DE CUENTAS V2RAY${NC}"
    echo ""

    if [ ! -f "$V2RAY_CONFIG_PATH" ]; then
        echo -e "${ERROR} ${RED}Configuración de V2Ray no encontrada${NC}"
        read -p "Presiona Enter para continuar..."
        return 1
    fi

    local local_ip=$(get_local_ip)
    local public_ip=$(get_public_ip)
    echo -e "${LINK} ${CYAN}IP Local:  ${WHITE}$local_ip${NC}"
    echo -e "${LINK} ${CYAN}IP Pública: ${WHITE}${public_ip:-"No disponible"}${NC}"
    echo ""

    # Extraer todas las cuentas
    local all_accounts
    all_accounts=$(extract_all_accounts)
    
    if [ -z "$all_accounts" ]; then
        echo -e "${WARNING} ${YELLOW}No hay cuentas configuradas${NC}"
        echo -e "${INFO} ${CYAN}Use la opción 2 del menú principal para crear una cuenta${NC}"
        read -p "Presiona Enter para continuar..."
        return
    fi

    # Convertir cuentas a array
    local accounts_array=()
    while IFS= read -r line; do
        [ -n "$line" ] && accounts_array+=("$line")
    done <<< "$all_accounts"

    while true; do
        clear
        show_banner
        echo -e "${INFO} ${BOLD}GESTIÓN DE CUENTAS V2RAY${NC}"
        echo ""
        echo -e "${LINK} ${CYAN}IP Local: ${WHITE}$local_ip${NC} │ ${LINK}${CYAN}IP Pública: ${WHITE}${public_ip:-"No disponible"}${NC}"
        echo ""

        echo -e "${CYAN}╔════╤══════════════════╤═══════════╤════════╤════════╤═══════╗${NC}"
        echo -e "${CYAN}║${WHITE} #  │ Nombre           │ Protocolo │ Puerto │ Red    │ TLS   ${CYAN}║${NC}"
        echo -e "${CYAN}╠════╪══════════════════╪═══════════╪════════╪════════╪═══════╣${NC}"

        local index=1
        for account in "${accounts_array[@]}"; do
            IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$account"
            local tls_status="${RED}No${NC}"
            [ "$security" == "tls" ] && tls_status="${GREEN}Sí${NC}"

            printf "${CYAN}║${WHITE} %-2d │ %-16s │ %-9s │ %-6s │ %-6s │ %-5s ${CYAN}║${NC}\n" \
                "$index" \
                "$(echo "$email" | cut -c1-16)" \
                "$protocol" \
                "$port" \
                "$network" \
                "$([ "$security" == "tls" ] && echo "Sí" || echo "No")"
            index=$((index+1))
        done

        echo -e "${CYAN}╚════╧══════════════════╧═══════════╧════════╧════════╧═══════╝${NC}"
        echo ""
        echo -e "${YELLOW}Opciones disponibles:${NC}"
        echo -e "  ${WHITE}[1-$(((${#accounts_array[@]})))]:${NC} Ver detalles de la cuenta"
        echo -e "  ${WHITE}d [1-$(((${#accounts_array[@]})))]:${NC} Eliminar cuenta (ej: d 1)"
        echo -e "  ${WHITE}e [1-$(((${#accounts_array[@]})))]:${NC} Editar cuenta (ej: e 1)"
        echo -e "  ${WHITE}r:${NC} Refrescar lista"
        echo -e "  ${WHITE}q:${NC} Volver al menú principal"
        echo ""
        echo -ne "${INFO} ${CYAN}Seleccione una opción: ${NC}"
        read -r choice

        case $choice in
            q|Q)
                return
                ;;
            r|R)
                all_accounts=$(extract_all_accounts)
                accounts_array=()
                while IFS= read -r line; do
                    [ -n "$line" ] && accounts_array+=("$line")
                done <<< "$all_accounts"
                ;;
            d\ *|D\ *)
                local delete_index="${choice#* }"
                if [[ "$delete_index" =~ ^[0-9]+$ ]] && [ "$delete_index" -ge 1 ] && [ "$delete_index" -le ${#accounts_array[@]} ]; then
                    delete_account_by_index "$delete_index" "${accounts_array[$((delete_index-1))]}"
                    # Refrescar lista
                    all_accounts=$(extract_all_accounts)
                    accounts_array=()
                    while IFS= read -r line; do
                        [ -n "$line" ] && accounts_array+=("$line")
                    done <<< "$all_accounts"
                else
                    echo -e "${ERROR} ${RED}Índice inválido${NC}"
                    sleep 1
                fi
                ;;
            e\ *|E\ *)
                local edit_index="${choice#* }"
                if [[ "$edit_index" =~ ^[0-9]+$ ]] && [ "$edit_index" -ge 1 ] && [ "$edit_index" -le ${#accounts_array[@]} ]; then
                    edit_account_by_index "$edit_index" "${accounts_array[$((edit_index-1))]}"
                    # Refrescar lista
                    all_accounts=$(extract_all_accounts)
                    accounts_array=()
                    while IFS= read -r line; do
                        [ -n "$line" ] && accounts_array+=("$line")
                    done <<< "$all_accounts"
                else
                    echo -e "${ERROR} ${RED}Índice inválido${NC}"
                    sleep 1
                fi
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#accounts_array[@]} ]; then
                    show_account_details "$choice" "${accounts_array[$((choice-1))]}" "$local_ip" "$public_ip"
                else
                    echo -e "${ERROR} ${RED}Opción inválida${NC}"
                    sleep 1
                fi
                ;;
        esac
    done
}

# Función para mostrar detalles de cuenta con allowInsecure
show_account_details() {
    local index="$1"
    local account_data="$2"
    local local_ip="$3"
    local public_ip="$4"
    
    IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$account_data"
    
    clear
    show_banner
    echo -e "${SUCCESS} ${GREEN}${BOLD}DETALLES DE LA CUENTA #${index}${NC}"
    echo ""

    # Información básica
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                        INFORMACIÓN BÁSICA                        ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${WHITE} 👤 Nombre:        ${YELLOW}$email${CYAN}                           ║${NC}"
    echo -e "${CYAN}║${WHITE} 🔑 UUID/Pass:     ${YELLOW}$uuid${CYAN} ║${NC}"
    echo -e "${CYAN}║${WHITE} 📡 Protocolo:     ${YELLOW}$protocol${CYAN}                              ║${NC}"
    echo -e "${CYAN}║${WHITE} 🌐 Red:           ${YELLOW}$network${CYAN}                               ║${NC}"
    echo -e "${CYAN}║${WHITE} 🔌 Puerto:        ${YELLOW}$port${CYAN}                                  ║${NC}"
    
    if [ "$security" == "tls" ]; then
        echo -e "${CYAN}║${WHITE} 🔒 TLS:           ${GREEN}Activado${CYAN}                              ║${NC}"
        echo -e "${CYAN}║${WHITE} 🔓 AllowInsecure: ${YELLOW}$allow_insecure${CYAN}                             ║${NC}"
    else
        echo -e "${CYAN}║${WHITE} 🔒 TLS:           ${RED}Desactivado${CYAN}                           ║${NC}"
    fi
    
    [ -n "$path" ] && echo -e "${CYAN}║${WHITE} 📂 Path:          ${YELLOW}$path${CYAN}                    ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"

    # URLs de configuración
    echo ""
    echo -e "${LINK} ${BOLD}URLS DE CONFIGURACIÓN:${NC}"
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                         CONFIGURACIONES                         ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    
    # URL con IP local
    local use_tls="false"
    [ "$security" == "tls" ] && use_tls="true"
    
    local local_url=$(generate_config_url "$protocol" "$uuid" "$local_ip" "$port" "$email" "$use_tls" "$path" "$network" "$allow_insecure")
    echo -e "${CYAN}║${WHITE} 🏠 IP Local:                                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${GREEN}    $local_url${CYAN}    ║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    
    # URL con IP pública (si está disponible)
    if [ -n "$public_ip" ] && [ "$public_ip" != "No disponible" ]; then
        local public_url=$(generate_config_url "$protocol" "$uuid" "$public_ip" "$port" "$email" "$use_tls" "$path" "$network" "$allow_insecure")
        echo -e "${CYAN}║${WHITE} 🌍 IP Pública:                                                  ${CYAN}║${NC}"
        echo -e "${CYAN}║${GREEN}    $public_url${CYAN}   ║${NC}"
    fi
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"

    # Generar códigos QR
    if command -v qrencode > /dev/null 2>&1; then
        echo ""
        echo -e "${INFO} ${YELLOW}¿Desea ver los códigos QR? (s/N): ${NC}"
        read -r show_qr
        
        if [[ $show_qr =~ ^[sS]$ ]]; then
            echo ""
            echo -e "${SUCCESS} ${GREEN}Código QR (IP Local):${NC}"
            echo ""
            qrencode -t ANSIUTF8 -s 1 -m 1 "$local_url" 2>/dev/null || echo -e "${ERROR} ${RED}Error al generar QR${NC}"
            
            if [ -n "$public_ip" ] && [ "$public_ip" != "No disponible" ]; then
                echo ""
                echo -e "${SUCCESS} ${GREEN}Código QR (IP Pública):${NC}"
                echo ""
                qrencode -t ANSIUTF8 -s 1 -m 1 "$public_url" 2>/dev/null || echo -e "${ERROR} ${RED}Error al generar QR${NC}"
            fi
            
            # Opción para guardar QRs como imágenes
            echo ""
            echo -e "${INFO} ${YELLOW}¿Desea guardar los códigos QR como imágenes? (s/N): ${NC}"
            read -r save_qr
            
            if [[ $save_qr =~ ^[sS]$ ]]; then
                local qr_dir="/tmp/v2ray_qr_$(date +%s)"
                mkdir -p "$qr_dir"
                
                qrencode -o "$qr_dir/${email}_local.png" "$local_url" 2>/dev/null && \
                echo -e "${SUCCESS} ${GREEN}QR Local guardado: ${WHITE}${qr_dir}/${email}_local.png${NC}"
                
                if [ -n "$public_ip" ] && [ "$public_ip" != "No disponible" ]; then
                    qrencode -o "$qr_dir/${email}_public.png" "$public_url" 2>/dev/null && \
                    echo -e "${SUCCESS} ${GREEN}QR Público guardado: ${WHITE}${qr_dir}/${email}_public.png${NC}"
                fi
            fi
        fi
    fi

    # Estadísticas de la cuenta (si están disponibles)
    echo ""
    echo -e "${INFO} ${BOLD}ESTADÍSTICAS:${NC}"
    local connection_count=$(netstat -tn 2>/dev/null | grep ":$port " | wc -l)
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE} 📊 Conexiones activas: ${YELLOW}$connection_count${CYAN}                          ║${NC}"
    echo -e "${CYAN}║${WHITE} ⏰ Estado del puerto:  $([ $connection_count -gt 0 ] && echo "${GREEN}Activo${CYAN}" || echo "${YELLOW}Inactivo${CYAN}")                            ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"

    echo ""
    echo -e "${YELLOW}Opciones disponibles:${NC}"
    echo -e "  ${WHITE}c:${NC} Copiar URL al portapapeles"
    echo -e "  ${WHITE}e:${NC} Editar esta cuenta"
    echo -e "  ${WHITE}d:${NC} Eliminar esta cuenta"
    echo -e "  ${WHITE}t:${NC} Probar conectividad del puerto"
    echo -e "  ${WHITE}Enter:${NC} Volver a la lista"
    echo ""
    echo -ne "${INFO} ${CYAN}Seleccione una opción: ${NC}"
    read -r detail_choice

    case $detail_choice in
        c|C)
            if command -v xclip > /dev/null 2>&1; then
                echo -n "$local_url" | xclip -selection clipboard
                echo -e "${SUCCESS} ${GREEN}URL copiada al portapapeles${NC}"
            elif command -v pbcopy > /dev/null 2>&1; then
                echo -n "$local_url" | pbcopy
                echo -e "${SUCCESS} ${GREEN}URL copiada al portapapeles${NC}"
            else
                echo -e "${WARNING} ${YELLOW}xclip o pbcopy no están disponibles${NC}"
                echo -e "${INFO} ${CYAN}URL: ${WHITE}$local_url${NC}"
            fi
            sleep 2
            ;;
        e|E)
            edit_account_by_data "$account_data"
            ;;
        d|D)
            delete_account_by_data "$account_data"
            return
            ;;
        t|T)
            test_port_connectivity "$port"
            ;;
        *)
            return
            ;;
    esac
    
    read -p "Presiona Enter para continuar..."
}

# Función para eliminar cuenta por índice
delete_account_by_index() {
    local index="$1"
    local account_data="$2"
    
    IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$account_data"
    
    echo ""
    echo -e "${WARNING} ${YELLOW}¿Está seguro de eliminar la cuenta '${WHITE}$email${YELLOW}'? (s/N): ${NC}"
    read -r confirm

    if [[ ! $confirm =~ ^[sS]$ ]]; then
        echo -e "${INFO} Operación cancelada"
        sleep 1
        return
    fi

    delete_account_by_data "$account_data"
}

# Función para eliminar cuenta por datos
delete_account_by_data() {
    local account_data="$1"
    IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$account_data"
    
    echo -e "${INFO} ${YELLOW}Eliminando cuenta '$email'...${NC}"

    # Crear backup antes de modificar
    cp "$V2RAY_CONFIG_PATH" "${V2RAY_CONFIG_PATH}.backup.$(date +%s)"

    # Eliminar la cuenta usando jq
    local temp_file
    temp_file=$(mktemp)
    
    jq --arg name "$email" '
        .inbounds = [.inbounds[] |
            if .settings.clients then
                .settings.clients = [.settings.clients[] | select(.email != $name)]
            else . end |
            if .settings.email then
                select(.settings.email != $name)
            else . end |
            select((.settings.clients != null and (.settings.clients | length) > 0) or .settings.email != null or .protocol == "freedom" or .protocol == "blackhole")
        ]' "$V2RAY_CONFIG_PATH" > "$temp_file"

    if [ $? -eq 0 ]; then
        mv "$temp_file" "$V2RAY_CONFIG_PATH"
        chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
        chmod 644 "$V2RAY_CONFIG_PATH"

        echo -e "${INFO} ${YELLOW}Reiniciando V2Ray...${NC}"
        if systemctl restart v2ray; then
            echo -e "${SUCCESS} ${GREEN}Cuenta '$email' eliminada exitosamente${NC}"
            log_message "Cuenta eliminada: $email"
        else
            echo -e "${ERROR} ${RED}Cuenta eliminada pero error al reiniciar V2Ray${NC}"
        fi
    else
        echo -e "${ERROR} ${RED}Error al eliminar la cuenta${NC}"
        rm -f "$temp_file"
    fi
    
    sleep 2
}

# Función para editar cuenta por índice
edit_account_by_index() {
    local index="$1"
    local account_data="$2"
    
    edit_account_by_data "$account_data"
}

# Función para editar cuenta
edit_account_by_data() {
    local account_data="$1"
    IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$account_data"
    
    echo ""
    echo -e "${GEAR} ${BOLD}EDITAR CUENTA: ${WHITE}$email${NC}"
    echo ""
    echo -e "${YELLOW}¿Qué desea modificar?${NC}"
    echo -e "  ${WHITE}1.${NC} Cambiar nombre"
    echo -e "  ${WHITE}2.${NC} Regenerar UUID/Password"
    echo -e "  ${WHITE}3.${NC} Cambiar puerto"
    echo -e "  ${WHITE}4.${NC} Alternar TLS"
    echo -e "  ${WHITE}5.${NC} Cambiar Path (WebSocket/HTTP)"
    echo -e "  ${WHITE}6.${NC} Cambiar AllowInsecure"
    echo -e "  ${WHITE}7.${NC} Cancelar"
    echo ""
    echo -ne "${INFO} ${CYAN}Seleccione una opción: ${NC}"
    read -r edit_choice

    case $edit_choice in
        1)
            edit_account_name "$email"
            ;;
        2)
            regenerate_account_uuid "$email" "$protocol"
            ;;
        3)
            change_account_port "$email" "$port"
            ;;
        4)
            toggle_account_tls "$email" "$security"
            ;;
        5)
            change_account_path "$email" "$path" "$network"
            ;;
        6)
            toggle_allow_insecure "$email" "$allow_insecure"
            ;;
        7)
            return
            ;;
        *)
            echo -e "${ERROR} ${RED}Opción inválida${NC}"
            sleep 1
            ;;
    esac
}

# Función para alternar allowInsecure
toggle_allow_insecure() {
    local account_name="$1"
    local current_allow_insecure="$2"
    
    local new_allow_insecure="false"
    if [ "$current_allow_insecure" == "false" ]; then
        new_allow_insecure="true"
        echo -e "${INFO} ${YELLOW}Activando AllowInsecure para '$account_name'${NC}"
    else
        echo -e "${INFO} ${YELLOW}Desactivando AllowInsecure para '$account_name'${NC}"
    fi

    # Actualizar configuración
    local temp_file
    temp_file=$(mktemp)
    
    jq --arg name "$account_name" --argjson new_allow_insecure "$new_allow_insecure" '
        (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings.tlsSettings.allowInsecure) = $new_allow_insecure
    ' "$V2RAY_CONFIG_PATH" > "$temp_file"

    if [ $? -eq 0 ]; then
        mv "$temp_file" "$V2RAY_CONFIG_PATH"
        chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
        chmod 644 "$V2RAY_CONFIG_PATH"
        
        systemctl restart v2ray && \
        echo -e "${SUCCESS} ${GREEN}AllowInsecure actualizado a $new_allow_insecure para '$account_name'${NC}" || \
        echo -e "${ERROR} ${RED}Error al aplicar cambios${NC}"
    else
        echo -e "${ERROR} ${RED}Error al actualizar configuración${NC}"
        rm -f "$temp_file"
    fi
    
    sleep 2
}

# Funciones auxiliares para edición de cuentas
edit_account_name() {
    local old_name="$1"
    echo -ne "${INFO} ${CYAN}Nuevo nombre para la cuenta: ${NC}"
    read -r new_name

    if [ -z "$new_name" ]; then
        echo -e "${ERROR} ${RED}El nombre no puede estar vacío${NC}"
        sleep 1
        return
    fi

    # Verificar que el nombre no exista
    if jq -e --arg name "$new_name" '.inbounds[] | select(.settings.clients[]?.email == $name)' "$V2RAY_CONFIG_PATH" > /dev/null 2>&1; then
        echo -e "${ERROR} ${RED}Ya existe una cuenta con ese nombre${NC}"
        sleep 1
        return
    fi

    # Actualizar nombre en la configuración
    local temp_file
    temp_file=$(mktemp)
    
    jq --arg old_name "$old_name" --arg new_name "$new_name" '
        (.inbounds[].settings.clients[]? | select(.email == $old_name) | .email) = $new_name
    ' "$V2RAY_CONFIG_PATH" > "$temp_file"

    if [ $? -eq 0 ]; then
        mv "$temp_file" "$V2RAY_CONFIG_PATH"
        chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
        chmod 644 "$V2RAY_CONFIG_PATH"
        
        systemctl restart v2ray && \
        echo -e "${SUCCESS} ${GREEN}Nombre cambiado de '$old_name' a '$new_name'${NC}" || \
        echo -e "${ERROR} ${RED}Error al aplicar cambios${NC}"
    else
        echo -e "${ERROR} ${RED}Error al actualizar configuración${NC}"
        rm -f "$temp_file"
    fi
    
    sleep 2
}

regenerate_account_uuid() {
    local account_name="$1"
    local protocol="$2"
    
    local new_uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(..\)/\1-/g; s/-$//' | sed 's/^\(.\{8\}\)-\(.\{4\}\)-\(.\{4\}\)-\(.\{4\}\)-/\1-\2-\3-\4-/')
    
    echo -e "${INFO} ${YELLOW}Regenerando UUID/Password...${NC}"
    echo -e "${CYAN}Nuevo UUID: ${WHITE}$new_uuid${NC}"

    local temp_file
    temp_file=$(mktemp)
    
    if [ "$protocol" == "trojan" ]; then
        jq --arg name "$account_name" --arg new_uuid "$new_uuid" '
            (.inbounds[].settings.clients[]? | select(.email == $name) | .password) = $new_uuid
        ' "$V2RAY_CONFIG_PATH" > "$temp_file"
    else
        jq --arg name "$account_name" --arg new_uuid "$new_uuid" '
            (.inbounds[].settings.clients[]? | select(.email == $name) | .id) = $new_uuid
        ' "$V2RAY_CONFIG_PATH" > "$temp_file"
    fi

    if [ $? -eq 0 ]; then
        mv "$temp_file" "$V2RAY_CONFIG_PATH"
        chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
        chmod 644 "$V2RAY_CONFIG_PATH"
        
        systemctl restart v2ray && \
        echo -e "${SUCCESS} ${GREEN}UUID/Password regenerado para '$account_name'${NC}" || \
        echo -e "${ERROR} ${RED}Error al aplicar cambios${NC}"
    else
        echo -e "${ERROR} ${RED}Error al actualizar configuración${NC}"
        rm -f "$temp_file"
    fi
    
    sleep 2
}

# Función para probar conectividad del puerto
test_port_connectivity() {
    local port="$1"
    echo -e "${INFO} ${YELLOW}Probando conectividad del puerto $port...${NC}"
    
    if netstat -tlnp 2>/dev/null | grep ":$port " > /dev/null; then
        echo -e "${SUCCESS} ${GREEN}Puerto $port está escuchando${NC}"
        
        # Mostrar proceso que usa el puerto
        local process=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $NF}' | head -n1)
        [ -n "$process" ] && echo -e "${INFO} ${CYAN}Proceso: ${WHITE}$process${NC}"
        
        # Probar conexión local
        if timeout 3 bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            echo -e "${SUCCESS} ${GREEN}Conexión local al puerto exitosa${NC}"
        else
            echo -e "${WARNING} ${YELLOW}No se pudo conectar localmente${NC}"
        fi
    else
        echo -e "${ERROR} ${RED}Puerto $port no está escuchando${NC}"
        echo -e "${INFO} ${CYAN}Verificando configuración de V2Ray...${NC}"
        
        if ! systemctl is-active --quiet v2ray; then
            echo -e "${ERROR} ${RED}V2Ray no está ejecutándose${NC}"
        else
            echo -e "${WARNING} ${YELLOW}V2Ray está ejecutándose pero el puerto no está activo${NC}"
        fi
    fi
    
    sleep 3
}

toggle_account_tls() {
   local account_name="$1"
   local current_security="$2"
   
   local new_security=""
   if [ "$current_security" == "tls" ]; then
       new_security="none"
       echo -e "${INFO} ${YELLOW}Desactivando TLS para '$account_name'${NC}"
   else
       new_security="tls"
       echo -e "${INFO} ${YELLOW}Activando TLS para '$account_name'${NC}"
       
       # Verificar que existan certificados
       if [ ! -f "$CERT_PATH/v2ray.crt" ] || [ ! -f "$CERT_PATH/v2ray.key" ]; then
           echo -e "${WARNING} ${YELLOW}Certificados TLS no encontrados. Generando...${NC}"
           generate_tls_certificates
       fi
   fi

   # Actualizar configuración TLS
   local temp_file
   temp_file=$(mktemp)
   
   if [ "$new_security" == "tls" ]; then
       jq --arg name "$account_name" '
           (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings.security) = "tls" |
           (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings.tlsSettings) = {
               "certificates": [
                   {
                       "certificateFile": "'$CERT_PATH'/v2ray.crt",
                       "keyFile": "'$CERT_PATH'/v2ray.key"
                   }
               ]
           }
       ' "$V2RAY_CONFIG_PATH" > "$temp_file"
   else
       jq --arg name "$account_name" '
           (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings.security) = "none" |
           (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings) |= del(.tlsSettings)
       ' "$V2RAY_CONFIG_PATH" > "$temp_file"
   fi

   if [ $? -eq 0 ]; then
       mv "$temp_file" "$V2RAY_CONFIG_PATH"
       chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
       chmod 644 "$V2RAY_CONFIG_PATH"
       
       systemctl restart v2ray && \
       echo -e "${SUCCESS} ${GREEN}TLS $([ "$new_security" == "tls" ] && echo "activado" || echo "desactivado") para '$account_name'${NC}" || \
       echo -e "${ERROR} ${RED}Error al aplicar cambios${NC}"
   else
       echo -e "${ERROR} ${RED}Error al actualizar configuración${NC}"
       rm -f "$temp_file"
   fi
   
   sleep 2
}

change_account_path() {
   local account_name="$1"
   local current_path="$2"
   local network="$3"
   
   if [[ "$network" != "ws" && "$network" != "httpupgrade" && "$network" != "xhttp" ]]; then
       echo -e "${WARNING} ${YELLOW}El protocolo $network no usa path${NC}"
       sleep 2
       return
   fi

   echo -e "${INFO} ${CYAN}Path actual: ${WHITE}${current_path:-"(vacío)"}${NC}"
   echo -ne "${INFO} ${CYAN}Nuevo path (ej: /mi-path): ${NC}"
   read -r new_path

   if [ -z "$new_path" ]; then
       echo -e "${ERROR} ${RED}El path no puede estar vacío${NC}"
       sleep 2
       return
   fi

   # Asegurar que comience con /
   if [[ ! "$new_path" =~ ^/ ]]; then
       new_path="/$new_path"
   fi

   # Actualizar path según el tipo de red
   local temp_file
   temp_file=$(mktemp)
   
   case "$network" in
       "ws")
           jq --arg name "$account_name" --arg new_path "$new_path" '
               (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings.wsSettings.path) = $new_path
           ' "$V2RAY_CONFIG_PATH" > "$temp_file"
           ;;
       "httpupgrade")
           jq --arg name "$account_name" --arg new_path "$new_path" '
               (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings.httpupgradeSettings.path) = $new_path
           ' "$V2RAY_CONFIG_PATH" > "$temp_file"
           ;;
       "xhttp")
           jq --arg name "$account_name" --arg new_path "$new_path" '
               (.inbounds[] | select(.settings.clients[]?.email == $name) | .streamSettings.xhttpSettings.path) = $new_path
           ' "$V2RAY_CONFIG_PATH" > "$temp_file"
           ;;
       *)
           echo -e "${ERROR} ${RED}Tipo de red no soportado para cambio de path${NC}"
           sleep 2
           return
           ;;
   esac

   if [ $? -eq 0 ]; then
       mv "$temp_file" "$V2RAY_CONFIG_PATH"
       chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
       chmod 644 "$V2RAY_CONFIG_PATH"
       
       systemctl restart v2ray && \
       echo -e "${SUCCESS} ${GREEN}Path cambiado a '$new_path' para '$account_name'${NC}" || \
       echo -e "${ERROR} ${RED}Error al aplicar cambios${NC}"
   else
       echo -e "${ERROR} ${RED}Error al actualizar configuración${NC}"
       rm -f "$temp_file"
   fi
   
   sleep 2
}

# Función mejorada para eliminar cuentas (mantener por compatibilidad)
delete_account() {
    show_banner
    echo -e "${WARNING} ${BOLD}ELIMINAR CUENTA V2RAY${NC}"
    echo ""

    if [ ! -f "$V2RAY_CONFIG_PATH" ]; then
        echo -e "${ERROR} ${RED}Configuración de V2Ray no encontrada${NC}"
        read -p "Presiona Enter para continuar..."
        return 1
    fi

    # Mostrar cuentas disponibles
    local all_accounts
    all_accounts=$(extract_all_accounts)
    
    if [ -z "$all_accounts" ]; then
        echo -e "${WARNING} ${YELLOW}No hay cuentas configuradas${NC}"
        read -p "Presiona Enter para continuar..."
        return
    fi

    echo -e "${INFO} ${YELLOW}Cuentas disponibles:${NC}"
   echo -e "${CYAN}╔════╤══════════════════╤═══════════╤════════╗${NC}"
   echo -e "${CYAN}║${WHITE} #  │ Nombre           │ Protocolo │ Puerto ${CYAN}║${NC}"
   echo -e "${CYAN}╠════╪══════════════════╪═══════════╪════════╣${NC}"

   local accounts_array=()
   local index=1
   while IFS= read -r line; do
       if [ -n "$line" ]; then
           accounts_array+=("$line")
           IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$line"
           printf "${CYAN}║${WHITE} %-2d │ %-16s │ %-9s │ %-6s ${CYAN}║${NC}\n" \
               "$index" \
               "$(echo "$email" | cut -c1-16)" \
               "$protocol" \
               "$port"
           index=$((index+1))
       fi
   done <<< "$all_accounts"

   echo -e "${CYAN}╚════╧══════════════════╧═══════════╧════════╝${NC}"
   echo ""

   echo -ne "${INFO} ${CYAN}Ingrese el NÚMERO de la cuenta a eliminar (0 para cancelar): ${NC}"
   read -r account_choice

   if [ "$account_choice" = "0" ] || [ -z "$account_choice" ]; then
       echo -e "${INFO} Operación cancelada"
       read -p "Presiona Enter para continuar..."
       return 0
   fi

   if [[ "$account_choice" =~ ^[0-9]+$ ]] && [ "$account_choice" -ge 1 ] && [ "$account_choice" -le ${#accounts_array[@]} ]; then
       local selected_account="${accounts_array[$((account_choice-1))]}"
       IFS='|' read -r email uuid protocol port network security path allow_insecure <<< "$selected_account"
       
       echo ""
       echo -e "${WARNING} ${YELLOW}¿Está seguro de eliminar la cuenta '${WHITE}$email${YELLOW}'? (s/N): ${NC}"
       read -r confirm

       if [[ $confirm =~ ^[sS]$ ]]; then
           delete_account_by_data "$selected_account"
       else
           echo -e "${INFO} Operación cancelada"
       fi
   else
       echo -e "${ERROR} ${RED}Número inválido${NC}"
   fi

   echo ""
   read -p "Presiona Enter para continuar..."
}

change_account_port() {
   local account_name="$1"
   local current_port="$2"
   
   echo -e "${INFO} ${CYAN}Puerto actual: ${WHITE}$current_port${NC}"
   echo -ne "${INFO} ${CYAN}Nuevo puerto (1024-65535): ${NC}"
   read -r new_port

   # Validar puerto
   if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1024 ] || [ "$new_port" -gt 65535 ]; then
       echo -e "${ERROR} ${RED}Puerto inválido${NC}"
       sleep 2
       return
   fi

   # Verificar si el puerto ya está en uso
   if jq -e --arg port "$new_port" '.inbounds[] | select(.port == ($port|tonumber))' "$V2RAY_CONFIG_PATH" > /dev/null 2>&1; then
       echo -e "${WARNING} ${YELLOW}El puerto $new_port ya está en uso${NC}"
       echo -ne "${INFO} ${CYAN}¿Continuar de todos modos? (s/N): ${NC}"
       read -r continue_choice
       if [[ ! $continue_choice =~ ^[sS]$ ]]; then
           return
       fi
   fi

   # Actualizar puerto en la configuración
   local temp_file
   temp_file=$(mktemp)
   
   jq --arg name "$account_name" --arg new_port "$new_port" '
       (.inbounds[] | select(.settings.clients[]?.email == $name) | .port) = ($new_port|tonumber)
   ' "$V2RAY_CONFIG_PATH" > "$temp_file"

   if [ $? -eq 0 ]; then
       mv "$temp_file" "$V2RAY_CONFIG_PATH"
       chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
       chmod 644 "$V2RAY_CONFIG_PATH"
       
       systemctl restart v2ray && \
       echo -e "${SUCCESS} ${GREEN}Puerto cambiado de $current_port a $new_port para '$account_name'${NC}" || \
       echo -e "${ERROR} ${RED}Error al aplicar cambios${NC}"
   else
       echo -e "${ERROR} ${RED}Error al actualizar configuración${NC}"
       rm -f "$temp_file"
   fi
   
   sleep 2
}

# Función para verificar y reparar configuración
check_and_repair_config() {
    if [ ! -f "$V2RAY_CONFIG_PATH" ]; then
        echo -e "${WARNING} ${YELLOW}Creando configuración básica...${NC}"
        mkdir -p "$(dirname "$V2RAY_CONFIG_PATH")"
        create_basic_config
    fi

    # Verificar estructura JSON
    if ! jq empty "$V2RAY_CONFIG_PATH" 2>/dev/null; then
        echo -e "${ERROR} ${RED}Configuración JSON inválida. Recreando...${NC}"
        create_basic_config
    fi

    # Verificar que exista el array de inbounds
    if ! jq -e '.inbounds' "$V2RAY_CONFIG_PATH" > /dev/null 2>&1; then
        jq '.inbounds = []' "$V2RAY_CONFIG_PATH" > /tmp/v2ray_temp.json
        mv /tmp/v2ray_temp.json "$V2RAY_CONFIG_PATH"
    fi

    # Generar certificados si no existen
    if [ ! -f "$CERT_PATH/v2ray.crt" ] || [ ! -f "$CERT_PATH/v2ray.key" ]; then
        echo -e "${WARNING} ${YELLOW}Generando certificados TLS...${NC}"
        generate_tls_certificates > /dev/null 2>&1
    fi

    # Asegurar permisos de directorio
    chown -R "$V2RAY_USER:$V2RAY_GROUP" /etc/v2ray
    chmod -R 755 /etc/v2ray
    chown "$V2RAY_USER:$V2RAY_GROUP" "$V2RAY_CONFIG_PATH"
    chmod 644 "$V2RAY_CONFIG_PATH"
}

# Función para mostrar estadísticas del sistema
show_system_stats() {
    show_banner
    echo -e "${INFO} ${BOLD}ESTADÍSTICAS DEL SISTEMA${NC}"
    echo ""

    # Estado de V2Ray
    if systemctl is-active --quiet v2ray; then
        echo -e "${SUCCESS} ${GREEN}Estado de V2Ray: Activo${NC}"
    else
        echo -e "${ERROR} ${RED}Estado de V2Ray: Inactivo${NC}"
    fi

    # Información de red
    local local_ip=$(get_local_ip)
    local public_ip=$(get_public_ip)

    echo -e "${LINK} ${CYAN}IP Local:  ${WHITE}$local_ip${NC}"
    echo -e "${LINK} ${CYAN}IP Pública: ${WHITE}${public_ip:-"No disponible"}${NC}"

    # Estadísticas de memoria y CPU
    local memory_usage=$(free | grep '^Mem' | awk '{print int($3/$2 * 100)}')
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)

    echo -e "${INFO} ${CYAN}Uso de Memoria: ${WHITE}${memory_usage}%${NC}"
    echo -e "${INFO} ${CYAN}Uso de CPU: ${WHITE}${cpu_usage}%${NC}"

    # Número de cuentas activas
    local account_count=0
    if [ -f "$V2RAY_CONFIG_PATH" ]; then
        account_count=$(jq '[.inbounds[]?.settings.clients[]?] | length' "$V2RAY_CONFIG_PATH" 2>/dev/null || echo 0)
    fi

    echo -e "${INFO} ${CYAN}Cuentas Activas: ${WHITE}$account_count${NC}"

    # Puertos en uso
    echo ""
    echo -e "${INFO} ${YELLOW}Puertos V2Ray en uso:${NC}"
    if [ -f "$V2RAY_CONFIG_PATH" ]; then
        jq -r '.inbounds[]?.port' "$V2RAY_CONFIG_PATH" 2>/dev/null | while read port; do
            [ -n "$port" ] && echo -e "  ${WHITE}• Puerto $port${NC}"
        done
    fi

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para mostrar logs de V2Ray
show_logs() {
    show_banner
    echo -e "${INFO} ${BOLD}LOGS DE V2RAY${NC}"
    echo ""

    echo -e "${YELLOW}Últimas 20 líneas del log del sistema:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    journalctl -u v2ray -n 20 --no-pager
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════╝${NC}"

    echo ""
    echo -e "${YELLOW}Logs de acceso (si están disponibles):${NC}"
    if [ -f "/var/log/v2ray/access.log" ]; then
        echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
        tail -n 10 /var/log/v2ray/access.log 2>/dev/null || echo "No hay logs de acceso disponibles"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════╝${NC}"
    else
        echo "No hay logs de acceso configurados"
    fi

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para backup y restauración
backup_restore_menu() {
    while true; do
        show_banner
        echo -e "${SHIELD} ${BOLD}BACKUP Y RESTAURACIÓN${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Crear backup de configuración"
        echo -e "${WHITE}2.${NC} Restaurar desde backup"
        echo -e "${WHITE}3.${NC} Listar backups disponibles"
        echo -e "${WHITE}4.${NC} Eliminar backup"
        echo -e "${WHITE}5.${NC} Volver al menú principal"
        echo ""
        echo -ne "${INFO} ${CYAN}Seleccione una opción: ${NC}"
        read -r choice

        case $choice in
            1) create_backup ;;
            2) restore_backup ;;
            3) list_backups ;;
            4) delete_backup ;;
            5) break ;;
            *) echo -e "${ERROR} ${RED}Opción inválida${NC}"; sleep 1 ;;
        esac
    done
}

# Función para crear backup
create_backup() {
    local backup_dir="/etc/v2ray/backups"
    local backup_name="v2ray_backup_$(date +%Y%m%d_%H%M%S).tar.gz"

    mkdir -p "$backup_dir"

    echo -e "${INFO} ${YELLOW}Creando backup...${NC}"

    tar -czf "$backup_dir/$backup_name" \
        -C / \
        usr/local/etc/v2ray \
        etc/v2ray/certs \
        var/log/v2ray 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${SUCCESS} ${GREEN}Backup creado: $backup_dir/$backup_name${NC}"
        log_message "Backup creado: $backup_name"
    else
        echo -e "${ERROR} ${RED}Error al crear backup${NC}"
    fi

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para restaurar backup
restore_backup() {
    local backup_dir="/etc/v2ray/backups"

    if [ ! -d "$backup_dir" ] || [ -z "$(ls -A $backup_dir 2>/dev/null)" ]; then
        echo -e "${WARNING} ${YELLOW}No hay backups disponibles${NC}"
        read -p "Presiona Enter para continuar..."
        return
    fi

    echo -e "${INFO} ${YELLOW}Backups disponibles:${NC}"
    ls -la "$backup_dir"/*.tar.gz 2>/dev/null | nl

    echo ""
    echo -ne "${INFO} ${CYAN}Ingrese el nombre completo del backup: ${NC}"
    read -r backup_file

    if [ -f "$backup_dir/$backup_file" ]; then
        echo -e "${WARNING} ${YELLOW}¿Confirma restaurar este backup? (s/N): ${NC}"
        read -r confirm

        if [[ $confirm =~ ^[sS]$ ]]; then
            systemctl stop v2ray
            tar -xzf "$backup_dir/$backup_file" -C /
            systemctl start v2ray
            echo -e "${SUCCESS} ${GREEN}Backup restaurado exitosamente${NC}"
            log_message "Backup restaurado: $backup_file"
        fi
    else
        echo -e "${ERROR} ${RED}Archivo de backup no encontrado${NC}"
    fi

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para listar backups
list_backups() {
    local backup_dir="/etc/v2ray/backups"

    if [ ! -d "$backup_dir" ] || [ -z "$(ls -A $backup_dir 2>/dev/null)" ]; then
        echo -e "${WARNING} ${YELLOW}No hay backups disponibles${NC}"
    else
        echo -e "${INFO} ${YELLOW}Backups disponibles:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════════════════════════${NC}"
        ls -lah "$backup_dir"/*.tar.gz 2>/dev/null
        echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    fi

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para eliminar backup
delete_backup() {
    local backup_dir="/etc/v2ray/backups"

    if [ ! -d "$backup_dir" ] || [ -z "$(ls -A $backup_dir 2>/dev/null)" ]; then
        echo -e "${WARNING} ${YELLOW}No hay backups para eliminar${NC}"
        read -p "Presiona Enter para continuar..."
        return
    fi

    list_backups
    echo -ne "${INFO} ${CYAN}Ingrese el nombre del backup a eliminar: ${NC}"
    read -r backup_file

    if [ -f "$backup_dir/$backup_file" ]; then
        echo -e "${WARNING} ${YELLOW}¿Confirma eliminar el backup '$backup_file'? (s/N): ${NC}"
        read -r confirm

        if [[ $confirm =~ ^[sS]$ ]]; then
            rm -f "$backup_dir/$backup_file"
            echo -e "${SUCCESS} ${GREEN}Backup eliminado${NC}"
            log_message "Backup eliminado: $backup_file"
        fi
    else
        echo -e "${ERROR} ${RED}Archivo no encontrado${NC}"
    fi

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para exportar configuraciones
export_configs() {
    show_banner
    echo -e "${LINK} ${BOLD}EXPORTAR CONFIGURACIONES${NC}"
    echo ""

    if [ ! -f "$V2RAY_CONFIG_PATH" ]; then
        echo -e "${ERROR} ${RED}No hay configuración V2Ray disponible${NC}"
        read -p "Presiona Enter para continuar..."
        return
    fi

    local export_dir="/tmp/v2ray_export_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$export_dir"

    # Exportar todas las configuraciones como URLs
    jq -r '.inbounds[] | select(.settings.clients != null) | . as $inbound | .settings.clients[] | "\(.email)|\(.id // .)|\($inbound.protocol)|\($inbound.port)|\($inbound.streamSettings.wsSettings.path // "")|\($inbound.streamSettings.security // "none")|\($inbound.streamSettings.tlsSettings.allowInsecure // false)"' "$V2RAY_CONFIG_PATH" 2>/dev/null > "$export_dir/accounts.txt"

    local local_ip=$(get_local_ip)

    echo -e "${SUCCESS} ${GREEN}Exportando configuraciones...${NC}"
    echo ""

    while IFS='|' read -r name uuid protocol port ws_path security allow_insecure; do
        if [ -n "$name" ]; then
            local use_tls="false"
            [ "$security" == "tls" ] && use_tls="true"

            local config_url=$(generate_config_url "$protocol" "$uuid" "$local_ip" "$port" "$name" "$use_tls" "$ws_path" "$network" "$allow_insecure")

            echo -e "${INFO} ${CYAN}Cuenta: ${WHITE}$name${NC}"
            echo -e "${LINK} URL: ${GREEN}$config_url${NC}"
            echo "$config_url" > "$export_dir/${name}_config.txt"

            if command -v qrencode > /dev/null 2>&1; then
                qrencode -o "$export_dir/${name}_qr.png" "$config_url" 2>/dev/null
                echo -e "${SUCCESS} QR guardado: ${WHITE}${name}_qr.png${NC}"
            fi
            echo ""
        fi
    done < "$export_dir/accounts.txt"

    echo -e "${SUCCESS} ${GREEN}Configuraciones exportadas en: ${WHITE}$export_dir${NC}"

    echo ""
    read -p "Presiona Enter para continuar..."
}

# Función para gestionar certificados TLS
manage_certificates() {
    while true; do
        show_banner
        echo -e "${CERTIFICATE} ${BOLD}GESTIÓN DE CERTIFICADOS TLS${NC}"
        echo ""
        echo -e "${INFO} ${YELLOW}Seleccione una operación:${NC}"
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${WHITE} 1.${NC} Mostrar información de certificados actuales            ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} 2.${NC} Generar nuevos certificados TLS (sobrescribir)         ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} 3.${NC} Volver al menú principal                              ${CYAN}║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -ne "${INFO} ${CYAN}Opción: ${NC}"
        read -r choice

        case $choice in
            1)
                check_existing_certificates
                ;;
            2)
                generate_tls_certificates
                ;;
            3)
                break
                ;;
            *)
                echo -e "${ERROR} ${RED}Opción inválida${NC}"
                sleep 1
                ;;
        esac
    done
}

# Función principal del menú con diseño mejorado
main_menu() {
    while true; do
        show_banner
        show_system_info
        echo ""
        # Banner animado con figlet si está disponible
        if command -v figlet > /dev/null 2>&1 && command -v lolcat > /dev/null 2>&1; then
            echo "V2RAY MANAGER" | figlet -f small | lolcat 2>/dev/null || echo -e "${PURPLE}V2RAY MANAGER${NC}"
        else
            echo -e "${PURPLE}${BOLD}    ╦  ╦┌─┐┬─┐┌─┐┬ ┬  ╔╦╗┌─┐┌┐┌┌─┐┌─┐┌─┐┬─┐${NC}"
            echo -e "${PURPLE}${BOLD}    ╚╗╔╝┌─┘├┬┘├─┤└┬┘  ║║║├─┤│││├─┤│ ┬├┤ ├┬┘${NC}"
            echo -e "${PURPLE}${BOLD}     ╚╝ └─┘┴└─┴ ┴ ┴   ╩ ╩┴ ┴┘└┘┴ ┴└─┘└─┘┴└─${NC}"
        fi

        echo ""
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${WHITE}                           MENÚ PRINCIPAL                         ${CYAN}║${NC}"
        echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║${WHITE} ${ROCKET}  1.${NC} Instalar V2Ray                                      ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${GEAR}  2.${NC} Crear nueva cuenta                                  ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${INFO}  3.${NC} Gestionar cuentas (listar/ver/editar/eliminar)      ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${ERROR} 4.${NC} Eliminar cuenta (método rápido)                     ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${SHIELD} 5.${NC} Verificar y reparar configuración                   ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${WARNING} 6.${NC} Desinstalar V2Ray                                   ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${INFO}  7.${NC} Mostrar estadísticas del sistema                    ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${INFO}  8.${NC} Ver logs de V2Ray                                   ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${SHIELD} 9.${NC} Backup y Restauración                               ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${LINK} 10.${NC} Exportar configuraciones                            ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${CERTIFICATE} 11.${NC} Gestionar certificados TLS                   ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${INFO}  12.${NC} Diagnosticar problemas de V2Ray                    ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${GEAR}  13.${NC} Corregir servicio systemd (timeout)               ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${INFO}  14.${NC} Estadísticas detalladas de cuentas                ${CYAN}║${NC}"
        echo -e "${CYAN}║${WHITE} ${ERROR} 0.${NC} Salir                                               ${CYAN}║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # Mostrar estado actual de V2Ray
        if systemctl is-active --quiet v2ray 2>/dev/null; then
            echo -e "${SUCCESS} ${GREEN}Estado: V2Ray está ejecutándose${NC}"
        else
            echo -e "${ERROR} ${RED}Estado: V2Ray no está ejecutándose${NC}"
        fi

        echo ""
        echo -ne "${INFO} ${BOLD}${CYAN}Seleccione una opción: ${NC}"
        read -r choice

        case $choice in
            1) install_v2ray ;;
            2) create_account ;;
            3) list_accounts ;;
            4) delete_account ;;
            5)
                check_and_repair_config
                echo -e "${SUCCESS} ${GREEN}Configuración verificada y reparada${NC}"
                read -p "Presiona Enter para continuar..."
                ;;
            6) uninstall_v2ray ;;
            7) show_system_stats ;;
            8) show_logs ;;
            9) backup_restore_menu ;;
            10) export_configs ;;
            11) manage_certificates ;;
            12) 
                diagnose_v2ray
                read -p "Presiona Enter para continuar..."
                ;;
            13) 
                fix_systemd_service
                systemctl enable v2ray > /dev/null 2>&1
                systemctl start v2ray
                sleep 2
                if systemctl is-active --quiet v2ray; then
                    echo -e "${SUCCESS} ${GREEN}V2Ray iniciado correctamente${NC}"
                else
                    echo -e "${ERROR} ${RED}Aún hay problemas. Ejecutando diagnóstico...${NC}"
                    diagnose_v2ray
                fi
                read -p "Presiona Enter para continuar..."
                ;;
            14) show_detailed_account_stats ;;
            0)
                echo -e "${SUCCESS} ${GREEN}¡Gracias por usar V2Ray Manager!${NC}"
                echo -e "${INFO} ${YELLOW}Script creado con ${RED}❤️${YELLOW} para la comunidad${NC}"
                exit 0
                ;;
            *)
                echo -e "${ERROR} ${RED}Opción inválida. Intente nuevamente.${NC}"
                sleep 1
                ;;
        esac
    done
}

# Función de inicialización
init_script() {
    # Verificar si se ejecuta como root
    check_root

    # Crear directorio de logs si no existe
    mkdir -p "$(dirname "$LOG_FILE")"

    # Log de inicio
    log_message "V2Ray Manager iniciado"

    # Verificar dependencias básicas
    if ! command -v jq > /dev/null 2>&1; then
        echo -e "${WARNING} ${YELLOW}Instalando dependencias básicas...${NC}"
        install_dependencies
    fi
}

# Función de manejo de señales
cleanup() {
    echo ""
    echo -e "${INFO} ${YELLOW}Limpiando archivos temporales...${NC}"
    rm -f /tmp/v2ray_*
    echo -e "${SUCCESS} ${GREEN}¡Hasta luego!${NC}"
    exit 0
}

# Registrar manejo de señales
trap cleanup SIGINT SIGTERM

# ═══════════════════════════════════════════════════════════════════════════════════════════════
#                            INICIO DEL SCRIPT
# ════════════════════════════════════════════════════════════════════════════════════════════════════
# Inicializar el script
init_script

# Ejecutar menú principal
main_menu
