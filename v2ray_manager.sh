#!/bin/bash

# Colores para mejor legibilidad
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Función para obtener la IP local
get_local_ip() {
    ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1
}

# Función para obtener la IP pública
get_public_ip() {
    curl -s ifconfig.me
}
# Verificar dependencias y instalarlas
install_dependencies() {
    echo -e "${YELLOW}Verificando e instalando dependencias...${NC}"
    local packages=(curl openssl jq)
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            echo -e "${YELLOW}Instalando $pkg...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update
                apt-get install -y "$pkg"
            else
                echo -e "${RED}No se pudo instalar $pkg. Por favor, instálelo manualmente.${NC}"
                return 1
            fi
        fi
    done
}
# Generar certificados TLS autofirmados
generate_tls_certificates() {
    echo -e "${YELLOW}Generando certificados TLS...${NC}"
    mkdir -p /etc/v2ray/certs
    
    # Verificar si los certificados ya existen
    if [ ! -f "/etc/v2ray/certs/v2ray.crt" ] || [ ! -f "/etc/v2ray/certs/v2ray.key" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/v2ray/certs/v2ray.key \
            -out /etc/v2ray/certs/v2ray.crt \
            -subj "/CN=v2ray.local"
        
        chmod 600 /etc/v2ray/certs/v2ray.crt /etc/v2ray/certs/v2ray.key
        chown nobody:nogroup /etc/v2ray/certs/v2ray.crt /etc/v2ray/certs/v2ray.key
        
        echo -e "${GREEN}Certificados TLS generados exitosamente.${NC}"
    else
        echo -e "${GREEN}Los certificados TLS ya existen.${NC}"
    fi
}
# Función principal de instalación de V2Ray
install_v2ray() {
    # Instalar dependencias
    install_dependencies
    
    # Generar certificados
    generate_tls_certificates
    
    echo -e "${YELLOW}Instalando V2Ray...${NC}"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    systemctl enable v2ray
    systemctl start v2ray
    
    echo -e "${GREEN}V2Ray instalado y activado.${NC}"
    
    # Verificar y reparar configuración
    check_and_repair_config
}
# Verificar si el script se está ejecutando como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Este script debe ejecutarse como root${NC}"
    exit 1
fi
# Función para generar un UUID aleatorio
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# Función para verificar el estado de V2Ray
check_v2ray_status() {
    echo -e "${YELLOW}Verificando el estado de V2Ray...${NC}"
    if systemctl is-active --quiet v2ray; then
        echo -e "${GREEN}V2Ray está activo y en ejecución.${NC}"
    else
        echo -e "${RED}V2Ray no está en ejecución. Intentando iniciar...${NC}"
        systemctl start v2ray
        if systemctl is-active --quiet v2ray; then
            echo -e "${GREEN}V2Ray se ha iniciado correctamente.${NC}"
        else
            echo -e "${RED}No se pudo iniciar V2Ray. Verifique los logs para más detalles.${NC}"
            journalctl -u v2ray | tail -n 20
        fi
    fi
}

# Función para verificar la configuración de V2Ray
verify_v2ray_config() {
    echo -e "${YELLOW}Verificando la configuración de V2Ray...${NC}"
    if v2ray test -config /usr/local/etc/v2ray/config.json; then
        echo -e "${GREEN}La configuración de V2Ray es válida.${NC}"
    else
        echo -e "${RED}La configuración de V2Ray no es válida. Por favor, revise el archivo de configuración.${NC}"
    fi
}

# Función para verificar y reparar la configuración de V2Ray
check_and_repair_config() {
    echo -e "${YELLOW}Verificando y reparando configuración de V2Ray...${NC}"
    
    # Ruta del archivo de configuración
    local config_path="/usr/local/etc/v2ray/config.json"
    
    # Generar certificados TLS si no existen
    generate_tls_certificates
    
    # Crear configuración si no existe o está vacía
    if [ ! -f "$config_path" ] || [ ! -s "$config_path" ]; then
        echo -e "${RED}Creando configuración básica de V2Ray...${NC}"
        
        mkdir -p "$(dirname "$config_path")"
        
        cat > "$config_path" << EOL
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [{
    "port": 10086,
    "protocol": "vmess",
    "settings": {
      "clients": [],
      "disableInsecureEncryption": false
    },
    "streamSettings": {
      "network": "tcp"
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOL
    fi
    
    # Validar la estructura de la configuración
    if ! jq -e '.inbounds[0].settings.clients' "$config_path" > /dev/null 2>&1; then
        echo -e "${RED}Corrigiendo estructura de la configuración...${NC}"
        jq '.inbounds[0].settings.clients = []' "$config_path" > "/tmp/v2ray_config_temp.json"
        mv "/tmp/v2ray_config_temp.json" "$config_path"
    fi
    
    # Verificar configuración
    if v2ray test -config "$config_path"; then
        echo -e "${GREEN}La configuración de V2Ray es válida.${NC}"
    else
        echo -e "${RED}La configuración de V2Ray no es válida. Se usará configuración básica.${NC}"
    fi
    
    # Reiniciar V2Ray
    systemctl restart v2ray
}

# Función para crear una nueva cuenta
create_account() {
    check_and_repair_config
    echo -e "${YELLOW}Creando nueva cuenta V2Ray...${NC}"

    # Generar un nuevo UUID
    uuid=$(cat /proc/sys/kernel/random/uuid)

    # Solicitar al usuario el nombre de la cuenta y verificar que no exista
    while true; do
        read -p "Ingrese el nombre para la nueva cuenta: " account_name
        if grep -q "\"email\": \"$account_name\"" /usr/local/etc/v2ray/config.json; then
            echo -e "${RED}Ya existe una cuenta con ese nombre. Por favor, elija otro.${NC}"
        else
            break
        fi
    done

    # Solicitar al usuario la duración en días
    while true; do
        read -p "Ingrese la duración de la cuenta en días: " duration
        if [[ "$duration" =~ ^[0-9]+$ ]]; then
            break
        else
            echo -e "${RED}Por favor, ingrese un número válido de días.${NC}"
        fi
    done

    # Calcular la fecha de expiración
    expiry_date=$(date -d "+$duration days" +"%Y-%m-%d")

    # Seleccionar el protocolo y la configuración
    echo "Seleccione el protocolo y la configuración:"
    echo "1. VMess"
    echo "2. VMess + WebSocket"
    echo "3. VMess + WebSocket + TLS"
    echo "4. VLESS"
    echo "5. VLESS + WebSocket"
    echo "6. VLESS + WebSocket + TLS"
    echo "7. Trojan"
    echo "8. Trojan + WebSocket"
    echo "9. Trojan + WebSocket + TLS"
    while true; do
        read -p "Elija una opción (1-9): " protocol_choice
        if [[ "$protocol_choice" =~ ^[1-9]$ ]]; then
            break
        else
            echo -e "${RED}Por favor, elija una opción válida (1-9).${NC}"
        fi
    done

    # Obtener el puerto actual de V2Ray
    current_port=$(jq '.inbounds[0].port' /usr/local/etc/v2ray/config.json)
    read -p "Ingrese el puerto para V2Ray (presione Enter para usar $current_port): " port
    port=${port:-$current_port}

    # Solicitar al usuario la dirección IP
    echo "¿Qué dirección IP desea usar?"
    echo "1. IP privada (local)"
    echo "2. IP pública"
    while true; do
        read -p "Elija una opción (1-2): " ip_choice
        case $ip_choice in
            1)
                ip_address=$(ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)
                break
                ;;
            2)
                ip_address=$(curl -s ifconfig.me)
                break
                ;;
            *)
                echo -e "${RED}Opción inválida. Por favor, elija 1 o 2.${NC}"
                ;;
        esac
    done

    # Configurar según la elección de protocolo
    case $protocol_choice in
        1)
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}]}"
            stream_settings="{}"
            ;;
        2)
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}]}"
            stream_settings="{\"network\": \"ws\", \"wsSettings\": {\"path\": \"/ws-$account_name\"}}"
            ;;
        3)
            protocol="vmess"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}]}"
            stream_settings="{\"network\": \"ws\", \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"/etc/v2ray/certs/v2ray.crt\", \"keyFile\": \"/etc/v2ray/certs/v2ray.key\"}]}, \"wsSettings\": {\"path\": \"/ws-$account_name\"}}"
            ;;
        4)
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            stream_settings="{}"
            ;;
        5)
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            stream_settings="{\"network\": \"ws\", \"wsSettings\": {\"path\": \"/ws-$account_name\"}}"
            ;;
        6)
            protocol="vless"
            settings="{\"clients\": [{\"id\": \"$uuid\", \"email\": \"$account_name\"}], \"decryption\": \"none\"}"
            stream_settings="{\"network\": \"ws\", \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"/etc/v2ray/certs/v2ray.crt\", \"keyFile\": \"/etc/v2ray/certs/v2ray.key\"}]}, \"wsSettings\": {\"path\": \"/ws-$account_name\"}}"
            ;;
        7)
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            stream_settings="{}"
            ;;
        8)
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            stream_settings="{\"network\": \"ws\", \"wsSettings\": {\"path\": \"/trojan-$account_name\"}}"
            ;;
        9)
            protocol="trojan"
            settings="{\"clients\": [{\"password\": \"$uuid\", \"email\": \"$account_name\"}]}"
            stream_settings="{\"network\": \"ws\", \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"/etc/v2ray/certs/v2ray.crt\", \"keyFile\": \"/etc/v2ray/certs/v2ray.key\"}]}, \"wsSettings\": {\"path\": \"/trojan-$account_name\"}}"
            ;;
    esac

    # Cambiar los permisos de los archivos TLS si se usa TLS
    if [[ "$protocol_choice" =~ ^[369]$ ]]; then
        sudo chown nobody:nogroup /etc/v2ray/certs/v2ray.crt /etc/v2ray/certs/v2ray.key
        sudo chmod 600 /etc/v2ray/certs/v2ray.crt /etc/v2ray/certs/v2ray.key
    fi

    # Crear la nueva configuración de inbound
    new_inbound=$(jq -n \
                  --arg protocol "$protocol" \
                  --arg port "$port" \
                  --argjson settings "$settings" \
                  --argjson stream_settings "$stream_settings" \
                  '{protocol: $protocol, port: ($port|tonumber), settings: $settings, streamSettings: $stream_settings}')

    # Añadir el nuevo inbound a la configuración existente
    jq --argjson new_inbound "$new_inbound" '.inbounds += [$new_inbound]' /usr/local/etc/v2ray/config.json > /tmp/v2ray_config_temp.json
    mv /tmp/v2ray_config_temp.json /usr/local/etc/v2ray/config.json

    # Reiniciar V2Ray para aplicar los cambios
    if ! systemctl restart v2ray; then
        echo -e "${RED}Error al reiniciar V2Ray. Por favor, verifique los logs del sistema.${NC}"
        return 1
    fi

    echo -e "${GREEN}Cuenta creada con éxito:${NC}"
    echo "Nombre: $account_name"
    echo "UUID/Password: $uuid"
    echo "Protocolo: $protocol"
    echo "IP: $ip_address"
    echo "Puerto: $port"
    echo "Fecha de expiración: $expiry_date"
    if [ "$stream_settings" != "{}" ]; then
        echo "Path WebSocket: $(echo $stream_settings | jq -r '.wsSettings.path')"
        if [ "$(echo $stream_settings | jq -r '.security')" == "tls" ]; then
            echo "TLS activado"
        fi
    fi
}

# Función para listar todas las cuentas
list_accounts() {
    check_and_repair_config
    echo -e "${YELLOW}Listando todas las cuentas V2Ray...${NC}"

    # Obtener la IP local
    local_ip=$(ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)

    echo "IP local: $local_ip"
    echo ""
    echo "Cuentas:"

    accounts=$(jq -r '.inbounds[] | select(.settings.clients != null) | .settings.clients[] | "\(.email)|\(.id // .password)"' /usr/local/etc/v2ray/config.json)

    IFS=$'\n'
    index=1
    for account in $accounts; do
        IFS='|' read -r email uuid <<< "$account"
        echo "$index) $email"
        index=$((index+1))
    done

    echo ""
    read -p "Seleccione un número para ver detalles (o presione Enter para volver): " choice

    if [[ -n $choice && $choice =~ ^[0-9]+$ ]]; then
        selected_account=$(echo "$accounts" | sed -n "${choice}p")
        IFS='|' read -r email uuid <<< "$selected_account"

        inbound=$(jq -r --arg email "$email" '.inbounds[] | select(.settings.clients[].email == $email)' /usr/local/etc/v2ray/config.json)

        echo ""
        echo "Detalles de la cuenta $email:"
        echo "UUID/Password: $uuid"
        echo "Protocolo: $(echo $inbound | jq -r '.protocol')"
        echo "Puerto: $(echo $inbound | jq -r '.port')"
        if [[ $(echo $inbound | jq -r '.streamSettings.network') == "ws" ]]; then
            echo "WebSocket Path: $(echo $inbound | jq -r '.streamSettings.wsSettings.path')"
        fi
    fi
}

# Función para eliminar una cuenta
delete_account() {
    check_and_repair_config
    echo -e "${YELLOW}Eliminando una cuenta V2Ray...${NC}"
    list_accounts
    read -p "Ingrese el email de la cuenta que desea eliminar: " account_email

    # Verificar si el archivo de configuración existe
    if [ ! -f /usr/local/etc/v2ray/config.json ]; then
        echo -e "${RED}El archivo de configuración de V2Ray no existe. ¿Está V2Ray instalado correctamente?${NC}"
        return
    fi

    jq --arg email "$account_email" 'del(.inbounds[0].settings.clients[] | select(.email == $email))' /usr/local/etc/v2ray/config.json > /tmp/v2ray_config_temp.json
    mv /tmp/v2ray_config_temp.json /usr/local/etc/v2ray/config.json

    systemctl restart v2ray
    echo -e "${GREEN}Cuenta eliminada y V2Ray reiniciado.${NC}"
}

# Verificar si el script se está ejecutando como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Este script debe ejecutarse como root${NC}"
    exit 1
fi

# Verificar si jq está instalado
if ! command -v jq &> /dev/null; then
    echo "El paquete 'jq' no está instalado. Instalándolo ahora..."
    if [ -f /etc/debian_version ]; then
        apt-get update
        apt-get install -y jq
    else
        echo -e "${RED}No se pudo instalar 'jq'. Por favor, instálelo manualmente.${NC}"
        exit 1
    fi
fi

# Menú principal
while true; do
    echo -e "${GREEN}==== Menú de Gestión de V2Ray ====${NC}"
    echo "1. Instalar V2Ray"
    echo "2. Crear nueva cuenta"
    echo "3. Listar cuentas"
    echo "4. Eliminar cuenta"
    echo "5. Verificar y reparar configuración"
    echo "6. Salir"
    read -p "Seleccione una opción: " choice

    case $choice in
        1) install_v2ray ;;
        2) create_account ;;
        3) list_accounts ;;
        4) delete_account ;;
        5) check_and_repair_config ;;
        6) echo "Saliendo..."; exit 0 ;;
        *) echo -e "${RED}Opción inválida. Por favor, intente de nuevo.${NC}" ;;
    esac
done
