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
# Función para instalar V2Ray
install_v2ray() {
    echo -e "${YELLOW}Instalando V2Ray...${NC}"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    systemctl enable v2ray
    systemctl start v2ray
    echo -e "${GREEN}V2Ray instalado y activado.${NC}"
    check_and_repair_config
}

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
    echo -e "${YELLOW}Verificando la configuración de V2Ray...${NC}"
    if [ ! -f /usr/local/etc/v2ray/config.json ] || [ ! -s /usr/local/etc/v2ray/config.json ]; then
        echo -e "${RED}El archivo de configuración está vacío o no existe. Creando una configuración básica...${NC}"
        sudo tee /usr/local/etc/v2ray/config.json > /dev/null << EOL
{
  "inbounds": [{
    "port": 10086,
    "protocol": "vmess",
    "settings": {
      "clients": []
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOL
        echo -e "${GREEN}Configuración básica creada.${NC}"
    else
        # Verificar si la estructura de la configuración es correcta
        if ! jq -e '.inbounds[0].settings.clients' /usr/local/etc/v2ray/config.json > /dev/null 2>&1; then
            echo -e "${RED}La estructura de la configuración no es correcta. Corrigiendo...${NC}"
            jq '.inbounds[0].settings.clients = []' /usr/local/etc/v2ray/config.json > /tmp/v2ray_config_temp.json
            mv /tmp/v2ray_config_temp.json /usr/local/etc/v2ray/config.json
        fi

        # Corregir la configuración de VLESS si es necesario
        if jq -e '.inbounds[0].protocol == "vless"' /usr/local/etc/v2ray/config.json > /dev/null; then
            echo -e "${YELLOW}Detectada configuración VLESS. Asegurando que 'decryption' esté configurado correctamente...${NC}"
            jq '.inbounds[0].settings.decryption = "none"' /usr/local/etc/v2ray/config.json > /tmp/v2ray_config_temp.json
            mv /tmp/v2ray_config_temp.json /usr/local/etc/v2ray/config.json
        fi
    fi

    if v2ray test -config /usr/local/etc/v2ray/config.json; then
        echo -e "${GREEN}La configuración de V2Ray es válida.${NC}"
    else
        echo -e "${RED}La configuración de V2Ray no es válida. Se ha creado una configuración básica.${NC}"
    fi

    systemctl restart v2ray
    echo -e "${GREEN}V2Ray ha sido reiniciado con la nueva configuración.${NC}"
}
# Función para crear una nueva cuenta
create_account() {
    check_and_repair_config
    echo -e "${YELLOW}Creando nueva cuenta V2Ray...${NC}"
    
    # Generar un nuevo UUID
    uuid=$(generate_uuid)
    
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
    echo "3. VLESS"
    echo "4. VLESS + WebSocket"
    echo "5. Trojan + WebSocket"
    while true; do
        read -p "Elija una opción (1-5): " protocol_choice
        if [[ "$protocol_choice" =~ ^[1-5]$ ]]; then
            break
        else
            echo -e "${RED}Por favor, elija una opción válida (1-5).${NC}"
        fi
    done
    
    # Solicitar al usuario el puerto y verificar que esté disponible
    while true; do
        read -p "Ingrese el puerto para V2Ray (por defecto 10086): " port
        port=${port:-10086}
        if ! netstat -tuln | grep -q ":$port "; then
            break
        else
            echo -e "${RED}El puerto $port ya está en uso. Por favor, elija otro.${NC}"
        fi
    done

    # Preguntar al usuario si desea usar IP pública o privada
    echo "¿Qué dirección IP desea usar?"
    echo "1. IP privada (local)"
    echo "2. IP pública"
    while true; do
        read -p "Elija una opción (1-2): " ip_choice
        case $ip_choice in
            1) 
                ip_address=$(get_local_ip)
                break
                ;;
            2) 
                ip_address=$(get_public_ip)
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
            ws_settings='{}'
            ;;
        2) 
            protocol="vmess"
            ws_settings='{"network": "ws", "wsSettings": {"path": "/ws"}}'
            ;;
        3) 
            protocol="vless"
            ws_settings='{}'
            ;;
        4) 
            protocol="vless"
            ws_settings='{"network": "ws", "wsSettings": {"path": "/ws"}}'
            ;;
        5)
            protocol="trojan"
            ws_settings='{"network": "ws", "wsSettings": {"path": "/trojan"}}'
            ;;
    esac
    
    # Crear la nueva configuración de cliente
    if [ "$protocol" = "vless" ]; then
        new_client="{\"id\": \"$uuid\", \"email\": \"$account_name\", \"flow\": \"\"}"
    elif [ "$protocol" = "trojan" ]; then
        new_client="{\"password\": \"$uuid\", \"email\": \"$account_name\"}"
    else
        new_client="{\"id\": \"$uuid\", \"email\": \"$account_name\"}"
    fi

    # Leer la configuración actual
    if [ ! -f /usr/local/etc/v2ray/config.json ]; then
        echo -e "${RED}El archivo de configuración no existe. Ejecutando check_and_repair_config...${NC}"
        check_and_repair_config
    fi
    config=$(cat /usr/local/etc/v2ray/config.json)

    # Añadir el nuevo cliente a la configuración existente
    updated_config=$(echo $config | jq --argjson new_client "$new_client" '.inbounds[0].settings.clients += [$new_client]')
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error al actualizar la configuración. Abortando...${NC}"
        return 1
    fi

    # Actualizar el puerto, el protocolo y las configuraciones específicas
    updated_config=$(echo $updated_config | jq --arg port "$port" --arg protocol "$protocol" '.inbounds[0].port = ($port | tonumber) | .inbounds[0].protocol = $protocol')
    if [ "$protocol" = "vless" ]; then
        updated_config=$(echo $updated_config | jq '.inbounds[0].settings.decryption = "none"')
    fi
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error al actualizar el puerto y el protocolo. Abortando...${NC}"
        return 1
    fi

    # Actualizar la configuración de WebSocket si es necesario
    if [ "$ws_settings" != "{}" ]; then
        updated_config=$(echo $updated_config | jq --argjson ws "$ws_settings" '.inbounds[0].streamSettings = $ws')
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error al actualizar la configuración de WebSocket. Abortando...${NC}"
            return 1
        fi
    fi

    # Guardar la configuración actualizada
    echo $updated_config > /usr/local/etc/v2ray/config.json
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error al guardar la configuración. Abortando...${NC}"
        return 1
    fi
    
    # Reiniciar V2Ray para aplicar los cambios
    if ! systemctl restart v2ray; then
        echo -e "${RED}Error al reiniciar V2Ray. Por favor, verifique los logs del sistema.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Cuenta creada con éxito:${NC}"
    echo "Nombre: $account_name"
    echo "UUID/Password: $uuid"
    echo "Protocolo: $protocol${ws_settings:+ con WebSocket}"
    echo "IP: $ip_address"
    echo "Puerto: $port"
    echo "Fecha de expiración: $expiry_date"
    if [ "$ws_settings" != "{}" ]; then
        if [ "$protocol" = "trojan" ]; then
            echo "Path WebSocket: /trojan"
        else
            echo "Path WebSocket: /ws"
        fi
    fi
}

# Función para listar todas las cuentas
list_accounts() {
    check_and_repair_config
    echo -e "${YELLOW}Listando todas las cuentas V2Ray...${NC}"
    
    # Obtener la IP local
    local_ip=$(get_local_ip)
    
    # Verificar si el archivo de configuración existe
    if [ ! -f /usr/local/etc/v2ray/config.json ]; then
        echo -e "${RED}El archivo de configuración de V2Ray no existe. ¿Está V2Ray instalado correctamente?${NC}"
        return
    fi

    # Obtener el puerto y protocolo actuales
    current_port=$(jq '.inbounds[0].port' /usr/local/etc/v2ray/config.json)
    current_protocol=$(jq -r '.inbounds[0].protocol' /usr/local/etc/v2ray/config.json)
    
    # Verificar si se está usando WebSocket
    using_ws=$(jq -r '.inbounds[0].streamSettings.network // empty' /usr/local/etc/v2ray/config.json)
    
    echo "Configuración actual:"
    echo "IP local: $local_ip"
    echo "Puerto: $current_port"
    echo "Protocolo: $current_protocol${using_ws:+ con WebSocket}"
    if [[ $using_ws ]]; then
        ws_path=$(jq -r '.inbounds[0].streamSettings.wsSettings.path // "/ws"' /usr/local/etc/v2ray/config.json)
        echo "Path WebSocket: $ws_path"
    fi
    echo ""
    echo "Cuentas:"
    jq -r '.inbounds[0].settings.clients[] | "Email: \(.email)\nUUID: \(.id)\n"' /usr/local/etc/v2ray/config.json
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
    echo "6. Salir "
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
