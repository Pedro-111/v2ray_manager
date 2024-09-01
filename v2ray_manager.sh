#!/bin/bash

# Colores para mejor legibilidad
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Función para instalar V2Ray
install_v2ray() {
    echo -e "${YELLOW}Instalando V2Ray...${NC}"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    systemctl enable v2ray
    systemctl start v2ray
    echo -e "${GREEN}V2Ray instalado y activado.${NC}"
}

# Función para generar un UUID aleatorio
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# Función para crear una nueva cuenta
create_account() {
    echo -e "${YELLOW}Creando nueva cuenta V2Ray...${NC}"
    
    # Generar un nuevo UUID
    uuid=$(generate_uuid)
    
    # Solicitar al usuario el nombre de la cuenta
    read -p "Ingrese el nombre para la nueva cuenta: " account_name
    
    # Solicitar al usuario la duración en días
    read -p "Ingrese la duración de la cuenta en días: " duration
    
    # Calcular la fecha de expiración
    expiry_date=$(date -d "+$duration days" +"%Y-%m-%d")
    
    # Seleccionar el protocolo
    echo "Seleccione el protocolo:"
    echo "1. VMess"
    echo "2. VLESS"
    read -p "Elija una opción (1-2): " protocol_choice
    
    case $protocol_choice in
        1) protocol="vmess" ;;
        2) protocol="vless" ;;
        *) echo "Opción inválida. Usando VMess por defecto."; protocol="vmess" ;;
    esac
    
    # Agregar la nueva configuración al archivo config.json de V2Ray
    if [ "$protocol" = "vmess" ]; then
        jq --arg uuid "$uuid" --arg name "$account_name" '.inbounds[0].settings.clients += [{"id": $uuid, "email": $name}]' /usr/local/etc/v2ray/config.json > /tmp/v2ray_config_temp.json
    else
        jq --arg uuid "$uuid" --arg name "$account_name" '.inbounds[0].settings.clients += [{"id": $uuid, "email": $name, "flow": "xtls-rprx-direct"}]' /usr/local/etc/v2ray/config.json > /tmp/v2ray_config_temp.json
    fi
    mv /tmp/v2ray_config_temp.json /usr/local/etc/v2ray/config.json
    
    # Reiniciar V2Ray para aplicar los cambios
    systemctl restart v2ray
    
    echo -e "${GREEN}Cuenta creada con éxito:${NC}"
    echo "Nombre: $account_name"
    echo "UUID: $uuid"
    echo "Protocolo: $protocol"
    echo "Fecha de expiración: $expiry_date"
}

# Función para listar todas las cuentas
list_accounts() {
    echo -e "${YELLOW}Listando todas las cuentas V2Ray...${NC}"
    jq '.inbounds[0].settings.clients[] | {email: .email, id: .id}' /usr/local/etc/v2ray/config.json
}

# Función para eliminar una cuenta
delete_account() {
    echo -e "${YELLOW}Eliminando una cuenta V2Ray...${NC}"
    list_accounts
    read -p "Ingrese el email de la cuenta que desea eliminar: " account_email
    
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
    echo "5. Salir"
    read -p "Seleccione una opción: " choice
    
    case $choice in
        1) install_v2ray ;;
        2) create_account ;;
        3) list_accounts ;;
        4) delete_account ;;
        5) echo "Saliendo..."; exit 0 ;;
        *) echo -e "${RED}Opción inválida. Por favor, intente de nuevo.${NC}" ;;
    esac
done
