#!/usr/bin/env bash
set -euo pipefail

# Script de configuração do SELinux para o Lanforge no Fedora Server / RHEL
# Execute como root ou com sudo

echo "=== Configuração do SELinux para Lanforge ==="

if [[ $EUID -ne 0 ]]; then
    echo "Erro: Este script deve ser executado como root (use sudo)." >&2
    exit 1
fi

if ! command -v getenforce >/dev/null 2>&1; then
    echo "SELinux não detectado neste sistema. Nada a fazer."
    exit 0
fi

SELINUX_STATUS=$(getenforce)
echo "Status atual do SELinux: $SELINUX_STATUS"

if [[ "$SELINUX_STATUS" == "Disabled" ]]; then
    echo "SELinux está desativado. Nenhuma ação necessária."
    exit 0
fi

# 1. Configurar portas de rede (Porta 8096 para WebUI / HTTP API como http_port_t)
echo "--> Configurando porta 8096 (WebUI / HTTP API) no SELinux..."
if command -v semanage >/dev/null 2>&1; then
    if ! semanage port -l | grep -q "http_port_t.*\<8096\>"; then
        semanage port -a -t http_port_t -p tcp 8096 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp 8096 2>/dev/null || true
        echo "    Porta 8096 associada a http_port_t."
    else
        echo "    Porta 8096 já associada a http_port_t."
    fi

    # Booleans úteis caso proxies reversos locais (SWAG, Nginx, Caddy) façam proxy para o Lanforge
    echo "--> Verificando booleans de rede para proxies..."
    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    setsebool -P nis_enabled 1 2>/dev/null || true

    # 2. Registrar contextos padrão FHS no policy store
    echo "--> Registrando contextos de arquivos padrão..."
    semanage fcontext -a -t bin_t "/usr/local/bin/lanforge.*" 2>/dev/null || true
    semanage fcontext -a -t etc_t "/etc/lanforge(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t var_lib_t "/var/lib/lanforge(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t var_run_t "/run/lanforge(/.*)?" 2>/dev/null || true
else
    echo "Aviso: 'semanage' não encontrado. Instale com: dnf install policycoreutils-python-utils"
fi

# 3. Aplicar contextos aos arquivos existentes (evita AVC denied entrypoint ao puxar de /tmp)
echo "--> Restaurando contextos de segurança (restorecon)..."
restorecon -v /usr/local/bin/lanforged /usr/local/bin/lanforge /usr/local/bin/lanforge-lab 2>/dev/null || true
restorecon -Rv /etc/lanforge /var/lib/lanforge 2>/dev/null || true
restorecon -Rv /run/lanforge 2>/dev/null || true

echo "=== SELinux configurado com sucesso para o Lanforge! ==="
