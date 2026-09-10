#!/usr/bin/env bash
set -euo pipefail

# Script de Instalação e Inicialização do Lanforge no Fedora Server / Linux
# Execute como root ou com sudo: sudo ./deploy/install.sh

echo "======================================================"
echo "    Instalador do Lanforge (Router & Core Daemon)    "
echo "======================================================"

if [[ $EUID -ne 0 ]]; then
    echo "Erro: Este instalador precisa ser executado como root (use sudo)." >&2
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$PROJECT_ROOT/deploy"

# 1. Configurar grupo dedicado 'lanforge' para acesso local ao socket UDS
echo "--> [1/7] Configurando grupo de sistema 'lanforge'..."
if ! getent group lanforge >/dev/null; then
    groupadd -r lanforge
    echo "    Grupo 'lanforge' criado."
else
    echo "    Grupo 'lanforge' já existe."
fi

# Adicionar o usuário que invocou o sudo ao grupo lanforge (permite usar a CLI sem sudo)
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    usermod -aG lanforge "$SUDO_USER"
    echo "    Usuário '$SUDO_USER' adicionado ao grupo 'lanforge' (acesso à CLI sem sudo)."
fi

# 2. Criar hierarquia de diretórios FHS
echo "--> [2/7] Criando diretórios FHS (/etc/lanforge e /var/lib/lanforge)..."
mkdir -p /etc/lanforge
mkdir -p /var/lib/lanforge/tftp

chown -R root:lanforge /etc/lanforge
chmod 0755 /etc/lanforge

chown -R root:lanforge /var/lib/lanforge
chmod 0750 /var/lib/lanforge
chmod 0755 /var/lib/lanforge/tftp

# 3. Instalar binários compilados se disponíveis
echo "--> [3/7] Verificando binários compilados..."
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
if [ -d "/mnt/ram/.rsbuild" ]; then
    TARGET_DIR="/mnt/ram/.rsbuild"
fi
BIN_DIR="$TARGET_DIR/release"
if [ ! -d "$BIN_DIR" ] && [ -d "$TARGET_DIR/target/release" ]; then
    BIN_DIR="$TARGET_DIR/target/release"
fi

for bin in lanforged lanforge lanforge-lab; do
    if [ -f "$BIN_DIR/$bin" ]; then
        echo "    Instalando $bin em /usr/local/bin/..."
        install -m 0755 "$BIN_DIR/$bin" "/usr/local/bin/$bin"
    elif [ -f "/usr/local/bin/$bin" ]; then
        echo "    Binário /usr/local/bin/$bin mantido existente."
    else
        echo "    Aviso: Binário $bin não encontrado em $BIN_DIR."
    fi
done

# Instalar o utilitário de atualização rápida 'lanforge-update'
if [ -f "$DEPLOY_DIR/pull-update.sh" ]; then
    echo "    Instalando atalho de atualização em /usr/local/bin/lanforge-update..."
    install -m 0755 "$DEPLOY_DIR/pull-update.sh" /usr/local/bin/lanforge-update
fi

# 4. Copiar arquivos de configuração padrão se não existirem
echo "--> [4/7] Configurações em /etc/lanforge/..."
if [ ! -f /etc/lanforge/lanforge.toml ]; then
    echo "    Instalando /etc/lanforge/lanforge.toml padrão..."
    cp "$DEPLOY_DIR/config/lanforge.toml" /etc/lanforge/lanforge.toml
    chown root:lanforge /etc/lanforge/lanforge.toml
    chmod 0640 /etc/lanforge/lanforge.toml
else
    echo "    /etc/lanforge/lanforge.toml existente mantido intacto."
fi

if [ ! -f /etc/lanforge/lanforge.env ]; then
    echo "    Instalando /etc/lanforge/lanforge.env padrão..."
    cp "$DEPLOY_DIR/config/lanforge.env" /etc/lanforge/lanforge.env
    chown root:lanforge /etc/lanforge/lanforge.env
    chmod 0640 /etc/lanforge/lanforge.env
else
    echo "    /etc/lanforge/lanforge.env existente mantido intacto."
fi

# 5. Instalar Unit do Systemd e Sysusers
echo "--> [5/7] Instalando unit do systemd..."
cp "$DEPLOY_DIR/systemd/lanforge.service" /etc/systemd/system/lanforge.service
chmod 0644 /etc/systemd/system/lanforge.service

if [ -d /etc/sysusers.d ]; then
    cp "$DEPLOY_DIR/systemd/lanforge.sysusers" /etc/sysusers.d/lanforge.conf
    chmod 0644 /etc/sysusers.d/lanforge.conf
fi

systemctl daemon-reload
echo "    Systemd recarregado com sucesso."

# 6. Configurar SELinux (se ativo)
echo "--> [6/7] Verificando SELinux..."
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    bash "$DEPLOY_DIR/selinux/install-selinux.sh"
else
    echo "    SELinux não está ativo ou não foi detectado."
fi

echo ""
echo "======================================================"
echo "    Instalação do Lanforge finalizada com sucesso!"
echo "======================================================"
echo ""
echo "Próximos passos recomendados:"
echo " 1. Revise e configure sua interface de rede em: /etc/lanforge/lanforge.toml"
echo " 2. Ative e inicie o serviço:"
echo "      sudo systemctl enable --now lanforge"
echo " 3. Acompanhe os logs com:"
echo "      journalctl -u lanforge -f"
echo " 4. Verifique o status detalhado e watchdog:"
echo "      systemctl status lanforge"
echo " 5. Para futuras atualizações diretas no mini PC, basta rodar:"
echo "      sudo lanforge-update"
echo ""
