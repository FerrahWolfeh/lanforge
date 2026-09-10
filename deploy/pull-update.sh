#!/usr/bin/env bash
set -euo pipefail

# Script de Atualização por PULL no Gateway
# Executa dentro do Gateway para puxar os binários compilados da estação de compilação
# Uso:
#   sudo ./deploy/pull-update.sh <usuario@host>
#   sudo lanforge-update [usuario@host]

echo "======================================================"
echo "    Lanforge Updater (Pull Mode -> Edge Gateway)      "
echo "======================================================"

if [[ $EUID -ne 0 ]]; then
    echo "Erro: Este script precisa ser executado com privilégios de root (use sudo)." >&2
    exit 1
fi

# Carregar variáveis de ambiente do Lanforge caso existam
if [ -f /etc/lanforge/lanforge.env ]; then
    # shellcheck disable=SC1091
    source /etc/lanforge/lanforge.env
fi

BUILD_HOST="${BUILD_HOST:-${1:-}}"
BUILD_DIR="${BUILD_DIR:-/mnt/ram/.rsbuild/release}"

if [ -z "$BUILD_HOST" ]; then
    echo "Erro: Host de compilação não configurado!" >&2
    echo "Defina BUILD_HOST no /etc/lanforge/lanforge.env ou passe como argumento:" >&2
    echo "  sudo $0 <usuario@host-compilador>" >&2
    exit 1
fi

echo "--> Host de compilação: $BUILD_HOST"
echo "--> Diretório remoto:   $BUILD_DIR"
echo ""

TMP_DAEMON="/tmp/lanforged.new.$$"
TMP_CLI="/tmp/lanforge.new.$$"

cleanup() {
    rm -f "$TMP_DAEMON" "$TMP_CLI"
}
trap cleanup EXIT

# 1. Puxar binários via SCP para /tmp (garante que não interrompe o serviço se a rede/scp falhar)
echo "--> [1/5] Baixando binário lanforged (daemon)..."
if ! scp "$BUILD_HOST:$BUILD_DIR/lanforged" "$TMP_DAEMON" 2>/dev/null; then
    # Tentativa alternativa caso o caminho de saída seja target/release
    ALT_DIR="${BUILD_DIR%/release}/target/release"
    echo "    Tentando caminho alternativo: $ALT_DIR/lanforged ..."
    scp "$BUILD_HOST:$ALT_DIR/lanforged" "$TMP_DAEMON"
fi

echo "--> [2/5] Baixando binário lanforge (CLI)..."
if ! scp "$BUILD_HOST:$BUILD_DIR/lanforge" "$TMP_CLI" 2>/dev/null; then
    ALT_DIR="${BUILD_DIR%/release}/target/release"
    echo "    Tentando caminho alternativo: $ALT_DIR/lanforge ..."
    scp "$BUILD_HOST:$ALT_DIR/lanforge" "$TMP_CLI"
fi

# 2. Validar que os arquivos foram baixados
if [ ! -s "$TMP_DAEMON" ] || [ ! -s "$TMP_CLI" ]; then
    echo "Erro: Um ou mais binários baixados estão vazios ou corrompidos!" >&2
    exit 1
fi

# 3. Instalação atômica em /usr/local/bin
echo "--> [3/5] Instalando novos binários em /usr/local/bin/..."
install -m 0755 "$TMP_DAEMON" /usr/local/bin/lanforged
install -m 0755 "$TMP_CLI" /usr/local/bin/lanforge

# 4. Restaurar contextos SELinux para evitar AVC denied
echo "--> [4/5] Aplicando contextos SELinux (restorecon)..."
restorecon -v /usr/local/bin/lanforged /usr/local/bin/lanforge 2>/dev/null || true

# 5. Reiniciar o serviço no systemd
echo "--> [5/5] Reiniciando serviço lanforge..."
systemctl restart lanforge

echo ""
echo "======================================================"
echo "    Atualização concluída com sucesso!"
echo "======================================================"
echo ""
systemctl status lanforge --no-pager
