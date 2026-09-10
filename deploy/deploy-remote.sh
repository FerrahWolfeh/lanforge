#!/usr/bin/env bash
set -euo pipefail

# Script de Deploy Automatizado (Push) da Estação de Desenvolvimento para o Gateway Edge
# Uso:
#   TARGET=user@gateway ./deploy/deploy-remote.sh            # Compila e envia lanforged + lanforge (CLI)
#   TARGET=user@gateway ./deploy/deploy-remote.sh --daemon   # Compila e envia somente o daemon lanforged
#   TARGET=user@gateway ./deploy/deploy-remote.sh --cli      # Compila e envia somente a CLI lanforge
#   TARGET=user@gateway ./deploy/deploy-remote.sh --ui       # Reconstrói a WebUI antes de compilar o daemon
#   TARGET=user@gateway ./deploy/deploy-remote.sh --setup    # Executa o instalador completo inicial no gateway

TARGET="${TARGET:-${GATEWAY_HOST:-}}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -z "$TARGET" ]; then
    echo "Erro: Destino remoto não configurado!" >&2
    echo "Defina TARGET no ambiente ou execute passando o host:" >&2
    echo "  TARGET=usuario@gateway $0 [opções]" >&2
    exit 1
fi

# Localização dos binários compilados (detecta RAM disk se existir, ou target padrão)
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
if [ -d "/mnt/ram/.rsbuild" ]; then
    TARGET_DIR="/mnt/ram/.rsbuild"
fi

BIN_DIR="$TARGET_DIR/release"
if [ ! -d "$BIN_DIR" ] && [ -d "$TARGET_DIR/target/release" ]; then
    BIN_DIR="$TARGET_DIR/target/release"
fi

echo "======================================================"
echo "    Deploy Lanforge (Push) -> $TARGET"
echo "======================================================"

build_ui() {
    echo ""
    echo "==> [WebUI] Compilando frontend estático SvelteKit..."
    (cd "$PROJECT_ROOT/web" && pnpm build)
    echo "==> [WebUI] Frontend compilado e pronto para embutir no binário."
}

build_binaries() {
    local packages=("$@")
    echo ""
    echo "==> [Build] Compilando ${packages[*]} em modo release..."
    cd "$PROJECT_ROOT"
    local build_args=("--release" "--locked")
    for pkg in "${packages[@]}"; do
        build_args+=("-p" "$pkg")
    done
    cargo build "${build_args[@]}"
}

deploy_daemon() {
    local binary="$BIN_DIR/lanforged"
    if [ ! -f "$binary" ]; then
        echo "Erro: Binário não encontrado em $binary" >&2
        exit 1
    fi

    echo "==> [Daemon] Enviando lanforged para $TARGET:/tmp/..."
    scp "$binary" "$TARGET:/tmp/lanforged.new"

    echo "==> [Daemon] Instalando e reiniciando o serviço no gateway..."
    ssh -t "$TARGET" "
        sudo install -m 0755 /tmp/lanforged.new /usr/local/bin/lanforged && \
        rm -f /tmp/lanforged.new && \
        sudo restorecon -v /usr/local/bin/lanforged && \
        sudo systemctl restart lanforge && \
        systemctl status lanforge --no-pager
    "
    echo "==> [Daemon] Deploy concluído com sucesso!"
}

deploy_cli() {
    local binary="$BIN_DIR/lanforge"
    if [ ! -f "$binary" ]; then
        echo "Erro: Binário não encontrado em $binary" >&2
        exit 1
    fi

    echo "==> [CLI] Enviando lanforge (CLI) para $TARGET:/tmp/..."
    scp "$binary" "$TARGET:/tmp/lanforge.new"

    echo "==> [CLI] Instalando em /usr/local/bin/..."
    ssh -t "$TARGET" "
        sudo install -m 0755 /tmp/lanforge.new /usr/local/bin/lanforge && \
        rm -f /tmp/lanforge.new && \
        sudo restorecon -v /usr/local/bin/lanforge
    "
    echo "==> [CLI] Deploy da CLI concluído com sucesso!"
}

deploy_all() {
    build_binaries "lanforge" "lanforge-cli"

    local bin_daemon="$BIN_DIR/lanforged"
    local bin_cli="$BIN_DIR/lanforge"

    if [ ! -f "$bin_daemon" ] || [ ! -f "$bin_cli" ]; then
        echo "Erro: Binários não encontrados em $BIN_DIR" >&2
        exit 1
    fi

    echo "==> Enviando lanforged e lanforge (CLI) para $TARGET:/tmp/..."
    scp "$bin_daemon" "$TARGET:/tmp/lanforged.new"
    scp "$bin_cli" "$TARGET:/tmp/lanforge.new"

    echo "==> Instalando binários e reiniciando o serviço no gateway..."
    ssh -t "$TARGET" "
        sudo install -m 0755 /tmp/lanforged.new /usr/local/bin/lanforged && \
        sudo install -m 0755 /tmp/lanforge.new /usr/local/bin/lanforge && \
        rm -f /tmp/lanforged.new /tmp/lanforge.new && \
        sudo restorecon -v /usr/local/bin/lanforged /usr/local/bin/lanforge && \
        sudo systemctl restart lanforge && \
        systemctl status lanforge --no-pager
    "
    echo "==> [Full] Deploy completo concluído com sucesso!"
}

deploy_setup() {
    echo ""
    echo "==> [Setup Inicial] Empacotando diretório deploy/..."
    local tmp_tar="/tmp/lanforge-deploy-bundle-$$.tar.gz"
    tar -czf "$tmp_tar" -C "$PROJECT_ROOT" deploy

    echo "==> [Setup Inicial] Enviando para $TARGET:/tmp/..."
    scp "$tmp_tar" "$TARGET:/tmp/lanforge-deploy-bundle.tar.gz"
    rm -f "$tmp_tar"

    echo "==> [Setup Inicial] Executando install.sh no gateway..."
    ssh -t "$TARGET" "
        cd /tmp && \
        tar -xzf lanforge-deploy-bundle.tar.gz && \
        sudo ./deploy/install.sh && \
        rm -rf lanforge-deploy-bundle.tar.gz deploy
    "
    echo "==> [Setup Inicial] Instalação remota finalizada!"
}

ACTION="${1:---all}"

case "$ACTION" in
    --daemon|-d)
        build_binaries "lanforge"
        deploy_daemon
        ;;
    --cli|-c)
        build_binaries "lanforge-cli"
        deploy_cli
        ;;
    --ui|-u)
        build_ui
        build_binaries "lanforge" "lanforge-cli"
        deploy_all
        ;;
    --setup)
        deploy_setup
        ;;
    --all|-a)
        deploy_all
        ;;
    *)
        echo "Opção desconhecida: $ACTION"
        echo "Uso: $0 [--all | --daemon | --cli | --ui | --setup]"
        exit 1
        ;;
esac

echo ""
echo "======================================================"
echo "    Operação finalizada em $TARGET!"
echo "======================================================"
