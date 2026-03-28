use std::io;
use thiserror::Error;

/// Erros específicos do subsistema de rede do Lanforge.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("falha de I/O: {0}")]
    Io(#[from] io::Error),

    #[error("falha no netlink: {0}")]
    Netlink(#[from] rtnetlink::Error),

    #[error("configuração inválida: {0}")]
    Config(String),

    #[error("falha ao criar ou configurar socket: {0}")]
    Socket(String),

    #[error("erro no canal AF_PACKET: {0}")]
    RawSocket(String),

    #[error("erro de rede genérico: {0}")]
    Generic(String),

    #[error("interface '{0}' não encontrada ou inválida")]
    InterfaceNotFound(String),

    #[error("endereco MAC inválido ou ausente: {0}")]
    InvalidMac(String),

    #[error("sem endereço link-local na interface {0}")]
    NoLinkLocal(u32),
}

pub type Result<T> = std::result::Result<T, NetworkError>;
