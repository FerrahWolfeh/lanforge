use thiserror::Error;

/// Erros específicos do servidor DNS do Lanforge.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("falha de I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("falha no protocolo DNS: {0}")]
    Protocol(#[from] hickory_proto::ProtoError),

    #[error("resposta UDP corrompida: {0}")]
    UdpDecode(String),

    #[error("falha ao codificar resposta UDP: {0}")]
    UdpEncode(String),

    #[error("resposta TCP corrompida: {0}")]
    TcpDecode(String),

    #[error("falha ao codificar resposta TCP: {0}")]
    TcpEncode(String),

    #[error("timeout esperando resposta do upstream")]
    UpstreamTimeout,

    #[error("canal de resposta fechado prematuramente")]
    ChannelClosed,

    #[error("falha ao vincular socket {0}: {1}")]
    BindError(&'static str, #[source] std::io::Error),

    #[error("falha no parser wire (zero-alloc)")]
    WireParseError,
}
