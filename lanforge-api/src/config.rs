/// Configuração do serviço de controle UDS.
///
/// Definida no crate da API para permitir seu uso em isolamento, sem depender
/// das estruturas de configuração internas do daemon principal.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Caminho para o socket Unix (ex: "/run/lanforge/control.sock").
    pub socket_path: String,

    /// Nome da interface LAN reportada no status (ex: "eth0").
    pub lan_iface: String,

    /// Indica se o serviço de RA está habilitado.
    pub ra_enabled: bool,

    /// Prefixo ULA anunciado (ex: "fd00::/64"), se houver.
    pub ula_prefix: Option<String>,

    /// Indica se o DHCPv4 está habilitado.
    pub dhcp_v4_enabled: bool,

    /// Indica se o DHCPv6 está habilitado.
    pub dhcp_v6_enabled: bool,

    /// Indica se o DNS está habilitado.
    pub dns_enabled: bool,

    /// Resolver upstream configurado no DNS.
    pub dns_upstream: Option<String>,

    /// Caminho do banco de dados (usado para calcular estatísticas de tamanho).
    pub db_path: String,
}

#[cfg(test)]
impl ApiConfig {
    /// Cria uma configuração dummy para testes.
    pub fn dummy() -> Self {
        Self {
            socket_path: "/tmp/lanforge.sock".to_string(),
            lan_iface: "eth0".to_string(),
            ra_enabled: true,
            ula_prefix: None,
            dhcp_v4_enabled: true,
            dhcp_v6_enabled: true,
            dns_enabled: true,
            dns_upstream: None,
            db_path: "/tmp/leases.db".to_string(),
        }
    }
}
