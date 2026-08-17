use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::DnsError;

pub struct TlsAcceptor {
    pub config: Arc<ServerConfig>,
}

pub fn load_tls_config(cert_input: &str, key_input: &str) -> Result<ServerConfig, DnsError> {
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certs = load_certs(cert_input)?;
    let key = load_private_key(key_input)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| DnsError::Tls(format!("Failed to create TLS config: {e}")))?;

    Ok(config)
}

fn load_certs(input: &str) -> Result<Vec<CertificateDer<'static>>, DnsError> {
    if is_pem_format(input) {
        let mut cursor = Cursor::new(input.as_bytes());
        CertificateDer::pem_reader_iter(&mut cursor)
            .map(|res| res.map(CertificateDer::into_owned))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DnsError::Tls(format!("Failed to parse raw PEM certificate: {e}")))
    } else {
        let path = Path::new(input);
        Ok(CertificateDer::pem_file_iter(path)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DnsError::Tls(format!("Failed to read certificate file {input}: {e}")))?)
    }
}

fn load_private_key(input: &str) -> Result<PrivateKeyDer<'static>, DnsError> {
    if is_pem_format(input) {
        let mut cursor = Cursor::new(input.as_bytes());
        PrivateKeyDer::pem_reader_iter(&mut cursor)
            .next()
            .ok_or_else(|| DnsError::Tls("No private key found in PEM".to_string()))?
            .map(|k| k.clone_key())
            .map_err(|e| DnsError::Tls(format!("Failed to parse raw PEM private key: {e}")))
    } else {
        let path = Path::new(input);
        Ok(PrivateKeyDer::pem_file_iter(path)?
            .next()
            .ok_or_else(|| DnsError::Tls(format!("No private key found in {input}")))?
            .map(|k| k.clone_key())
            .map_err(|e| DnsError::Tls(format!("Failed to read private key file {input}: {e}")))?)
    }
}

fn is_pem_format(input: &str) -> bool {
    input.trim_start().starts_with("-----BEGIN")
}
