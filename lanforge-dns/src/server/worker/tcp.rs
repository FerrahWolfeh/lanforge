use crate::server::DnsContext;
use crate::wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, trace};

pub fn spawn_tcp_worker(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = ctx.cfg.listen;
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind TCP listener on {}: {}", addr, e);
                return;
            }
        };

        loop {
            match listener.accept().await {
                Ok((mut stream, src)) => {
                    let task_ctx = Arc::clone(&ctx);
                    tokio::spawn(async move {
                        let mut len_buf = [0u8; 2];
                        while stream.read_exact(&mut len_buf).await.is_ok() {
                            let len = u16::from_be_bytes(len_buf) as usize;
                            if len > 4096 {
                                break;
                            }

                            let mut data = vec![0u8; len];
                            if stream.read_exact(&mut data).await.is_err() {
                                break;
                            }

                            let header = match WireHeader::parse(&data) {
                                Some(h) => h,
                                None => break,
                            };
                            let question = match WireQuestion::parse(&data) {
                                Some(q) => q,
                                None => break,
                            };

                            // Noise filtering (e.g. malformed IoT queries like empty qname or ":0")
                            let mut labels = question.labels();
                            let is_noise = match labels.next() {
                                None => true,                                             // Empty qname (.)
                                Some(l) if l == b":0" && labels.next().is_none() => true, // Literally ":0"
                                _ => false,
                            };

                            if is_noise {
                                let mut resp_buf = Vec::with_capacity(64);
                                WireResponseWriter::write_error_response(
                                    &data,
                                    &question,
                                    1, // FORMERR
                                    WireOptScanner::scan(&data, &header, &question),
                                    false,
                                    &mut resp_buf,
                                );

                                if !resp_buf.is_empty() {
                                    let resp_len = u16::try_from(resp_buf.len())
                                        .unwrap_or(u16::MAX)
                                        .to_be_bytes();
                                    if stream.write_all(&resp_len).await.is_err() {
                                        break;
                                    }
                                    if stream.write_all(&resp_buf).await.is_err() {
                                        break;
                                    }
                                }
                                continue;
                            }

                            let mut resp_buf = Vec::with_capacity(len + 128);
                            if let Err(e) = task_ctx
                                .pipeline
                                .run(
                                    &task_ctx,
                                    &data,
                                    &header,
                                    &question,
                                    src.ip(),
                                    &mut resp_buf,
                                )
                                .await
                            {
                                trace!("TCP query handling failed: {:?}", e);
                                break;
                            }

                            if !resp_buf.is_empty() {
                                let resp_len = u16::try_from(resp_buf.len())
                                    .unwrap_or(u16::MAX)
                                    .to_be_bytes();
                                if stream.write_all(&resp_len).await.is_err() {
                                    break;
                                }
                                if stream.write_all(&resp_buf).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("TCP worker accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    })
}
