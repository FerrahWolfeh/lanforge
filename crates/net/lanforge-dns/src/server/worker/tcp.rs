use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_types::network::dns::TransportProtocol;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tracing::{error, trace};

pub fn spawn_tcp_worker(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addrs = ctx.cfg.listen.addrs();
        let mut handles = Vec::new();

        for addr in addrs {
            let listener = match crate::server::transport::net::bind_tcp(addr) {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind TCP listener on {}: {}", addr, e);
                    continue;
                }
            };
            tracing::info!(%addr, "DNS: TCP listening");

            let task_ctx = Arc::clone(&ctx);
            handles.push(tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((mut stream, src)) => {
                            let task_ctx = Arc::clone(&task_ctx);
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

                            let edns = WireOptScanner::scan(&data, &header, &question);

                            if is_noise {
                                let mut resp_buf = Vec::with_capacity(64);
                                WireResponseWriter::write_error_response(
                                    &data,
                                    &question,
                                    1, // FORMERR
                                    edns,
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
                            let filter_match = parking_lot::Mutex::new(None);
                            let run_res = task_ctx
                                .pipeline
                                .run(
                                    &task_ctx,
                                    DnsPipelineRequest::new(
                                        &data,
                                        &header,
                                        &question,
                                        src.ip(),
                                        TransportProtocol::Tcp,
                                        &filter_match,
                                    ),
                                    &mut resp_buf,
                                )
                                .await;

                            if let Err(e) = run_res {
                                trace!("Pipeline error (sending SERVFAIL): {:?}", e);
                                resp_buf.clear();
                                WireResponseWriter::write_error_response(
                                    &data,
                                    &question,
                                    2, // SERVFAIL
                                    edns,
                                    !task_ctx.recursive.is_empty(),
                                    &mut resp_buf,
                                );
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
                    error!("TCP worker accept error on {}: {}", addr, e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }));
}

for h in handles {
    let _ = h.await;
}
})
}
