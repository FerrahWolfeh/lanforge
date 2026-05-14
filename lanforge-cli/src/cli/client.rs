use color_eyre::eyre::{Context, Result, eyre};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::cli::commands::CliCommand;
use lanforge_api::api::{Compression, Encoding, Response};

pub struct ClientOptions {
    pub bincode: bool,
    pub no_compress: bool,
}

pub struct LanforgeClient {
    pub socket: String,
    pub opts: ClientOptions,
    #[cfg(feature = "remote")]
    pub remote: Option<String>,
    #[cfg(feature = "remote")]
    pub token: Option<String>,
    #[cfg(feature = "remote")]
    pub password: Option<String>,
}

impl LanforgeClient {
    pub async fn execute_handler(&self, mut handler: Box<dyn CliCommand>) -> Result<()> {
        #[cfg(feature = "remote")]
        if let Some(remote_url) = &self.remote {
            use lanforge_http::RemoteClient;
            let mut client = RemoteClient::new(remote_url.clone(), self.token.clone());
            if let Some(pwd) = &self.password {
                client
                    .login(pwd)
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
            }

            let control_cmd = handler.prepare()?;
            let resp = client
                .send(control_cmd)
                .await
                .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
            let _ = handler.on_response(&resp)?;
            return Ok(());
        }

        run_local_with_handler(handler, &self.socket, &self.opts).await
    }
}

pub async fn run_local_with_handler(
    mut handler: Box<dyn CliCommand>,
    socket_path: &str,
    opts: &ClientOptions,
) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!("Failed to connect to daemon at '{socket_path}'. Is the daemon running?")
    })?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut control_cmd = match handler.prepare() {
        Ok(cmd) => cmd,
        Err(e) => {
            if e.to_string() == "Cancelled." || e.to_string().contains("is required") {
                return Ok(());
            }
            return Err(e);
        }
    };

    // --- Capabilities Check & Negotiation ---
    let (encoding, compression) = negotiate_protocol(&mut reader, &mut writer, opts).await?;

    control_cmd.encoding = Some(encoding);
    control_cmd.compression = Some(compression);

    loop {
        write_request(&mut writer, &control_cmd, encoding).await?;

        let Some(response) = read_response(&mut reader, encoding, compression).await? else {
            break;
        };

        if let Some(next_cmd) = handler.on_response(&response)? {
            control_cmd = next_cmd;
            control_cmd.encoding = Some(encoding);
            control_cmd.compression = Some(compression);
            continue;
        }

        if handler.is_streaming() {
            loop {
                let Some(resp) = read_response(&mut reader, encoding, compression).await? else {
                    break;
                };
                let _ = handler.on_response(&resp)?;
            }
        }
        break;
    }

    Ok(())
}

async fn negotiate_protocol<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    opts: &ClientOptions,
) -> Result<(Encoding, Compression)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let encoding = if opts.bincode {
        Encoding::Bincode
    } else {
        Encoding::Json
    };

    // Send a Status command to check capabilities
    let mut status_cmd = lanforge_api::api::Command::new(lanforge_api::api::CommandAction::Status);
    status_cmd.encoding = Some(encoding);
    status_cmd.compression = Some(Compression::None);

    write_request(writer, &status_cmd, encoding).await?;
    let resp = read_response(reader, encoding, Compression::None)
        .await?
        .ok_or_else(|| eyre!("Daemon closed connection during negotiation"))?;

    let compression = match resp {
        Response::Status(s) => {
            if !opts.no_compress && s.capabilities.compression.contains(&Compression::Zstd) {
                #[cfg(feature = "zstd")]
                {
                    Compression::Zstd
                }
                #[cfg(not(feature = "zstd"))]
                {
                    Compression::None
                }
            } else {
                Compression::None
            }
        }
        _ => Compression::None,
    };

    Ok((encoding, compression))
}

pub(crate) async fn write_request<W>(
    writer: &mut W,
    cmd: &lanforge_api::api::Command,
    encoding: Encoding,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let data = match encoding {
        Encoding::Json => {
            let mut s = serde_json::to_string(cmd)?;
            s.push('\n');
            s.into_bytes()
        }
        Encoding::Bincode => {
            let mut buf =
                bincode::serialize(cmd).map_err(|e| eyre!("Bincode serialize error: {e}"))?;
            let mut final_buf = (u32::try_from(buf.len()).unwrap_or(u32::MAX))
                .to_be_bytes()
                .to_vec();
            final_buf.append(&mut buf);
            final_buf
        }
    };
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_response<R>(
    reader: &mut BufReader<R>,
    encoding: Encoding,
    compression: Compression,
) -> Result<Option<Response>>
where
    R: AsyncRead + Unpin,
{
    let data = if encoding == Encoding::Bincode || compression != Compression::None {
        // Framed protocol
        let mut len_bytes = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut len_bytes).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(e.into());
        }
        let len = u32::from_be_bytes(len_bytes);
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf).await?;
        buf
    } else {
        // Line-based JSON
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        line.into_bytes()
    };

    let decompressed = match compression {
        Compression::None => data,
        Compression::Zstd => {
            #[cfg(feature = "zstd")]
            {
                zstd::stream::decode_all(&data[..]).map_err(|e| eyre!("Zstd decode error: {e}"))?
            }
            #[cfg(not(feature = "zstd"))]
            {
                return Err(eyre!("Zstd support not enabled in this binary"));
            }
        }
    };

    let resp = match encoding {
        Encoding::Json => serde_json::from_slice(&decompressed)?,
        Encoding::Bincode => bincode::deserialize(&decompressed)
            .map_err(|e| eyre!("Bincode deserialize error: {e}"))?,
    };

    Ok(Some(resp))
}
