use color_eyre::eyre::{Context, Result, eyre};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::args::Command;
use crate::cli::commands::CliCommand;
use crate::cli::commands::GenericHandler;
use crate::cli::commands::db::DbHandler;
use crate::cli::commands::devices::DevicesHandler;
use crate::cli::commands::dns::DnsCommand;
use crate::cli::commands::host::HostHandler;
use crate::cli::commands::lease::LeaseHandler;
use crate::cli::commands::log::LogHandler;
use crate::cli::commands::status::StatusHandler;
use crate::cli::commands::whois::WhoisHandler;
use crate::cli::commands::wol::WolCommand;
use lanforge_api::api::{Compression, Encoding, Response};

pub struct ClientOptions {
    pub bincode: bool,
    pub no_compress: bool,
}

pub async fn run_client(command: Command, socket_path: &str, opts: ClientOptions) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!("Failed to connect to daemon at '{socket_path}'. Is the daemon running?")
    })?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut handler: Box<dyn CliCommand> = match command {
        Command::Status => Box::new(StatusHandler),
        Command::Devices {
            verbose,
            filter,
            vendor,
            method,
            format,
            sort,
            show_vendor,
        } => Box::new(DevicesHandler {
            verbose,
            filter,
            vendor,
            method,
            format,
            sort,
            show_vendor,
        }),
        Command::Host { action } => Box::new(HostHandler { action }),
        Command::Lease { action } => Box::new(LeaseHandler { action }),
        Command::Db { action } => Box::new(DbHandler { action }),
        Command::Log {
            follow,
            verbose,
            lines,
        } => Box::new(LogHandler {
            follow,
            verbose,
            lines,
        }),
        Command::Reload => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::new(lanforge_api::api::CommandAction::Reload),
            streaming: false,
        }),
        Command::Watch => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::new(lanforge_api::api::CommandAction::Watch),
            streaming: true,
        }),
        Command::Scan => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::new(lanforge_api::api::CommandAction::Scan),
            streaming: false,
        }),
        Command::Purge { mac } => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::new(lanforge_api::api::CommandAction::Purge { mac }),
            streaming: false,
        }),
        Command::Wol { target } => Box::new(WolCommand { target }),
        Command::Whois { target } => Box::new(WhoisHandler { target }),
        Command::Dns { action } => Box::new(DnsCommand { action }),
        Command::Query { target } => Box::new(crate::cli::commands::query::QueryHandler { target }),
    };

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
    let (encoding, compression) = negotiate_protocol(&mut reader, &mut writer, &opts).await?;

    control_cmd.encoding = Some(encoding);
    control_cmd.compression = Some(compression);

    loop {
        write_request(&mut writer, &control_cmd, encoding).await?;

        let response = match read_response(&mut reader, encoding, compression).await? {
            Some(r) => r,
            None => break,
        };

        if let Some(next_cmd) = handler.on_response(&response)? {
            control_cmd = next_cmd;
            control_cmd.encoding = Some(encoding);
            control_cmd.compression = Some(compression);
            continue;
        }

        if handler.is_streaming() {
            loop {
                let resp = match read_response(&mut reader, encoding, compression).await? {
                    Some(r) => r,
                    None => break,
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

async fn write_request<W>(
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
            let mut final_buf = (buf.len() as u32).to_be_bytes().to_vec();
            final_buf.append(&mut buf);
            final_buf
        }
    };
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_response<R>(
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
