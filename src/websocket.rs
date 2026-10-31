use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha1::{Digest, Sha1};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME: usize = 1024 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
const SSH_BACKEND: &str = "127.0.0.1:22";

#[derive(Debug, PartialEq, Eq)]
struct Handshake {
    accept: String,
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn token_header(headers: &str, name: &str, token: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        key.trim().eq_ignore_ascii_case(name)
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

fn validate_handshake(request: &str) -> std::result::Result<Handshake, u16> {
    let Some((head, _)) = request.split_once("\r\n\r\n") else {
        return Err(400);
    };
    let mut lines = head.lines();
    let Some(start) = lines.next() else {
        return Err(400);
    };
    let fields: Vec<_> = start.split_ascii_whitespace().collect();
    if fields.len() != 3 || fields[0] != "GET" || fields[2] != "HTTP/1.1" {
        return Err(400);
    }
    if !token_header(head, "Upgrade", "websocket") || !token_header(head, "Connection", "upgrade") {
        return Err(400);
    }
    if header_value(head, "Sec-WebSocket-Version") != Some("13") {
        return Err(426);
    }
    let key = header_value(head, "Sec-WebSocket-Key").ok_or(400u16)?;
    let decoded = STANDARD.decode(key).map_err(|_| 400u16)?;
    if decoded.len() != 16 {
        return Err(400);
    }

    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(GUID.as_bytes());
    Ok(Handshake {
        accept: STANDARD.encode(sha.finalize()),
    })
}

fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | (opcode & 0x0f));
    match payload.len() {
        length @ 0..=125 => out.push(length as u8),
        length @ 126..=65535 => {
            out.push(126);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            out.push(127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

async fn read_client_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(u8, bool, Vec<u8>)> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0f;
    if header[0] & 0x70 != 0 || header[1] & 0x80 == 0 || !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid WebSocket frame header",
        ));
    }

    let mut length = (header[1] & 0x7f) as u64;
    if length == 126 {
        let mut extended = [0u8; 2];
        reader.read_exact(&mut extended).await?;
        length = u16::from_be_bytes(extended) as u64;
        if length < 126 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    } else if length == 127 {
        let mut extended = [0u8; 8];
        reader.read_exact(&mut extended).await?;
        length = u64::from_be_bytes(extended);
        if length < 65536 || length >> 63 != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    if length > MAX_FRAME as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebSocket frame exceeds 1 MiB",
        ));
    }
    if opcode >= 8 && (!fin || length > 125) {
        return Err(io::ErrorKind::InvalidData.into());
    }

    let mut mask = [0u8; 4];
    reader.read_exact(&mut mask).await?;
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Ok((opcode, fin, payload))
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    writer.write_all(&encode_frame(opcode, payload)).await
}

async fn bridge(client: TcpStream, ssh: TcpStream) -> io::Result<()> {
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut ssh_reader, mut ssh_writer) = ssh.into_split();
    let mut ssh_buffer = [0u8; 8192];
    let mut fragmented_message = false;

    loop {
        tokio::select! {
            incoming = read_client_frame(&mut client_reader) => match incoming {
                Ok((opcode, fin, payload)) => match opcode {
                    0 => {
                        if !fragmented_message {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        ssh_writer.write_all(&payload).await?;
                        if fin { fragmented_message = false; }
                    }
                    1 | 2 => {
                        if fragmented_message {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        ssh_writer.write_all(&payload).await?;
                        fragmented_message = !fin;
                    }
                    8 => {
                        write_frame(&mut client_writer, 8, &payload).await?;
                        let _ = ssh_writer.shutdown().await;
                        return Ok(());
                    }
                    9 => write_frame(&mut client_writer, 10, &payload).await?,
                    10 => {},
                    _ => unreachable!(),
                },
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    let _ = ssh_writer.shutdown().await;
                    return Ok(());
                }
                Err(error) => {
                    let _ = write_frame(&mut client_writer, 8, &[0x03, 0xea]).await;
                    return Err(error);
                }
            },
            bytes = ssh_reader.read(&mut ssh_buffer) => match bytes {
                Ok(0) => {
                    write_frame(&mut client_writer, 8, &[0x03, 0xe8]).await?;
                    client_writer.shutdown().await?;
                    return Ok(());
                }
                Ok(count) => write_frame(&mut client_writer, 2, &ssh_buffer[..count]).await?,
                Err(error) => return Err(error),
            }
        }
    }
}

async fn read_headers(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    while request.len() < MAX_HEADERS {
        let mut byte = [0u8; 1];
        let count = client.read(&mut byte).await?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            return Ok(request);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "WebSocket headers exceed 16 KiB",
    ))
}

/// WebSocket RFC 6455 com túnel de destino fixo para SSH local.
pub async fn handle_websocket(mut client: TcpStream, _status: &str) -> Result<()> {
    client.set_nodelay(true)?;
    let request = match timeout(Duration::from_secs(5), read_headers(&mut client)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            let _ = send_error(&mut client, 400, "Bad Request").await;
            return Err(error.into());
        }
        Err(_) => {
            let _ = send_error(&mut client, 408, "Request Timeout").await;
            bail!("timeout lendo handshake WebSocket");
        }
    };

    let request_text = String::from_utf8_lossy(&request);
    let handshake = match validate_handshake(&request_text) {
        Ok(handshake) => handshake,
        Err(426) => {
            client
                .write_all(b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .await?;
            bail!("versao WebSocket nao suportada");
        }
        Err(_) => {
            send_error(&mut client, 400, "Bad Request").await?;
            bail!("handshake WebSocket invalido");
        }
    };

    let ssh = match timeout(Duration::from_secs(3), TcpStream::connect(SSH_BACKEND)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            send_error(&mut client, 502, "Bad Gateway").await?;
            bail!("backend SSH local indisponivel");
        }
    };
    ssh.set_nodelay(true)?;

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        handshake.accept
    );
    client.write_all(response.as_bytes()).await?;
    bridge(client, ssh).await?;
    Ok(())
}

async fn send_error(client: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let body = format!("{code} {reason}\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    client.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::{encode_frame, validate_handshake};

    #[test]
    fn frame_encoder_handles_websocket_length_boundaries() {
        assert_eq!(encode_frame(2, b"abc"), vec![0x82, 3, b'a', b'b', b'c']);
        assert_eq!(&encode_frame(2, &vec![0; 126])[..4], &[0x82, 126, 0, 126]);
        assert_eq!(
            &encode_frame(2, &vec![0; 65536])[..10],
            &[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]
        );
    }

    #[test]
    fn validates_rfc6455_handshake_and_key() {
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert_eq!(
            validate_handshake(request).unwrap().accept,
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(
            validate_handshake(&request.replace("Version: 13", "Version: 12")),
            Err(426)
        );
        assert_eq!(
            validate_handshake(&request.replace("dGhlIHNhbXBsZSBub25jZQ==", "AAAA")),
            Err(400)
        );
    }
}
