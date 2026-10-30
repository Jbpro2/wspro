use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha1::{Digest, Sha1};
use std::{env, io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME: usize = 1024 * 1024;
const MAX_HEADERS: usize = 16 * 1024;

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
    header_value(headers, name)
        .map(|value| {
            value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case(token))
        })
        .unwrap_or(false)
}

fn validate_handshake(request: &str) -> Result<Handshake, u16> {
    let Some((head, _)) = request.split_once("\r\n\r\n") else {
        return Err(400u16);
    };
    let mut lines = head.lines();
    let Some(start) = lines.next() else {
        return Err(400u16);
    };
    let fields: Vec<_> = start.split_ascii_whitespace().collect();
    if fields.len() != 3 || fields[0] != "GET" || fields[2] != "HTTP/1.1" {
        return Err(400u16);
    }
    if !token_header(head, "Upgrade", "websocket") || !token_header(head, "Connection", "upgrade") {
        return Err(400u16);
    }
    if header_value(head, "Sec-WebSocket-Version") != Some("13") {
        return Err(426);
    }
    let key = header_value(head, "Sec-WebSocket-Key").ok_or(400u16)?;
    let decoded = STANDARD.decode(key).map_err(|_| 400u16)?;
    if decoded.len() != 16 {
        return Err(400u16);
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
        n @ 0..=125 => out.push(n as u8),
        n @ 126..=65535 => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

async fn read_client_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<(u8, bool, Vec<u8>)> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).await?;
    let fin = h[0] & 0x80 != 0;
    let rsv = h[0] & 0x70;
    let opcode = h[0] & 0x0f;
    if rsv != 0 || h[1] & 0x80 == 0 || !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid WebSocket frame header",
        ));
    }
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0; 2];
        r.read_exact(&mut b).await?;
        len = u16::from_be_bytes(b) as u64;
        if len < 126 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    } else if len == 127 {
        let mut b = [0; 8];
        r.read_exact(&mut b).await?;
        len = u64::from_be_bytes(b);
        if len < 65536 || len >> 63 != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    if len as usize > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 1 MiB",
        ));
    }
    let control = opcode >= 8;
    if control && (!fin || len > 125) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut mask = [0u8; 4];
    r.read_exact(&mut mask).await?;
    let mut payload = vec![0; len as usize];
    r.read_exact(&mut payload).await?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok((opcode, fin, payload))
}

async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    w.write_all(&encode_frame(opcode, payload)).await
}

async fn bridge(client: TcpStream, ssh: TcpStream) -> io::Result<()> {
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = ssh.into_split();
    let mut ssh_buf = [0u8; 8192];
    let mut fragmenting = false;
    loop {
        tokio::select! {
            incoming = read_client_frame(&mut cr) => match incoming {
                Ok((opcode, fin, payload)) => match opcode {
                    0 => { if !fragmenting { return Err(io::ErrorKind::InvalidData.into()); } sw.write_all(&payload).await?; if fin { fragmenting=false; } }
                    1 | 2 => { if fragmenting { return Err(io::ErrorKind::InvalidData.into()); } sw.write_all(&payload).await?; fragmenting=!fin; }
                    8 => { write_frame(&mut cw, 8, &payload).await?; sw.shutdown().await?; return Ok(()); }
                    9 => write_frame(&mut cw, 10, &payload).await?,
                    10 => {},
                    _ => unreachable!(),
                },
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => { let _ = sw.shutdown().await; return Ok(()); }
                Err(e) => { let _ = write_frame(&mut cw, 8, &[0x03,0xea]).await; return Err(e); }
            },
            n = sr.read(&mut ssh_buf) => match n {
                Ok(0) => { write_frame(&mut cw, 8, &[0x03,0xe8]).await?; cw.shutdown().await?; return Ok(()); }
                Ok(n) => write_frame(&mut cw, 2, &ssh_buf[..n]).await?,
                Err(e) => return Err(e),
            }
        }
    }
}

async fn serve(mut client: TcpStream, ssh_addr: &str) -> io::Result<()> {
    let mut request = Vec::new();
    loop {
        if request.len() >= MAX_HEADERS {
            return send_error(&mut client, 400, "Bad Request").await;
        }
        let mut b = [0u8; 1];
        match client.read(&mut b).await? {
            0 => return Ok(()),
            _ => request.push(b[0]),
        }
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&request);
    let handshake = match validate_handshake(&text) {
        Ok(h) => h,
        Err(426) => {
            client.write_all(b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(());
        }
        Err(_) => return send_error(&mut client, 400, "Bad Request").await,
    };
    let ssh = match timeout(Duration::from_secs(3), TcpStream::connect(ssh_addr)).await {
        Ok(Ok(s)) => s,
        _ => return send_error(&mut client, 502, "Bad Gateway").await,
    };
    client.set_nodelay(true)?;
    ssh.set_nodelay(true)?;
    let response=format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",handshake.accept);
    client.write_all(response.as_bytes()).await?;
    bridge(client, ssh).await
}

async fn send_error(s: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let body = format!("{code} {reason}\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(response.as_bytes()).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut port = 8081u16;
    let mut ssh_port = 22u16;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?;
        match arg.as_str() {
            "--port" => port = value.parse()?,
            "--ssh-port" => ssh_port = value.parse()?,
            _ => anyhow::bail!("unknown argument: {arg}"),
        }
    }
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    let ssh_addr = format!("127.0.0.1:{ssh_port}");
    loop {
        let (stream, _) = listener.accept().await?;
        let addr = ssh_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(stream, &addr).await {
                eprintln!("websocket connection: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encode_frame_boundaries_and_payload() {
        assert_eq!(encode_frame(2, b"abc"), vec![0x82, 3, b'a', b'b', b'c']);
        assert_eq!(&encode_frame(2, &vec![0; 126])[..4], &[0x82, 126, 0, 126]);
        assert_eq!(
            &encode_frame(2, &vec![0; 65536])[..10],
            &[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]
        );
    }
    #[test]
    fn validates_rfc_handshake() {
        let req="GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert_eq!(
            validate_handshake(req).unwrap().accept,
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(
            validate_handshake(&req.replace("Version: 13", "Version: 12")),
            Err(426)
        );
        assert_eq!(
            validate_handshake(&req.replace("dGhlIHNhbXBsZSBub25jZQ==", "AAAA")),
            Err(400)
        );
    }
}
