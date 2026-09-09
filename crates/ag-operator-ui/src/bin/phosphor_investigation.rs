//! Loopback-only browser and terminal service-investigation inspector.
use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener},
    path::PathBuf,
};

use ag_operator_ui::investigation;
use anyhow::{Context as _, Result, bail};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Read-only Operational Formalism inspector for service investigations")]
struct Args {
    #[arg(long)]
    root: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8437")]
    bind: SocketAddr,
    #[arg(long)]
    terminal: Option<String>,
    /// Open the interactive read-only terminal inspector for one investigation.
    #[arg(long, conflicts_with = "terminal")]
    tui: Option<String>,
    #[arg(long, default_value_t = 100)]
    width: u16,
    #[arg(long, default_value_t = 30)]
    height: u16,
    #[arg(long)]
    ascii: bool,
    #[arg(long)]
    monochrome: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = args
        .root
        .canonicalize()
        .context("resolve investigation root")?;
    if let Some(id) = args.tui {
        let item = investigation::load(&root, &id).map_err(anyhow::Error::msg)?;
        investigation::run_tui(&item, args.ascii, args.monochrome).map_err(anyhow::Error::msg)?;
        return Ok(());
    }
    if let Some(id) = args.terminal {
        let item = investigation::load(&root, &id).map_err(anyhow::Error::msg)?;
        print!(
            "{}",
            investigation::render_terminal(
                &item,
                args.width,
                args.height,
                args.ascii,
                args.monochrome
            )
            .map_err(anyhow::Error::msg)?
        );
        return Ok(());
    }
    if !args.bind.ip().is_loopback() {
        bail!("inspector must bind to loopback");
    }
    let listener = TcpListener::bind(args.bind)?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut bytes = [0_u8; 16 * 1024];
        let size = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..size]);
        let line = request.lines().next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");
        if !matches!(method, "GET" | "HEAD") {
            write_response(
                &mut stream,
                405,
                "text/plain",
                b"read only",
                method == "HEAD",
            )?;
            continue;
        }
        let (status, kind, body) = route(&root, path);
        write_response(&mut stream, status, kind, body.as_bytes(), method == "HEAD")?;
    }
    Ok(())
}

fn route(root: &std::path::Path, path: &str) -> (u16, &'static str, String) {
    if path == "/style.css" {
        return (200, "text/css", investigation::style().into());
    }
    if matches!(path, "/" | "/phosphor-ng/investigations") {
        return match investigation::list(root) {
            Ok(v) => (200, "text/html", investigation::render_index(&v)),
            Err(e) => (503, "text/plain", e),
        };
    }
    if let Some(id) = path.strip_prefix("/phosphor-ng/investigations/") {
        let id = id.replace("%3A", ":").replace("%3a", ":");
        return match investigation::load(root, &id) {
            Ok(v) => (200, "text/html", investigation::render_detail(&v)),
            Err(e) => (404, "text/plain", e),
        };
    }
    if path == "/api/v1/investigations" {
        return match investigation::list(root) {
            Ok(v) => (200, "application/json", serde_json::to_string(&v).unwrap()),
            Err(e) => (
                503,
                "application/json",
                serde_json::json!({"error":e}).to_string(),
            ),
        };
    }
    (404, "text/plain", "not found".into())
}

fn write_response(
    stream: &mut std::net::TcpStream,
    status: u16,
    kind: &str,
    body: &[u8],
    head: bool,
) -> Result<()> {
    let phrase = if status == 200 {
        "OK"
    } else if status == 405 {
        "Method Not Allowed"
    } else if status == 404 {
        "Not Found"
    } else {
        "Unavailable"
    };
    write!(
        stream,
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: {kind}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'self'; form-action 'none'\r\nAllow: GET, HEAD\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !head {
        stream.write_all(body)?;
    }
    Ok(())
}
