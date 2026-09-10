//! Loopback-only browser and terminal service-investigation inspector.
use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
};

use ag_operator_ui::investigation;
use anyhow::{bail, Context as _, Result};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Read-only Operational Formalism inspector for service investigations")]
struct Args {
    #[arg(long)]
    root: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8437")]
    bind: SocketAddr,
    /// Mutable design surface used by cross-surface navigation.
    #[arg(long, default_value = "http://127.0.0.1:8427/phosphor/design")]
    design_url: String,
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
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_connection(&root, &args.design_url, &mut stream) {
                    eprintln!("investigation request failed: {error:#}");
                }
            }
            Err(error) => eprintln!("investigation connection failed: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(
    root: &std::path::Path,
    design_url: &str,
    stream: &mut (impl std::io::Read + std::io::Write),
) -> Result<()> {
    let mut bytes = [0_u8; 16 * 1024];
    let size = stream.read(&mut bytes)?;
    if size == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&bytes[..size]);
    let line = request.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if !matches!(method, "GET" | "HEAD") {
        return write_response(stream, 405, "text/plain", b"read only", method == "HEAD");
    }
    let (status, kind, body) = route(root, path, design_url);
    write_response(stream, status, kind, body.as_bytes(), method == "HEAD")
}

fn route(root: &std::path::Path, path: &str, design_url: &str) -> (u16, &'static str, String) {
    if path == "/style.css" {
        return (200, "text/css", investigation::style().into());
    }
    if matches!(path, "/" | "/phosphor-ng/investigations") {
        return match investigation::list(root) {
            Ok(v) => (
                200,
                "text/html",
                investigation::render_index_with_design(&v, design_url),
            ),
            Err(e) => (503, "text/plain", e),
        };
    }
    if let Some(id) = path.strip_prefix("/phosphor-ng/investigations/") {
        let id = id.replace("%3A", ":").replace("%3a", ":");
        return match investigation::load(root, &id) {
            Ok(v) => (
                200,
                "text/html",
                investigation::render_detail_with_design(&v, design_url),
            ),
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
    stream: &mut impl std::io::Write,
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::handle_connection;

    #[test]
    fn empty_reachability_connection_is_not_a_server_failure() {
        let root = tempfile::tempdir().unwrap();
        let mut stream = Cursor::new(Vec::new());

        handle_connection(
            root.path(),
            "http://127.0.0.1:8427/phosphor/design",
            &mut stream,
        )
        .unwrap();
        assert!(stream.into_inner().is_empty());
    }
}
