//! Loopback-only HTTP transport for the read-only operator projection.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::Serialize;

use crate::links::GovernedRuntimeLinkV1;
use crate::render;
use crate::source::OperatorReaderV1;

const MAX_REQUEST_HEADER_BYTES: u64 = 16 * 1024;

/// Validates and runs the local operator server.
///
/// # Errors
///
/// Returns an error for a non-loopback address or listener failure.
pub fn serve(address: SocketAddr, reader: OperatorReaderV1) -> Result<(), String> {
    if !address.ip().is_loopback() {
        return Err("operator UI must bind a loopback address".to_owned());
    }
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("bind operator UI at {address}: {error}"))?;
    eprintln!("Phosphor read-only inspector listening on http://{address}");
    let reader = Arc::new(reader);
    for connection in listener.incoming() {
        let reader = Arc::clone(&reader);
        match connection {
            Ok(mut stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle_stream(&mut stream, &reader) {
                        eprintln!("operator UI request failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("operator UI connection refused: {error}"),
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ResponseV1 {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl ResponseV1 {
    fn html(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.into_bytes(),
        }
    }

    fn json(status: u16, value: &impl Serialize) -> Self {
        match serde_json::to_vec_pretty(value) {
            Ok(body) => Self {
                status,
                content_type: "application/json; charset=utf-8",
                body,
            },
            Err(error) => Self::plain(500, format!("operator projection serialization: {error}")),
        }
    }

    fn plain(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into_bytes(),
        }
    }
}

#[derive(Serialize)]
struct ApiErrorV1<'a> {
    schema: &'static str,
    error: &'a str,
}

fn handle_stream(stream: &mut TcpStream, reader: &OperatorReaderV1) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("set request timeout: {error}"))?;
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("read request: {error}"))?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if u64::try_from(request.len()).unwrap_or(u64::MAX) > MAX_REQUEST_HEADER_BYTES {
            return write_response(
                stream,
                &ResponseV1::plain(431, "request header too large".to_owned()),
                false,
            );
        }
    }
    let request =
        std::str::from_utf8(&request).map_err(|_| "request header is not UTF-8".to_owned())?;
    let line = request
        .lines()
        .next()
        .ok_or_else(|| "empty request".to_owned())?;
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next().ok_or_else(|| "missing method".to_owned())?;
    let target = parts.next().ok_or_else(|| "missing target".to_owned())?;
    let version = parts.next().ok_or_else(|| "missing version".to_owned())?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return write_response(
            stream,
            &ResponseV1::plain(400, "malformed request line".to_owned()),
            false,
        );
    }
    let Some(head) = read_method(method) else {
        return write_response(
            stream,
            &ResponseV1::plain(
                405,
                "read-only interface: only GET and HEAD are allowed".to_owned(),
            ),
            false,
        );
    };
    write_response(stream, &route(target, reader), head)
}

const fn read_method(method: &str) -> Option<bool> {
    match method.as_bytes() {
        b"GET" => Some(false),
        b"HEAD" => Some(true),
        _ => None,
    }
}

fn route(target: &str, reader: &OperatorReaderV1) -> ResponseV1 {
    let (path, query) = target
        .split_once('?')
        .map_or((target, ""), |(path, query)| (path, query));
    match path {
        "/" | "/phosphor-ng" | "/phosphor-ng/" => match reader.campaign_index() {
            Ok(model) => ResponseV1::html(
                200,
                render::campaign_index_with_context(&model, reader.mode_label(), query),
            ),
            Err(error) => ResponseV1::html(
                503,
                visible_html_error("Campaign index unavailable", &error),
            ),
        },
        "/api/v1/campaigns" => match reader.campaign_index() {
            Ok(model) => ResponseV1::json(200, &model),
            Err(error) => ResponseV1::json(
                503,
                &ApiErrorV1 {
                    schema: "ag.operator-ui.error/v1",
                    error: &error,
                },
            ),
        },
        "/style.css" => ResponseV1 {
            status: 200,
            content_type: "text/css; charset=utf-8",
            body: render::STYLE.as_bytes().to_vec(),
        },
        _ => campaign_route(path, reader),
    }
}

fn campaign_route(path: &str, reader: &OperatorReaderV1) -> ResponseV1 {
    match GovernedRuntimeLinkV1::parse_path(path) {
        Ok(Some(link)) => {
            return match reader.campaign_detail_for_link(&link) {
                Ok(model) => ResponseV1::html(
                    200,
                    render::campaign_detail_for_link_with_context(
                        &model,
                        reader.mode_label(),
                        &link,
                    ),
                ),
                Err(error) => ResponseV1::html(
                    404,
                    visible_html_error("Governed occurrence unavailable", &error),
                ),
            };
        }
        Ok(None) => {}
        Err(error) => {
            return ResponseV1::html(
                400,
                visible_html_error("Invalid Phosphor deep link", &error),
            );
        }
    }
    if let Some(semantic_path) = path.strip_prefix("/api/v1") {
        match GovernedRuntimeLinkV1::parse_path(semantic_path) {
            Ok(Some(link)) => {
                return match reader.campaign_detail_for_link(&link) {
                    Ok(model) => ResponseV1::json(200, &model),
                    Err(error) => ResponseV1::json(
                        404,
                        &ApiErrorV1 {
                            schema: "ag.operator-ui.error/v1",
                            error: &error,
                        },
                    ),
                };
            }
            Ok(None) => {}
            Err(error) => {
                return ResponseV1::json(
                    400,
                    &ApiErrorV1 {
                        schema: "ag.operator-ui.error/v1",
                        error: &error,
                    },
                );
            }
        }
    }
    if let Some(token) = path.strip_prefix("/campaign/")
        && valid_token(token)
    {
        return match reader.campaign_detail(token) {
            Ok(model) => ResponseV1::html(
                200,
                render::campaign_detail_with_context(&model, reader.mode_label()),
            ),
            Err(error) => ResponseV1::html(404, visible_html_error("Campaign unavailable", &error)),
        };
    }
    if let Some(token) = path.strip_prefix("/api/v1/campaigns/")
        && valid_token(token)
    {
        return match reader.campaign_detail(token) {
            Ok(model) => ResponseV1::json(200, &model),
            Err(error) => ResponseV1::json(
                404,
                &ApiErrorV1 {
                    schema: "ag.operator-ui.error/v1",
                    error: &error,
                },
            ),
        };
    }
    ResponseV1::plain(404, "not found".to_owned())
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 510
        && token.len().is_multiple_of(2)
        && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn write_response(stream: &mut TcpStream, response: &ResponseV1, head: bool) -> Result<(), String> {
    let phrase = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Response",
    };
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nAllow: GET, HEAD\r\nConnection: close\r\n\r\n",
        response.status,
        phrase,
        response.content_type,
        response.body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| {
            if head {
                Ok(())
            } else {
                stream.write_all(&response.body)
            }
        })
        .map_err(|error| format!("write response: {error}"))
}

fn visible_html_error(title: &str, detail: &str) -> String {
    let safe_title = html_escape(title);
    let safe_detail = html_escape(detail);
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><title>{safe_title}</title><link rel=stylesheet href=/style.css></head><body><header><a href=/phosphor-ng>Phosphor</a><span class=projection>read only</span></header><main><section class=\"panel critical\"><h1>{safe_title}</h1><span class=error>unavailable</span><pre>{safe_detail}</pre></section></main></body></html>"
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Rejects any configured non-loopback bind before opening a listener.
///
/// # Errors
///
/// Returns an error when the address is not loopback.
pub fn validate_bind_ip(ip: IpAddr) -> Result<(), String> {
    if ip.is_loopback() {
        Ok(())
    } else {
        Err("operator UI may listen only on loopback".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::OperatorSourceConfigV1;

    #[test]
    fn routes_have_no_mutation_method() {
        assert!(valid_token("6162632e73716c697465"));
        assert!(!valid_token("../campaign.sqlite"));
        assert!(validate_bind_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(validate_bind_ip("0.0.0.0".parse().unwrap()).is_err());
    }

    #[test]
    fn visible_errors_escape_external_diagnostics() {
        let page = visible_html_error("unavailable", "<source refused>");
        assert!(page.contains("&lt;source refused&gt;"));
        assert!(!page.contains("<source refused>"));
    }

    #[test]
    fn mutation_http_methods_are_mechanically_refused() {
        assert_eq!(read_method("GET"), Some(false));
        assert_eq!(read_method("HEAD"), Some(true));
        for forbidden in ["POST", "PUT", "PATCH", "DELETE", "CONNECT"] {
            assert_eq!(read_method(forbidden), None);
        }
    }

    #[test]
    fn index_and_json_routes_project_an_empty_configured_root() {
        let root = tempfile::tempdir().unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: root.path().join("ag-loopctl"),
            nightshift: None,
            docket: None,
            maude_acquisition: None,
        })
        .unwrap();
        let page = route("/", &reader);
        assert_eq!(page.status, 200);
        assert!(
            String::from_utf8(page.body)
                .unwrap()
                .contains("No campaign stores")
        );
        let product_page = route("/phosphor-ng", &reader);
        assert_eq!(product_page.status, 200);
        assert!(
            String::from_utf8(product_page.body)
                .unwrap()
                .contains("Phosphor")
        );
        let api = route("/api/v1/campaigns", &reader);
        assert_eq!(api.status, 200);
        let value: serde_json::Value = serde_json::from_slice(&api.body).unwrap();
        assert_eq!(value["schema"], "ag.operator-ui.campaign-index/v1");
        assert!(value["campaigns"].as_array().unwrap().is_empty());
    }

    #[test]
    fn malformed_semantic_links_fail_visible_without_locator_fallback() {
        let root = tempfile::tempdir().unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: root.path().join("ag-loopctl"),
            nightshift: None,
            docket: None,
            maude_acquisition: None,
        })
        .unwrap();
        let response = route(
            "/phosphor-ng/campaigns/not-a-digest/occurrences/not-a-uuid",
            &reader,
        );
        assert_eq!(response.status, 400);
        assert!(
            String::from_utf8(response.body)
                .unwrap()
                .contains("Invalid Phosphor deep link")
        );
    }
}
