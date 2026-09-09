//! Read-only Operational Formalism projection of Nightshift investigation artifacts.
use std::{fs, path::Path};

use ratatui::{
    Terminal,
    backend::TestBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MAX: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// A read-only composition of one exact Nightshift occurrence.
pub struct InvestigationProjectionV1 {
    /// Projection schema.
    pub schema: String,
    /// Exact Nightshift state artifact.
    pub state: Value,
    /// Durable-launch receipt, when retained.
    pub submission: Option<Value>,
    /// Terminal investigation record, when retained.
    pub record: Option<Value>,
    /// Exact Maude handoff.
    pub handoff: Value,
    /// Owner-custody occurrence directory.
    pub occurrence_path: String,
    /// Standing and NQ custody artifacts.
    pub sources: Vec<SourceArtifactV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// One exact owner artifact retained beside an occurrence.
pub struct SourceArtifactV1 {
    /// Filename in owner custody.
    pub name: String,
    /// Digest of exact retained bytes.
    pub digest: String,
    /// Parsed value for presentation.
    pub value: Value,
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() || meta.len() > MAX {
        return Err(format!(
            "{} is not a bounded regular artifact",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 != meta.len() {
        return Err(format!("{} changed while reading", path.display()));
    }
    Ok(bytes)
}

fn json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

/// Load and validate one exact occurrence without mutation.
pub fn load(root: &Path, id: &str) -> Result<InvestigationProjectionV1, String> {
    if id.len() != 71
        || !id.starts_with("sha256:")
        || !id[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("malformed investigation identity".into());
    }
    let occurrence = root.join(&id[7..]);
    let handoff = json(&occurrence.join("handoff.json"))?;
    let mut unsigned = handoff.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or("handoff must be an object")?;
    let handoff_digest = object
        .remove("handoff_digest")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or("handoff digest absent")?;
    if hash(&canonical(&unsigned)?) != handoff_digest
        || handoff.get("investigation_id").and_then(Value::as_str) != Some(id)
    {
        return Err("handoff identity/digest mismatch".into());
    }
    let state = json(&occurrence.join("state.json"))?;
    let submission = occurrence
        .join("submission.json")
        .exists()
        .then(|| json(&occurrence.join("submission.json")))
        .transpose()?;
    let record = occurrence
        .join("record.json")
        .exists()
        .then(|| json(&occurrence.join("record.json")))
        .transpose()?;
    let mut sources = Vec::new();
    for entry in fs::read_dir(&occurrence).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
            continue;
        };
        if name.ends_with(".standing.json")
            || name.ends_with(".nq.json")
            || name.ends_with(".qualification.json")
        {
            let bytes = read(&path)?;
            sources.push(SourceArtifactV1 {
                name: name.to_owned(),
                digest: hash(&bytes),
                value: serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
            });
        }
    }
    sources.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(InvestigationProjectionV1 {
        schema: "phosphor-ng.service-investigation-projection/v1".into(),
        state,
        submission,
        record,
        handoff,
        occurrence_path: occurrence.display().to_string(),
        sources,
    })
}

/// List validated occurrences in owner custody.
pub fn list(root: &Path) -> Result<Vec<InvestigationProjectionV1>, String> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.len() == 64 {
                result.push(load(root, &format!("sha256:{name}"))?);
            }
        }
    }
    result.sort_by(|a, b| id(b).cmp(id(a)));
    Ok(result)
}

/// Return the handoff-bound investigation identity.
pub fn id(value: &InvestigationProjectionV1) -> &str {
    value
        .handoff
        .get("investigation_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn raw(label: &str, value: &Value) -> String {
    format!(
        "<details class=raw><summary>{}</summary><pre>{}</pre></details>",
        esc(label),
        esc(&serde_json::to_string_pretty(value).unwrap_or_default())
    )
}

/// Shared browser style for the operational investigation surface.
pub fn style() -> &'static str {
    r#":root{color-scheme:dark;--bg:#0b0c0c;--panel:#151614;--line:#555248;--text:#e2dece;--muted:#9e9a8d;--amber:#d7a53b;--oxide:#b66b52}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-monospace,monospace}a{color:#e6bd65}.top{padding:.7rem 1rem;border-bottom:3px double var(--line);display:flex;gap:1rem}.top span{margin-left:auto;color:var(--muted)}main{max-width:1500px;margin:auto;padding:1rem}.rail{border-left:2px solid var(--line);padding:.25rem 0 1rem 1rem;margin-left:.4rem}.seam{border-top:3px double var(--line);padding-top:.7rem}.open{border-left:2px dashed var(--amber)}.stop{border-right:5px double var(--oxide);padding:.6rem;background:#211711}.grid{display:grid;grid-template-columns:1fr 1.4fr 1fr;gap:.8rem}.panel{border:1px solid var(--line);background:var(--panel);padding:.8rem;min-width:0}.wide{grid-column:1/-1}.muted{color:var(--muted)}.tag{border:1px solid var(--line);padding:.1rem .35rem;text-transform:uppercase;font-size:.7rem}.raw{margin-top:.5rem}.raw pre{overflow:auto;max-height:30rem;background:#070808;padding:.7rem}.finding{border-left:2px solid var(--amber);padding-left:.7rem;margin:.7rem 0}@media(max-width:900px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}}"#
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>{}</title><link rel=stylesheet href=/style.css></head><body><header class=top><a href=/phosphor-ng/investigations><strong>PHOSPHOR-NG</strong></a><b>service investigations</b><span>read only · no aggregate verdict</span></header><main>{body}</main></body></html>",
        esc(title)
    )
}

/// Render the read-only investigation index.
pub fn render_index(items: &[InvestigationProjectionV1]) -> String {
    let rows = items.iter().map(|item| {
        let state = item.state.get("state").and_then(Value::as_str).unwrap_or("unknown");
        let label = item.handoff.pointer("/profile/subject_label").and_then(Value::as_str).unwrap_or("unnamed subject");
        format!("<div class=rail><span class=tag>{}</span><h2><a href=\"/phosphor-ng/investigations/{}\">{}</a></h2><div class=muted>{}</div></div>", esc(state), esc(id(item)), esc(label), esc(id(item)))
    }).collect::<String>();
    page(
        "Service investigations",
        &format!(
            "<h1>Operational investigations</h1><p class=muted>Nightshift lifecycle and exact NQ/Standing custody, projected without mutation.</p>{rows}"
        ),
    )
}

/// Render operations, reasoning, and custody planes for one occurrence.
pub fn render_detail(item: &InvestigationProjectionV1) -> String {
    let state = item
        .state
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let label = item
        .handoff
        .pointer("/profile/subject_label")
        .and_then(Value::as_str)
        .unwrap_or("unnamed subject");
    let findings = item
        .record
        .as_ref()
        .and_then(|v| v.get("findings"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|finding| {
                    let profile = finding
                        .get("profile")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown profile");
                    let condition = finding
                        .pointer("/outcome/condition")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    format!(
                        "<div class=finding><strong>{}</strong><p>condition: {}</p>{}</div>",
                        esc(profile),
                        esc(condition),
                        raw("Exact finding", finding)
                    )
                })
                .collect::<String>()
        })
        .unwrap_or_else(|| {
            "<div class=\"rail open\">Expected findings ─────────╴ unresolved coverage</div>".into()
        });
    let custody = item
        .sources
        .iter()
        .map(|source| {
            format!(
                "<div class=rail><strong>{}</strong><div class=muted>{}</div>{}</div>",
                esc(&source.name),
                esc(&source.digest),
                raw("Exact owner artifact", &source.value)
            )
        })
        .collect::<String>();
    let authority = if item
        .sources
        .iter()
        .any(|v| v.name.ends_with(".standing.json"))
    {
        "Standing admission attached to acquisition rail"
    } else {
        "acquisition ─────⊣ Standing admission absent"
    };
    page(
        label,
        &format!(
            "<h1>{}</h1><p><span class=tag>{}</span> <span class=muted>{}</span></p><div class=grid><section class=panel><h2>Operations</h2><div class=rail>plan revision<br>{}</div><div class=\"rail seam\">Nightshift state<br><strong>{}</strong></div><div class=stop>{}</div></section><section class=panel><h2>Reasoning</h2>{}</section><section class=panel><h2>Custody</h2>{}</section><section class=\"panel wide\"><h2>Exact lifecycle</h2>{}{}</section></div>",
            esc(label),
            esc(state),
            esc(id(item)),
            esc(item
                .handoff
                .get("revision_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")),
            esc(state),
            esc(authority),
            findings,
            custody,
            raw("Handoff", &item.handoff),
            raw("State", &item.state)
        ),
    )
}

/// Render the same semantic projection for an exact terminal capability profile.
pub fn render_terminal(
    item: &InvestigationProjectionV1,
    width: u16,
    height: u16,
    ascii: bool,
    monochrome: bool,
) -> Result<String, String> {
    let backend = TestBackend::new(width.max(40), height.max(16));
    let mut terminal = Terminal::new(backend).map_err(|e| e.to_string())?;
    terminal.draw(|frame| {
        let areas = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Min(8), Constraint::Length(3)]).split(frame.area());
        let columns = if width >= 100 { Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(28), Constraint::Percentage(44), Constraint::Percentage(28)]).split(areas[1]) } else { Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(34), Constraint::Percentage(40), Constraint::Percentage(26)]).split(areas[1]) };
        let line = if ascii { "---" } else { "───" };
        let state = item.state.get("state").and_then(Value::as_str).unwrap_or("unknown");
        let label = item.handoff.pointer("/profile/subject_label").and_then(Value::as_str).unwrap_or("unnamed subject");
        let border = if monochrome { Style::default() } else { Style::default().fg(Color::DarkGray) };
        frame.render_widget(Paragraph::new(Line::from(vec![Span::styled(" NIGHTSHIFT / PHOSPHOR-NG ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(format!("subject:{label}  state:{state}"))])).block(Block::default().borders(Borders::ALL).border_style(border)), areas[0]);
        frame.render_widget(Paragraph::new(format!("SUBJECT RAIL\n{} Standing boundary\n{line} {label}\n{line} revision\n{line} Nightshift {state}", if ascii { "|-" } else { "├─" })).wrap(Wrap { trim: false }).block(Block::default().title(" OPERATIONS ").borders(Borders::ALL)), columns[0]);
        let reason = item.record.as_ref().and_then(|v| v.get("findings")).and_then(Value::as_array).map(|v| v.iter().map(|x| format!("{}  {}", x.get("profile").and_then(Value::as_str).unwrap_or("unknown"), x.pointer("/outcome/condition").and_then(Value::as_str).unwrap_or("unknown"))).collect::<Vec<_>>().join("\n")).unwrap_or_else(|| format!("findings {line}\u{2574}\nunknown / open edge"));
        frame.render_widget(Paragraph::new(reason).wrap(Wrap { trim: false }).block(Block::default().title(" REASONING ").borders(Borders::ALL)), columns[1]);
        frame.render_widget(Paragraph::new(format!("no aggregate verdict\nartifacts: {}\nrecord: {}", item.sources.len(), if item.record.is_some() { "retained" } else { "absent" })).wrap(Wrap { trim: false }).block(Block::default().title(" CUSTODY ").borders(Borders::ALL)), columns[2]);
        frame.render_widget(Paragraph::new("1 operations   2 reasoning   3 custody   / search   q quit").block(Block::default().borders(Borders::ALL)), areas[2]);
    }).map_err(|e| e.to_string())?;
    let buffer = terminal.backend().buffer();
    let mut output = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            output.push_str(buffer[(x, y)].symbol());
        }
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_owner_artifacts_render_in_browser_and_terminal() {
        let temp = tempfile::tempdir().unwrap();
        let id = format!("sha256:{}", "1".repeat(64));
        let occurrence = temp.path().join(&id[7..]);
        fs::create_dir(&occurrence).unwrap();
        let mut handoff = json!({
            "draft_id":"draft_service", "investigation_id":id,
            "plan_digest":format!("sha256:{}", "2".repeat(64)),
            "profile":{"subject_label":"fixed service"},
            "revision_id":"revision_fixture", "schema":"maude.service-investigation-handoff/v1"
        });
        let exact = hash(&canonical(&handoff).unwrap());
        handoff
            .as_object_mut()
            .unwrap()
            .insert("handoff_digest".into(), json!(exact));
        fs::write(
            occurrence.join("handoff.json"),
            canonical(&handoff).unwrap(),
        )
        .unwrap();
        fs::write(occurrence.join("state.json"), br#"{"state":"completed"}"#).unwrap();
        fs::write(
            occurrence.join("pn_systemd.standing.json"),
            br#"{"receipt":"standing"}"#,
        )
        .unwrap();
        fs::write(occurrence.join("record.json"), br#"{"findings":[{"outcome":{"condition":"present"},"profile":"nq.systemd_unit/v1"}],"aggregate_verdict":null}"#).unwrap();
        let loaded = load(temp.path(), handoff["investigation_id"].as_str().unwrap()).unwrap();
        assert_eq!(loaded.sources.len(), 1);
        let browser = render_detail(&loaded);
        assert!(browser.contains("no aggregate verdict"));
        assert!(browser.contains("Standing admission attached"));
        let wide = render_terminal(&loaded, 140, 40, false, false).unwrap();
        assert!(wide.contains("OPERATIONS") && wide.contains("REASONING"));
        let narrow = render_terminal(&loaded, 80, 24, true, true).unwrap();
        assert!(narrow.contains("Standing boundary") && narrow.contains("no aggregate verdict"));
    }

    #[test]
    fn changed_handoff_bytes_refuse() {
        let temp = tempfile::tempdir().unwrap();
        let id = format!("sha256:{}", "1".repeat(64));
        let occurrence = temp.path().join(&id[7..]);
        fs::create_dir(&occurrence).unwrap();
        fs::write(occurrence.join("handoff.json"), format!(r#"{{"draft_id":"different","handoff_digest":"sha256:{}","investigation_id":"{}"}}"#, "0".repeat(64), id)).unwrap();
        fs::write(occurrence.join("state.json"), b"{}").unwrap();
        assert!(load(temp.path(), &id).unwrap_err().contains("mismatch"));
    }
}
