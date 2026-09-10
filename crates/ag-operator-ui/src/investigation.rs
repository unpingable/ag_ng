//! Read-only Operational Formalism projection of Nightshift investigation artifacts.
use std::{fmt::Write as _, fs, io, path::Path};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use ratatui::{
    backend::{CrosstermBackend, TestBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
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
///
/// # Errors
///
/// Returns an error when any required owner artifact is absent, malformed,
/// oversized, changed during its read, or disagrees with the requested identity.
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
///
/// # Errors
///
/// Returns an error when the root or any candidate occurrence cannot be read
/// and validated under the exact supported schema.
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
#[must_use]
pub fn style() -> &'static str {
    r":root{color-scheme:dark;--bg:#0d0d0b;--surface:#141410;--panel:#1a1a15;--raised:#22221b;--line:#555247;--line-soft:#35332c;--text:#e7e0ce;--muted:#aaa28f;--amber:#d3a445;--blue:#8299ad;--green:#849b72;--oxide:#b36d55;--focus:#f0c66d}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,sans-serif}a{color:#e2b95f;text-underline-offset:.18em}a:focus-visible,summary:focus-visible{outline:3px solid var(--focus);outline-offset:3px}.skip{position:absolute;left:-10000px}.skip:focus{left:.8rem;top:.8rem;z-index:30;background:var(--raised);padding:.5rem}.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:1.2rem;padding:.8rem 1.2rem;background:#10100deF;border-bottom:3px double var(--line)}.brand{color:var(--text);font-weight:800;text-decoration:none;letter-spacing:.04em}.nav{display:flex;gap:.25rem}.nav a{color:var(--muted);padding:.3rem .45rem;text-decoration:none}.nav a[aria-current=page]{color:var(--text);border-bottom:2px solid var(--amber)}.context{margin-left:auto;color:var(--muted);font:12px/1.4 ui-monospace,monospace;overflow-wrap:anywhere}main{max-width:1240px;margin:auto;padding:2rem 1.2rem 5rem}h1,h2,h3,p{margin-top:0}h1{font-size:clamp(1.8rem,4vw,3rem);line-height:1.08;max-width:22ch;margin-bottom:.65rem}h2{font-size:1.05rem;letter-spacing:.02em}h3{font-size:1rem}.eyebrow,.label{display:block;color:var(--muted);font:700 11px/1.4 ui-monospace,monospace;letter-spacing:.1em;text-transform:uppercase}.lede{font-size:1.13rem;max-width:72ch;color:#d4ccba}.muted{color:var(--muted);overflow-wrap:anywhere}.mono,code,pre{font-family:ui-monospace,monospace;overflow-wrap:anywhere}.button{display:inline-block;border:1px solid var(--amber);background:#2b2415;color:#f1d28c;padding:.55rem .8rem;text-decoration:none;font-weight:750}.summary{border-left:5px solid var(--amber);background:var(--surface);padding:1rem 1.15rem;margin:1.4rem 0}.summary strong{display:block;font-size:1.2rem}.nonclaim{color:var(--muted);font-size:.88rem;margin:.45rem 0 0}.status-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border:1px solid var(--line);margin:1.2rem 0}.status-cell{padding:.85rem;border-left:1px solid var(--line-soft);min-width:0}.status-cell:first-child{border-left:0}.status-cell strong{display:block}.layout{display:grid;grid-template-columns:minmax(0,2fr) minmax(17rem,1fr);gap:1rem;align-items:start}.panel{border:1px solid var(--line);background:var(--panel);padding:1rem;min-width:0}.panel+.panel{margin-top:1rem}.observation{border-top:1px solid var(--line);padding:1.15rem 0}.observation:first-of-type{border-top:0}.observation-head{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem}.observation h3{font-size:1.2rem;margin:.15rem 0 .35rem}.state{display:inline-block;border:1px solid var(--line);padding:.15rem .4rem;font:700 11px/1.3 ui-monospace,monospace;text-transform:uppercase;letter-spacing:.05em}.state.observed{border-color:var(--green);color:#b9cca9}.state.unresolved{border-color:var(--amber);color:#efca7a}.state.refused{border-color:var(--oxide);color:#e5a18a}.facts{display:grid;grid-template-columns:minmax(8rem,11rem) minmax(0,1fr);gap:.35rem .8rem;margin:.8rem 0}.facts dt{color:var(--muted)}.facts dd{margin:0;overflow-wrap:anywhere}.limits{margin:.5rem 0;padding-left:1.2rem;color:var(--muted)}.timeline{border-left:2px solid var(--blue);padding-left:1rem;margin-left:.25rem}.timeline div{padding:.2rem 0 1rem}.timeline strong{display:block}.evidence-list{display:grid;gap:.55rem}.evidence{border-left:2px solid var(--line);padding-left:.8rem;min-width:0}.evidence strong{display:block}.raw{margin-top:.65rem;border:1px solid var(--line-soft)}.raw summary{cursor:pointer;padding:.6rem .7rem;background:var(--raised);font-weight:700}.raw pre{white-space:pre;overflow:auto;max-height:34rem;margin:0;background:#090906;padding:.8rem;font-size:.72rem;line-height:1.45}.record-actions{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0}.service-list{display:grid;gap:.8rem}.service-card{border:1px solid var(--line);background:var(--panel);padding:1rem}.service-card h2{font-size:1.35rem;margin:.2rem 0}.service-meta{display:flex;gap:1rem;flex-wrap:wrap;color:var(--muted);font-size:.88rem}.empty{border-left:4px dashed var(--blue);padding:1rem;background:var(--surface)}@media(max-width:760px){.top{position:static;align-items:flex-start;flex-wrap:wrap}.context{width:100%;margin:0}.status-grid,.layout{grid-template-columns:1fr}.status-cell{border-left:0;border-top:1px solid var(--line-soft)}.status-cell:first-child{border-top:0}main{padding:1.25rem .8rem 4rem}.observation-head{display:block}.state{margin-bottom:.5rem}.facts{grid-template-columns:1fr}.facts dd{margin-bottom:.35rem}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}"
}

fn page(title: &str, body: &str, design_url: &str, active: &str, context: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>{} · Operational ECAD</title><link rel=stylesheet href=/style.css></head><body><a class=skip href=#main>Skip to investigation</a><header class=top><a class=brand href=\"{}\">OPERATIONAL ECAD</a><nav class=nav aria-label=Workspace><a href=\"{}\">Service</a><a {} href=/phosphor-ng/investigations>Findings</a><a href=\"{}#advanced-plan-editing\">Advanced</a></nav><span class=context>{}</span></header><main id=main>{body}</main></body></html>",
        esc(title), esc(design_url), esc(design_url), if active == "findings" { "aria-current=page" } else { "" }, esc(design_url), esc(context)
    )
}

fn profile_copy(profile: &str) -> (&'static str, &'static str) {
    match profile {
        "nq.systemd_unit/v1" => (
            "Service-manager observation",
            "Does the target service-manager state match the admitted policy?",
        ),
        "nq.http_endpoint/v1" => (
            "HTTP observation",
            "Is complete current HTTP testimony available from the controller vantage?",
        ),
        _ => (
            "Bounded observation",
            "What did the configured diagnostic establish?",
        ),
    }
}

fn source_for<'a>(
    item: &'a InvestigationProjectionV1,
    node: &str,
    suffix: &str,
) -> Option<&'a SourceArtifactV1> {
    item.sources
        .iter()
        .find(|source| source.name == format!("{node}.{suffix}.json"))
}

fn outcome_phrase(profile: &str, condition: &str, summary: &str) -> String {
    match (profile, condition) {
        ("nq.systemd_unit/v1", "present") => "Service-manager policy mismatch observed".into(),
        ("nq.http_endpoint/v1", "unresolved") => "HTTP question unresolved".into(),
        (_, _) if !summary.is_empty() => summary.into(),
        _ => format!("Observation condition: {condition}"),
    }
}

fn source_label(name: &str) -> &'static str {
    if name.ends_with(".nq.json") {
        "Diagnostic finding"
    } else if name.ends_with(".qualification.json") {
        "Evidence applicability check"
    } else if name.ends_with(".standing.json") {
        "Permission receipt"
    } else {
        "Owner artifact"
    }
}

fn compact_identity(value: &str) -> String {
    if value.len() <= 28 {
        value.into()
    } else {
        format!("{}…{}", &value[..18], &value[value.len() - 7..])
    }
}

fn display_time(value: &str) -> String {
    value.replace('T', " ")
}

/// Render the read-only investigation index.
#[must_use]
pub fn render_index(items: &[InvestigationProjectionV1]) -> String {
    render_index_with_design(items, "http://127.0.0.1:8427/phosphor/design")
}

/// Render the read-only investigation index with an explicit mutable-design return URL.
#[must_use]
pub fn render_index_with_design(items: &[InvestigationProjectionV1], design_url: &str) -> String {
    let mut rows = String::new();
    for item in items {
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
        let _ = write!(
            rows,
            "<article class=service-card><span class=state>{}</span><h2><a href=\"/phosphor-ng/investigations/{}\">{}</a></h2><p>{}</p><div class=service-meta><span>Investigation {}</span><span>Last observed {}</span></div></article>",
            esc(if state == "completed" { "diagnostic completed" } else { state }),
            esc(id(item)),
            esc(label),
            if state == "completed" { "Review the independent observations and unresolved questions." } else { "Open the retained investigation state." },
            esc(state),
            esc(&display_time(item.state.get("updated_at").and_then(Value::as_str).unwrap_or("time unavailable")))
        );
    }
    page(
        "Service investigations",
        &format!(
            "<span class=eyebrow>Investigation history</span><h1>Service investigations</h1><p class=lede>Open a retained diagnostic to understand what each observation established. A completed diagnostic is not a service-health verdict.</p><section class=service-list>{}</section>",
            if rows.is_empty() { "<div class=empty>No retained investigation records are available. Return to Service to prepare the supported diagnostic.</div>" } else { &rows }
        ),
        design_url,
        "findings",
        "service investigations",
    )
}

/// Render operations, reasoning, and custody planes for one occurrence.
pub fn render_detail(item: &InvestigationProjectionV1) -> String {
    render_detail_with_design(item, "http://127.0.0.1:8427/phosphor/design")
}

/// Render one occurrence with an explicit mutable-design return URL.
pub fn render_detail_with_design(item: &InvestigationProjectionV1, design_url: &str) -> String {
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
    let finding_values = item
        .record
        .as_ref()
        .and_then(|v| v.get("findings"))
        .and_then(Value::as_array);
    let mut findings = String::new();
    let mut summary_parts = Vec::new();
    if let Some(values) = finding_values {
        for finding in values {
            let profile = finding
                .get("profile")
                .and_then(Value::as_str)
                .unwrap_or("unknown profile");
            let node = finding
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let condition = finding
                .pointer("/outcome/condition")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let summary = finding
                .pointer("/outcome/summary")
                .and_then(Value::as_str)
                .unwrap_or("");
            let coverage = finding
                .pointer("/outcome/coverage")
                .and_then(Value::as_str)
                .unwrap_or("not stated");
            let (title, question) = profile_copy(profile);
            let phrase = outcome_phrase(profile, condition, summary);
            summary_parts.push(phrase.clone());
            let source = source_for(item, node, "nq");
            let completed = source
                .and_then(|value| value.value.get("completed_at"))
                .and_then(Value::as_str)
                .map_or_else(|| "time unavailable".into(), display_time);
            let vantage = item
                .handoff
                .pointer("/profile/diagnostics")
                .and_then(Value::as_array)
                .and_then(|values| {
                    values
                        .iter()
                        .find(|value| value.get("node_id").and_then(Value::as_str) == Some(node))
                })
                .and_then(|value| value.get("vantage"))
                .and_then(Value::as_str)
                .unwrap_or("vantage unavailable");
            let limits = source
                .and_then(|value| value.value.get("limitations"))
                .and_then(Value::as_array)
                .map_or_else(
                    || "<li>No additional limitation projection is available.</li>".into(),
                    |values| {
                        values
                            .iter()
                            .filter_map(|value| value.get("detail").and_then(Value::as_str))
                            .map(|value| format!("<li>{}</li>", esc(value)))
                            .collect::<Vec<_>>()
                            .join("")
                    },
                );
            let refusal = source
                .and_then(|value| {
                    value
                        .value
                        .pointer("/outcome/refusals/0/origin/payload/refusal/message")
                })
                .and_then(Value::as_str);
            let _ = write!(findings, "<article class=observation><div class=observation-head><div><span class=eyebrow>{}</span><h3>{}</h3></div><span class=\"state {}\">{}</span></div><p>{}</p><dl class=facts><dt>Question</dt><dd>{}</dd><dt>Observed from</dt><dd>{}</dd><dt>Observation time</dt><dd>{}</dd><dt>Coverage</dt><dd>{}</dd>{}</dl><h3>Limits of this observation</h3><ul class=limits>{}</ul><p><a href=\"#evidence-{}.nq.json\">View supporting evidence</a></p>{}</article>",
                esc(title), esc(&phrase), if condition == "unresolved" { "unresolved" } else { "observed" }, if condition == "unresolved" { "unresolved" } else { "bounded finding" }, esc(summary), esc(question), esc(vantage), esc(&completed), esc(coverage), refusal.map_or_else(String::new, |message| format!("<dt>Why unresolved</dt><dd>{}</dd>", esc(message))), limits, esc(node), raw("Exact bounded finding", finding));
        }
    } else {
        findings.push_str("<div class=empty>Individual findings are not yet available. Reopen this same investigation later; do not submit replacement work.</div>");
    }
    let mut custody = String::new();
    let mut ordered_sources = item.sources.iter().collect::<Vec<_>>();
    ordered_sources.sort_by_key(|source| {
        let node = if source.name.starts_with("pn_systemd.") {
            0
        } else if source.name.starts_with("pn_http.") {
            1
        } else {
            2
        };
        let kind = if source.name.ends_with(".nq.json") {
            0
        } else if source.name.ends_with(".qualification.json") {
            1
        } else {
            2
        };
        (node, kind, &source.name)
    });
    for source in ordered_sources {
        let _ = write!(
            custody,
            "<div class=evidence id=\"evidence-{}\"><span class=eyebrow>{}</span><strong>{}</strong><span class=muted>Original file: {}<br><code>{}</code></span>{}</div>",
            esc(&source.name),
            source_label(&source.name),
            esc(match source_label(&source.name) { "Diagnostic finding" => "Observation result and derivation", "Evidence applicability check" => "Applicability of admitted evidence", "Permission receipt" => "Permission consumed before this check", _ => "Exact owner artifact" }),
            esc(&source.name),
            esc(&compact_identity(&source.digest)),
            raw("Exact owner artifact", &source.value)
        );
    }
    let authority_count = item
        .sources
        .iter()
        .filter(|value| value.name.ends_with(".standing.json"))
        .count();
    let draft = item
        .handoff
        .get("draft_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let preparation_url = format!(
        "{}/drafts/{}/investigation",
        design_url.trim_end_matches('/'),
        draft
    );
    let overall = if state == "completed" {
        format!("Diagnostic completed. {}.", summary_parts.join("; "))
    } else {
        format!("Investigation state: {state}.")
    };
    let accepted = item
        .submission
        .as_ref()
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("not recorded");
    let updated = item
        .state
        .get("updated_at")
        .and_then(Value::as_str)
        .map_or_else(|| "time unavailable".into(), display_time);
    page(
        label,
        &format!(
            "<span class=eyebrow>Findings / retained investigation</span><h1>{}</h1><p class=lede>Understand what the diagnostic established, what remains unanswered, and where its exact record lives.</p><div class=summary><strong>{}</strong><p class=nonclaim>These are independent bounded observations. No aggregate service-health verdict was produced.</p></div><section class=status-grid aria-label=Investigation status><div class=status-cell><span class=label>Submission</span><strong>Investigation {}</strong></div><div class=status-cell><span class=label>Diagnostic lifecycle</span><strong>{}</strong></div><div class=status-cell><span class=label>Last observed</span><strong>{}</strong></div></section><div class=record-actions><a class=button href=\"{}\">Review diagnostic plan</a><a href=#record>Investigation record</a></div><div class=layout><div><section class=panel><span class=eyebrow>Explanation and observations</span><h2>What the checks found</h2>{}</section><section class=panel id=record><span class=eyebrow>Accountable record</span><h2>Investigation record</h2><p>The diagnostic retained {} permission record(s) for {} observation(s). Exact identities remain available below.</p><div class=timeline><div><strong>Investigation accepted</strong>{}</div><div><strong>Diagnostic {}</strong>{}</div></div>{}{}{}</section></div><aside><section class=panel><span class=eyebrow>Supporting evidence</span><h2>Evidence and permission records</h2><div class=evidence-list>{}</div></section></aside></div>",
            esc(label), esc(&overall), esc(accepted), esc(state), esc(&updated), esc(&preparation_url), findings, authority_count, finding_values.map_or(0, |values| values.len()), esc(item.submission.as_ref().and_then(|value| value.get("run_id")).and_then(Value::as_str).unwrap_or("run identity unavailable")), esc(state), esc(&updated), item.record.as_ref().map_or_else(String::new, |record| raw("Exact investigation record", record)), raw("Exact plan handoff", &item.handoff), raw("Exact lifecycle state", &item.state), custody
        ),
        design_url,
        "findings",
        label,
    )
}

/// Render the same semantic projection for an exact terminal capability profile.
///
/// # Errors
///
/// Returns an error if the terminal backend cannot be created or drawn.
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
        let columns = if width >= 120 { Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(28), Constraint::Percentage(44), Constraint::Percentage(28)]).split(areas[1]) } else { Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(34), Constraint::Percentage(40), Constraint::Percentage(26)]).split(areas[1]) };
        let line = if ascii { "---" } else { "───" };
        let state = item.state.get("state").and_then(Value::as_str).unwrap_or("unknown");
        let label = item.handoff.pointer("/profile/subject_label").and_then(Value::as_str).unwrap_or("unnamed subject");
        let border = if monochrome { Style::default() } else { Style::default().fg(Color::DarkGray) };
        let header = if width < 90 {
            format!("state:{state}")
        } else {
            format!("subject:{label}  state:{state}")
        };
        frame.render_widget(Paragraph::new(Line::from(vec![Span::styled(" NIGHTSHIFT / PHOSPHOR-NG ", Style::default().add_modifier(Modifier::BOLD)), Span::raw(header)])).block(Block::default().borders(Borders::ALL).border_style(border)), areas[0]);
        frame.render_widget(Paragraph::new(format!("SUBJECT RAIL\n{} Standing boundary\n{line} {label}\n{line} revision\n{line} Nightshift {state}", if ascii { "|-" } else { "├─" })).wrap(Wrap { trim: false }).block(Block::default().title(" OPERATIONS ").borders(Borders::ALL)), columns[0]);
        let reason = item.record.as_ref().and_then(|v| v.get("findings")).and_then(Value::as_array).map_or_else(|| format!("findings {line}\u{2574}\nunknown / open edge"), |v| v.iter().map(|x| format!("{}  {}", x.get("profile").and_then(Value::as_str).unwrap_or("unknown"), x.pointer("/outcome/condition").and_then(Value::as_str).unwrap_or("unknown"))).collect::<Vec<_>>().join("\n"));
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

#[derive(Clone, Debug, Default)]
struct TuiState {
    plane: usize,
    focus: usize,
    expanded: bool,
    searching: bool,
    query: String,
    notice: String,
}

fn apply_key(state: &mut TuiState, key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press {
        return true;
    }
    if state.searching {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => state.searching = false,
            KeyCode::Backspace => {
                state.query.pop();
            }
            KeyCode::Char(value) => state.query.push(value),
            _ => {}
        }
        return true;
    }
    match key.code {
        KeyCode::Char('q') => return false,
        KeyCode::Char('1') => state.plane = 0,
        KeyCode::Char('2') => state.plane = 1,
        KeyCode::Char('3') => state.plane = 2,
        KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') => {
            state.focus = state.focus.saturating_add(1);
        }
        KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') => {
            state.focus = state.focus.saturating_sub(1);
        }
        KeyCode::Enter | KeyCode::Char(' ') => state.expanded = !state.expanded,
        KeyCode::Char('t') => {
            state.notice = "provenance trace remains within exact retained owner artifacts".into();
        }
        KeyCode::Char('c' | '[' | ']') => {
            state.notice =
                "comparison unavailable: this occurrence exposes no admitted generation relation"
                    .into();
        }
        KeyCode::Char('/') => {
            state.searching = true;
            state.query.clear();
        }
        KeyCode::Esc => {
            state.expanded = false;
            state.notice.clear();
        }
        KeyCode::Left | KeyCode::Char('h') => state.plane = state.plane.saturating_sub(1),
        KeyCode::Right | KeyCode::Char('l') => state.plane = (state.plane + 1).min(2),
        _ => {}
    }
    true
}

fn plane_text(item: &InvestigationProjectionV1, state: &TuiState) -> String {
    let status = item
        .state
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut text = match state.plane {
        0 => format!(
            "SUBJECT RAIL\n|- {}\n|- plan revision {}\n|- Nightshift {}\n\nAUTHORITY\nacquisition -----| Standing admission required",
            item.handoff
                .pointer("/profile/subject_label")
                .and_then(Value::as_str)
                .unwrap_or("unnamed subject"),
            item.handoff
                .get("revision_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            status
        ),
        1 => item
            .record
            .as_ref()
            .and_then(|value| value.get("findings"))
            .and_then(Value::as_array)
            .map_or_else(
                || "EXPECTED FINDINGS --------.\nunknown / open edge".into(),
                |findings| {
                    findings
                        .iter()
                        .map(|finding| {
                            format!(
                                "|- {}\n   condition: {}",
                                finding
                                    .get("profile")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown profile"),
                                finding
                                    .pointer("/outcome/condition")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                },
            ),
        _ => format!(
            "RECEIPT BLOCKS\nretained sources: {}\nterminal record: {}\noccurrence: {}",
            item.sources.len(),
            if item.record.is_some() {
                "retained"
            } else {
                "absent"
            },
            item.occurrence_path
        ),
    };
    if state.expanded {
        let exact = match state.plane {
            0 => &item.state,
            1 => item.record.as_ref().unwrap_or(&item.state),
            _ => &item.handoff,
        };
        text.push_str("\n\nEXACT MATERIAL\n");
        text.push_str(&serde_json::to_string_pretty(exact).unwrap_or_default());
    }
    if !state.query.is_empty() {
        let found = text.to_lowercase().contains(&state.query.to_lowercase());
        let _ = write!(
            text,
            "\n\nsearch /{}  {}",
            state.query,
            if found { "match" } else { "no match" }
        );
    }
    text
}

/// Run the read-only terminal inspector. All keys change presentation only.
///
/// # Errors
///
/// Returns an error when raw-mode setup, terminal drawing, or event reads fail.
pub fn run_tui(
    item: &InvestigationProjectionV1,
    ascii: bool,
    monochrome: bool,
) -> Result<(), String> {
    enable_raw_mode().map_err(|error| error.to_string())?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|error| error.to_string())?;
    let result = (|| {
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
        let mut state = TuiState::default();
        loop {
            terminal.draw(|frame| {
                let area = frame.area();
                let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(8), Constraint::Length(3)]).split(area);
                let label = item.handoff.pointer("/profile/subject_label").and_then(Value::as_str).unwrap_or("unnamed subject");
                frame.render_widget(Paragraph::new(format!(" NIGHTSHIFT / PHOSPHOR-NG  subject:{label}")).block(Block::default().borders(Borders::ALL)), rows[0]);
                let titles = [" OPERATIONS ", " REASONING ", " CUSTODY "];
                let body = plane_text(item, &state);
                frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }).block(Block::default().title(titles[state.plane]).borders(Borders::ALL).border_style(if monochrome { Style::default() } else { Style::default().fg(Color::DarkGray) })), rows[1]);
                let edge = if ascii { "-----|" } else { "─────⊣" };
                let footer = if state.searching { format!("search /{}   enter accept   esc cancel", state.query) } else { format!("1/2/3 plane  arrows/hjkl focus  enter/space decompose  t trace  c compare({edge})  / search  q quit  {}", state.notice) };
                frame.render_widget(Paragraph::new(footer).block(Block::default().borders(Borders::ALL)), rows[2]);
            }).map_err(|error| error.to_string())?;
            let Event::Key(key) = event::read().map_err(|error| error.to_string())? else {
                continue;
            };
            if !apply_key(&mut state, key) {
                break;
            }
        }
        Ok(())
    })();
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
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
        assert!(browser.contains("No aggregate service-health verdict"));
        assert!(browser.contains("Service-manager policy mismatch observed"));
        assert!(browser.contains("Permission consumed before this check"));
        assert!(style().contains("overflow-wrap:anywhere"));
        let wide = render_terminal(&loaded, 140, 40, false, false).unwrap();
        assert!(wide.contains("OPERATIONS") && wide.contains("REASONING"));
        let narrow = render_terminal(&loaded, 80, 24, true, true).unwrap();
        assert!(narrow.contains("state:completed"));
        assert!(narrow.contains("Standing boundary") && narrow.contains("no aggregate verdict"));
        let serial = render_terminal(&loaded, 79, 24, true, true).unwrap();
        assert!(serial.contains("state:completed"));
        assert!(serial.contains("Standing boundary") && serial.contains("no aggregate verdict"));
    }

    #[test]
    fn terminal_keys_change_presentation_only_and_expose_unavailable_comparison() {
        let mut state = TuiState::default();
        assert!(apply_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE)
        ));
        assert_eq!(state.plane, 1);
        assert!(apply_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
        ));
        assert!(state.expanded);
        assert!(apply_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE)
        ));
        assert!(state.notice.contains("unavailable"));
        assert!(!apply_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)
        ));
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
