//! Dense server-rendered views over the typed canonical read model.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use ag_campaign::governed::{OccurrenceSnapshotV1, ProgramCounterV1};
use ag_primitives::Digest;
use serde::Serialize;
use serde_json::Value;

use crate::links::GovernedRuntimeLinkV1;
use crate::model::{
    AgInspectV1, CampaignDetailV1, CampaignIndexEntryV1, CampaignIndexV1, DocketInspectionV1,
    DocketRecordStatusV1, ProjectionCorrespondenceV1, RelatedSourceV1, SourceResultV1,
};
use crate::source::selected_snapshot;

const MAX_RENDERED_TRANSITIONS: usize = 500;

/// Shared stylesheet for the local operator console.
pub const STYLE: &str = r#"
.campaign>div{min-width:0;overflow-wrap:anywhere}.campaign .k,.campaign .pc{max-width:100%;overflow-wrap:anywhere;word-break:break-word}.campaign .identity a{display:block;overflow-wrap:anywhere;text-decoration:none}.campaign-source{display:block;font:650 .88rem/1.35 ui-sans-serif,system-ui;text-decoration:underline;text-underline-offset:.18em}.campaign-digest{display:block;margin-top:.16rem;color:var(--muted);font-size:.72rem;font-weight:500}.projection-findings{padding:.6rem .7rem}.projection-findings:empty{display:none}.facts{margin:.65rem 0;padding-left:1.25rem}.facts li{margin:.3rem 0;overflow-wrap:anywhere}
:root{color-scheme:dark;--bg:#090d12;--surface:#0e141b;--panel:#121a23;--raised:#18222d;--line:#2a3745;--text:#e7edf4;--muted:#95a5b6;--fact:#86d4c8;--projection:#9abdf5;--unknown:#f1c76f;--bad:#ff9b9b;--accent:#c8a7f6;--focus:#72b7ff;--spent:#ff8c79}*{box-sizing:border-box}html{scroll-padding-top:5.5rem}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.48 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}a{color:#9dccff;text-underline-offset:.18em}a:hover{color:#c8e2ff}a:focus-visible,summary:focus-visible{outline:2px solid var(--focus);outline-offset:3px;border-radius:2px}.skip{position:absolute;left:-10000px}.skip:focus{left:.8rem;top:.7rem;z-index:20;background:var(--raised);padding:.5rem}.topbar{position:sticky;top:0;z-index:10;display:flex;gap:1rem;align-items:center;padding:.72rem 1.15rem;background:#0b1017f2;border-bottom:1px solid var(--line);backdrop-filter:blur(8px)}.topbar a{color:var(--text);text-decoration:none}.topbar .mode{margin-left:auto;color:var(--muted);font-size:.78rem}main{max-width:1520px;margin:auto;padding:1.1rem 1.25rem 5rem}h1,h2,h3{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}h1{font-size:1.42rem;line-height:1.25;margin:.2rem 0 .35rem;overflow-wrap:anywhere}h2{font-size:1rem;line-height:1.3;margin:0 0 .72rem;color:#f4f7fa}h3{font-size:.88rem;line-height:1.3;margin:1rem 0 .48rem}.lede{max-width:85rem;color:var(--muted);margin:.25rem 0 1rem}.eyebrow{font:700 .7rem/1.2 ui-monospace,SFMono-Regular,monospace;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:.75rem;margin:.75rem 0}.panel{grid-column:span 6;background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:.9rem;min-width:0}.panel.wide,.wide{grid-column:1/-1}.panel.third{grid-column:span 4}.panel.attention{border-color:#795c2d;background:#201a11}.panel.danger{border-color:#804542;background:#231414;box-shadow:inset 3px 0 0 var(--spent)}.panel.unknown-outcome{border-color:#8d6632;background:#241b10;box-shadow:inset 3px 0 0 var(--unknown)}.panel.terminal{border-color:#495766;background:#111820}.summary-strip{display:grid;grid-template-columns:minmax(16rem,1.5fr) minmax(12rem,1fr) minmax(17rem,1.5fr);gap:.7rem;margin:.85rem 0}.summary-cell{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:.85rem;min-width:0}.summary-cell strong{display:block;font:650 1.02rem/1.35 ui-sans-serif,system-ui;overflow-wrap:anywhere}.summary-cell .k{display:block;overflow-wrap:anywhere}.summary-cell.emphasis{border-color:#775a2b;background:#1e1810}.summary-cell.danger{border-color:#88443e;background:#241313}.kv{display:grid;grid-template-columns:minmax(9.5rem,13rem) minmax(0,1fr);gap:.34rem .8rem}.k{color:var(--muted)}.v{overflow-wrap:anywhere}.fact,.projection,.unknown,.error,.spent,.terminal-badge{display:inline-block;border-radius:999px;padding:.11rem .48rem;font-size:.68rem;font-weight:750;text-transform:uppercase;letter-spacing:.055em;vertical-align:middle}.fact{color:var(--fact);border:1px solid #356b64}.projection{color:var(--projection);border:1px solid #3b587b}.unknown{color:var(--unknown);border:1px solid #715d31}.error{color:var(--bad);border:1px solid #804949}.spent{color:#ffb2a6;border:1px solid #934c43;background:#321815}.terminal-badge{color:#c0cad5;border:1px solid #526172}.pc{font:650 1rem/1.3 ui-sans-serif,system-ui;color:var(--accent);overflow-wrap:anywhere}.localnav,.filters,.occurrence-jumps{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin:.75rem 0}.localnav a,.filters a,.occurrence-jumps a{display:inline-block;padding:.3rem .55rem;border:1px solid var(--line);border-radius:5px;background:var(--surface);text-decoration:none;font-size:.78rem}.filters a[aria-current=true]{border-color:var(--accent);color:var(--text);background:#241b32}.index-head{display:grid;grid-template-columns:minmax(20rem,2fr) minmax(13rem,1.05fr) minmax(16rem,1.25fr) minmax(14rem,1.1fr);gap:.85rem;padding:.55rem .72rem;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--line)}.campaign-list{background:var(--panel);border:1px solid var(--line);border-radius:7px;overflow:hidden}.campaign{display:grid;grid-template-columns:minmax(20rem,2fr) minmax(13rem,1.05fr) minmax(16rem,1.25fr) minmax(14rem,1.1fr);gap:.85rem;padding:.72rem;border-top:1px solid var(--line);min-width:0}.campaign:first-of-type{border-top:0}.campaign:hover{background:var(--raised)}.campaign .identity{min-width:0}.campaign .identity a{font-family:ui-sans-serif,system-ui;font-weight:650}.campaign .identity .v{font-size:.78rem;color:#bac6d2}.attention-line{margin-top:.35rem}.timeline{list-style:none;padding:0;margin:.2rem 0 0}.occurrence-boundary{display:flex;align-items:center;gap:.65rem;margin:1.15rem 0 .8rem;color:var(--text);font:700 .78rem/1.2 ui-sans-serif,system-ui;text-transform:uppercase;letter-spacing:.06em}.occurrence-boundary:after{content:"";height:1px;background:var(--line);flex:1}.event{position:relative;margin-left:.65rem;padding:0 0 1.05rem 1.55rem;border-left:2px solid #344554;min-width:0}.event:before{content:"";position:absolute;left:-6px;top:.25rem;width:10px;height:10px;border-radius:50%;background:#73869a}.event.current{border-left-color:var(--accent)}.event.current:before{background:var(--accent);box-shadow:0 0 0 4px #c8a7f624}.event.unknown-step:before{background:var(--unknown)}.event.danger-step:before{background:var(--spent)}.event.terminal-step:before{background:#9ba9b7}.event-title{display:flex;gap:.58rem;align-items:baseline;flex-wrap:wrap}.event-title strong{font-family:ui-sans-serif,system-ui}.seq{color:var(--muted)}details{margin-top:.55rem;border-radius:4px}summary{cursor:pointer;color:#b5d4f7;width:fit-content}.raw{margin-top:.6rem;border:1px solid #26313c;background:#090c10;border-radius:6px;overflow:hidden}.raw summary{width:auto;padding:.55rem .7rem;background:#101720}.raw-meta{color:var(--muted);font-size:.75rem}.schema{color:var(--projection)}pre{white-space:pre;overflow:auto;max-height:36rem;margin:0;padding:.75rem;background:#080b0f;color:#d0dae4;font:12px/1.48 ui-monospace,SFMono-Regular,Menlo,monospace;tab-size:2}.source-error{border:1px solid #754043;border-left:4px solid var(--bad);border-radius:5px;padding:.65rem;margin:.6rem 0;background:#211214}.source-error pre{white-space:pre-wrap}.finding{color:var(--muted);margin:.25rem 0;overflow-wrap:anywhere}.residual{padding:.48rem 0;border-top:1px dotted var(--line)}.empty{color:var(--muted);font-style:italic}.mono{font-family:ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}.note{padding:.55rem .68rem;border-left:3px solid var(--projection);background:#111a24;color:#cbd5df}.count{color:var(--muted);font-size:.78rem}.visually-hidden{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}@media(max-width:1050px){.index-head{display:none}.campaign{grid-template-columns:minmax(17rem,1.4fr) minmax(12rem,1fr)}.panel.third{grid-column:span 6}.summary-strip{grid-template-columns:1fr 1fr}.summary-cell:last-child{grid-column:1/-1}}@media(max-width:920px){.panel,.panel.third{grid-column:1/-1}}@media(max-width:720px){html{scroll-padding-top:1rem}.topbar{position:static;align-items:flex-start;flex-wrap:wrap}.topbar .mode{width:100%;margin:0}.campaign,.summary-strip,.kv{grid-template-columns:1fr}main{padding:.85rem .75rem 4rem}.campaign{gap:.55rem}.event{margin-left:.35rem;padding-left:1.2rem}.localnav{position:static}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}@media print{.topbar,.filters,.localnav{display:none}body{background:#fff;color:#111}.panel,.campaign-list{border-color:#bbb;background:#fff}pre{color:#111;background:#f6f6f6}.fact,.projection,.unknown,.error,.spent{color:#111;border-color:#777}}
"#;

/// Renders the campaign index from independently captured canonical facts.
#[must_use]
pub fn campaign_index(model: &CampaignIndexV1) -> String {
    campaign_index_with_context(model, "canonical source", "")
}

/// Renders a filterable index while retaining exact canonical classifications.
#[must_use]
pub fn campaign_index_with_context(
    model: &CampaignIndexV1,
    source_mode: &str,
    query: &str,
) -> String {
    let view = IndexViewV1::parse(query);
    let sort = IndexSortV1::parse(query);
    let mut entries = model
        .campaigns
        .iter()
        .filter(|entry| view.includes(entry))
        .collect::<Vec<_>>();
    match sort {
        IndexSortV1::Recent => entries.sort_by_key(|entry| std::cmp::Reverse(last_sequence(entry))),
        IndexSortV1::Campaign => entries.sort_by_key(|entry| campaign_sort_key(entry)),
        IndexSortV1::ProgramCounter => entries.sort_by_key(|entry| {
            entry.inspect.value().map_or_else(
                || "unknown".to_owned(),
                |value| format!("{:?}", value.current.program_counter()),
            )
        }),
    }
    let mut body = String::new();
    let _ = write!(
        body,
        "<div class=eyebrow>Phosphor-ng / governed-runtime inspector</div><h1>Governed campaigns</h1><p class=lede><span class=projection>read-only view</span> {}. Open a campaign to see its current run, what each owner recorded, what is missing, and where to inspect the supporting records. This page does not calculate an overall health result.</p>",
        escape(source_mode)
    );
    index_controls(&mut body, view, sort, model.campaigns.len(), entries.len());
    body.push_str("<section class=campaign-list aria-label=\"Campaign records\"><div class=index-head><span>Campaign source / identity / run</span><span>Current step</span><span>What is needed now</span><span>Last recorded fact</span></div>");
    if entries.is_empty() {
        body.push_str("<p class=empty>No campaign stores were found in the configured root.</p>");
    }
    for entry in entries {
        body.push_str("<article class=campaign>");
        if let Some(inspect) = entry.inspect.value() {
            let link = if source_mode == "deterministic demo corpus" {
                format!("/campaign/{}", entry.locator_token)
            } else {
                snapshot_link(&inspect.current, false).relative_path()
            };
            let campaign = inspect.current.key().campaign.as_str();
            let source_label = campaign_source_label(&entry.locator);
            let _ = write!(
                body,
                "<div class=identity><a href=\"{}\" title=\"Campaign {} · store {}\" aria-label=\"Campaign {}; store {}\"><span class=campaign-source>{}</span><code class=campaign-digest aria-hidden=true>{}</code></a><div class=k>run {}</div></div><div><span class=pc>{}</span><div class=k>{}</div></div><div>{}</div>",
                escape(&link),
                escape(campaign),
                escape(&entry.locator),
                escape(campaign),
                escape(&entry.locator),
                escape(source_label),
                escape(&compact_campaign_identity(campaign)),
                escape(&inspect.current.key().occurrence.to_string()),
                pc(inspect.current.program_counter()),
                terminal_label(&inspect.current),
                immediate_condition(&inspect.current)
            );
        } else {
            let _ = write!(
                body,
                "<div class=identity><a href=\"/campaign/{}\">{}</a><div class=unknown>unknown</div></div><div>AG record unavailable</div><div><span class=unknown>unavailable</span> the current run cannot be displayed; open the campaign for source diagnostics</div>",
                escape(&entry.locator_token),
                escape(&entry.locator)
            );
        }
        let last = entry
            .history
            .value()
            .and_then(|value| value.transitions.last());
        if let Some(last) = last {
            let _ = write!(
                body,
                "<div><span class=fact>persisted fact</span><div>{:?}</div><div class=k>sequence {} · recorded {}</div>",
                last.kind, last.sequence, last.recorded_at_unix_ms
            );
            if let Some(refusal) = entry
                .refusals
                .value()
                .and_then(|value| value.refusals.last())
            {
                let _ = write!(
                    body,
                    "<div><span class=error>refusal</span> {:?}</div>",
                    refusal.outcome.code
                );
            }
            body.push_str("</div>");
        } else {
            body.push_str("<div><span class=unknown>unknown</span><div>last recorded transition unavailable</div></div>");
        }
        body.push_str("</article>");
    }
    body.push_str("</section>");
    page_with_mode("Campaign index", &body, source_mode)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IndexViewV1 {
    All,
    Active,
    Reconciliation,
    Human,
    Terminal,
    SourceProblem,
}

impl IndexViewV1 {
    fn parse(query: &str) -> Self {
        match query_value(query, "view") {
            Some("active") => Self::Active,
            Some("reconciliation") => Self::Reconciliation,
            Some("human") => Self::Human,
            Some("terminal") => Self::Terminal,
            Some("source-problem") => Self::SourceProblem,
            _ => Self::All,
        }
    }

    fn includes(self, entry: &CampaignIndexEntryV1) -> bool {
        let current = entry.inspect.value().map(|value| &value.current);
        match self {
            Self::All => true,
            Self::Active => current.is_some_and(|value| {
                !matches!(
                    value.program_counter(),
                    ProgramCounterV1::Halted | ProgramCounterV1::Completed
                )
            }),
            Self::Reconciliation => current.is_some_and(|value| {
                value.program_counter() == ProgramCounterV1::ReconciliationRequired
            }),
            Self::Human => {
                current.is_some_and(|value| value.halted().is_some())
                    && entry.refusals.value().is_some_and(|value| {
                        value.refusals.iter().any(|refusal| {
                            refusal.outcome.code
                                == ag_campaign::governed::RefusalCodeV1::HumanDecisionRequired
                        })
                    })
            }
            Self::Terminal => current.is_some_and(|value| {
                matches!(
                    value.program_counter(),
                    ProgramCounterV1::Halted | ProgramCounterV1::Completed
                )
            }),
            Self::SourceProblem => {
                entry.projection.correspondence != ProjectionCorrespondenceV1::Exact
            }
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Active => "active",
            Self::Reconciliation => "reconciliation",
            Self::Human => "human",
            Self::Terminal => "terminal",
            Self::SourceProblem => "source-problem",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IndexSortV1 {
    Recent,
    Campaign,
    ProgramCounter,
}

impl IndexSortV1 {
    fn parse(query: &str) -> Self {
        match query_value(query, "sort") {
            Some("campaign") => Self::Campaign,
            Some("state") => Self::ProgramCounter,
            _ => Self::Recent,
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::Recent => "recent",
            Self::Campaign => "campaign",
            Self::ProgramCounter => "state",
        }
    }
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (candidate, value) = part.split_once('=')?;
        (candidate == key).then_some(value)
    })
}

fn index_controls(
    body: &mut String,
    view: IndexViewV1,
    sort: IndexSortV1,
    total: usize,
    shown: usize,
) {
    let mut views = String::new();
    for (candidate, label) in [
        (IndexViewV1::All, "all"),
        (IndexViewV1::Active, "nonterminal"),
        (IndexViewV1::Reconciliation, "reconciliation"),
        (IndexViewV1::Human, "human required"),
        (IndexViewV1::Terminal, "terminal"),
        (IndexViewV1::SourceProblem, "source problem"),
    ] {
        let current = if candidate == view {
            " aria-current=true"
        } else {
            ""
        };
        let _ = write!(
            views,
            "<a href=\"/?view={}&amp;sort={}\"{current}>{label}</a>",
            candidate.key(),
            sort.key()
        );
    }
    let mut sorts = String::new();
    for (candidate, label) in [
        (IndexSortV1::Recent, "recent transition"),
        (IndexSortV1::Campaign, "campaign identity"),
        (IndexSortV1::ProgramCounter, "current step"),
    ] {
        let current = if candidate == sort {
            " aria-current=true"
        } else {
            ""
        };
        let _ = write!(
            sorts,
            "<a href=\"/?view={}&amp;sort={}\"{current}>{label}</a>",
            view.key(),
            candidate.key()
        );
    }
    let _ = write!(
        body,
        "<nav class=filters aria-label=\"Campaign filters\"><span class=eyebrow>Show</span>{views}</nav><nav class=filters aria-label=\"Campaign ordering\"><span class=eyebrow>Order</span>{sorts}<span class=count>showing {shown} of {total}</span></nav>"
    );
}

fn last_sequence(entry: &CampaignIndexEntryV1) -> u64 {
    entry
        .history
        .value()
        .and_then(|value| value.transitions.last())
        .map_or(0, |transition| transition.recorded_at_unix_ms)
}

fn campaign_sort_key(entry: &CampaignIndexEntryV1) -> String {
    entry.inspect.value().map_or_else(
        || entry.locator.clone(),
        |value| value.current.key().campaign.as_str().to_owned(),
    )
}

/// Renders one end-to-end campaign/occurrence inspection.
#[must_use]
pub fn campaign_detail(model: &CampaignDetailV1) -> String {
    campaign_detail_with_context(model, "canonical source")
}

/// Renders one campaign with a visible source-mode boundary.
#[must_use]
pub fn campaign_detail_with_context(model: &CampaignDetailV1, source_mode: &str) -> String {
    campaign_detail_selection(model, source_mode, None)
}

/// Renders the exact historical or current occurrence selected by a semantic
/// Phosphor-ng link.
#[must_use]
pub fn campaign_detail_for_link_with_context(
    model: &CampaignDetailV1,
    source_mode: &str,
    link: &GovernedRuntimeLinkV1,
) -> String {
    campaign_detail_selection(model, source_mode, Some(link))
}

fn campaign_detail_selection(
    model: &CampaignDetailV1,
    source_mode: &str,
    link: Option<&GovernedRuntimeLinkV1>,
) -> String {
    let mut body = String::new();
    let canonical_title = model.inspect.value().map_or_else(
        || model.locator.clone(),
        |value| value.current.key().campaign.to_string(),
    );
    let title = campaign_source_label(&model.locator);
    let _ = write!(
        body,
        "<div class=eyebrow>Phosphor-ng / governed runtime / selected case</div><h1>{}</h1><p class=lede><span class=projection>projection</span> Campaign <code title=\"{}\">{}</code> · source {}. Independently captured owner sources remain separate; semantic links carry identities, never authority.</p>",
        escape(title),
        escape(&canonical_title),
        escape(&compact_campaign_identity(&canonical_title)),
        escape(&model.locator)
    );
    if let Some(inspect) = model.inspect.value() {
        let selected = link
            .and_then(|value| selected_snapshot(model, value))
            .unwrap_or(&inspect.current);
        let selected_is_current = selected.state_digest() == inspect.current.state_digest();
        if link.is_some() && !selected_is_current {
            let current_link = snapshot_link(&inspect.current, false).relative_path();
            let _ = write!(
                body,
                "<p class=note><span class=fact>historical run</span> This view shows run {} from the verified journal. The campaign's <a href=\"{}\">current run</a> is {}.</p>",
                escape(&selected.key().occurrence.to_string()),
                escape(&current_link),
                escape(&inspect.current.key().occurrence.to_string())
            );
        }
        quick_orientation(&mut body, selected, selected_is_current);
        local_navigation(&mut body);
        projection_panel(&mut body, model);
        overview(&mut body, inspect, selected, selected_is_current);
        authority(&mut body, selected);
        execution(&mut body, selected, &model.docket);
        timeline(&mut body, model, &inspect.current, selected);
        evidence(
            &mut body,
            selected,
            &model.nightshift,
            &model.authoring_contexts,
            &model.authoring_custody,
            &model.external_observations,
            &model.observation_acquisitions,
        );
        refusals(&mut body, &model.refusals);
        intervention_submissions(&mut body, model.intervention_submissions.as_ref());
    } else {
        body.push_str("<section class=panel critical><h2>AG campaign unavailable</h2><p>The authoritative campaign view cannot be rendered. Other source diagnostics and raw captures remain below.</p></section>");
    }
    raw_sources(&mut body, model);
    page_with_mode(&format!("{title} · governed case"), &body, source_mode)
}

fn quick_orientation(body: &mut String, current: &OccurrenceSnapshotV1, selected_is_current: bool) {
    let meta = current.state().meta();
    let class = match current.program_counter() {
        ProgramCounterV1::AuthorizationConsumed => " danger",
        ProgramCounterV1::Dispatched | ProgramCounterV1::ReconciliationRequired => " emphasis",
        _ => "",
    };
    let _ = write!(
        body,
        "<section class=summary-strip aria-label=\"Selected run summary\"><div class=summary-cell><span class=eyebrow>{}</span><strong>{}</strong><span class=k>{}</span></div><div class=summary-cell><span class=eyebrow>Current step</span><strong class=pc>{}</strong><span class=k>raw program counter · expected work {}</span></div><div class=\"summary-cell{}\"><span class=eyebrow>What is needed now</span><strong>{}</strong></div></section>",
        if selected_is_current {
            "Current run"
        } else {
            "Historical run"
        },
        escape(&current.key().occurrence.to_string()),
        escape(current.key().campaign.as_str()),
        pc(current.program_counter()),
        escape(meta.expected_work().as_str()),
        class,
        immediate_condition(current)
    );
}

fn local_navigation(body: &mut String) {
    body.push_str("<nav class=localnav aria-label=\"Read-only navigation\"><span class=eyebrow>Inspect this run</span><a href=#overview>summary and exact IDs</a><a href=#authority>standing and authority</a><a href=#execution>execution outcome</a><a href=#timeline>recorded history</a><a href=#evidence>evidence and proposal</a><a href=#refusals>refusals</a><a href=#intervention-submissions>submitted intent</a><a href=#raw>raw owner records</a></nav>");
}

fn refusals(
    body: &mut String,
    source: &SourceResultV1<ag_store::campaign::CampaignRefusalHistoryV1>,
) {
    body.push_str("<section id=refusals class=\"panel wide\"><h2>Durable refusals <span class=fact>non-authorizing facts</span></h2>");
    match source {
        SourceResultV1::Available { value, .. } if value.refusals.is_empty() => {
            body.push_str("<p class=empty>No durable refusal is recorded.</p>");
        }
        SourceResultV1::Available { value, .. } => {
            for refusal in &value.refusals {
                let _ = write!(
                    body,
                    "<article class=residual><div class=kv>{}{}{}{}{}{}</div>{}",
                    kv("refusal", refusal.refusal.as_str()),
                    kv("code", &format!("{:?}", refusal.outcome.code)),
                    kv("campaign", refusal.outcome.key.campaign.as_str()),
                    kv("run", &refusal.outcome.key.occurrence.to_string()),
                    kv("at state", refusal.outcome.at_state_digest.as_str()),
                    kv("recorded at", &refusal.recorded_at_unix_ms.to_string()),
                    raw_details("canonical refusal", refusal)
                );
                if let Some(verified) = &refusal.outcome.governed_intervention {
                    let _ = write!(
                        body,
                        "<p class=attention-line><span class=error>intervention refused</span> {} — authenticated intent created no transition or authority</p>",
                        intervention_summary(verified)
                    );
                }
                body.push_str("</article>");
            }
        }
        SourceResultV1::Unavailable { .. } => source_summary(body, source),
    }
    body.push_str("<p class=k>A refusal records why authority was not created; it is never an authorization.</p></section>");
}

fn intervention_submissions(
    body: &mut String,
    source: Option<&SourceResultV1<crate::model::InterventionSubmissionHistoryProjectionV1>>,
) {
    body.push_str("<section id=intervention-submissions class=\"panel wide\"><h2>Intervention submission custody <span class=projection>delivery is not authorization</span></h2>");
    match source {
        None => body.push_str("<p class=unknown>not recorded</p><p class=k>This campaign projection predates the canonical ingress receipt source.</p>"),
        Some(SourceResultV1::Available { value, .. }) if value.receipts.is_empty() => {
            body.push_str("<p class=empty>No authenticated intervention submission receipt is recorded.</p>");
        }
        Some(SourceResultV1::Available { value, .. }) => {
            for receipt in &value.receipts {
                let status = receipt.result.get("status").and_then(Value::as_str).unwrap_or("unknown");
                let _ = write!(
                    body,
                    "<article class=receipt><h3>{}</h3><div class=kv>{}{}{}{}{}{}</div>{}</article>",
                    escape(status),
                    kv("receipt", receipt.receipt.as_str()),
                    kv("submission", receipt.submission.as_ref().map_or("unknown", Digest::as_str)),
                    kv("request", receipt.request.as_ref().map_or("unknown", Digest::as_str)),
                    kv("submitter", receipt.submitting_principal.as_deref().unwrap_or("unknown")),
                    kv("target runtime", receipt.target_runtime_profile.as_ref().map_or("unknown", Digest::as_str)),
                    kv("recorded at", &receipt.recorded_at_unix_ms.to_string()),
                    raw_details("canonical ingress receipt", receipt),
                );
            }
        }
        Some(unavailable @ SourceResultV1::Unavailable { .. }) => {
            source_summary(body, unavailable);
        }
    }
    body.push_str("<p class=k>Received, governed accepted/refused, and outcome unknown are distinct owner facts. None is an AG authorization or execution receipt.</p></section>");
}

fn projection_panel(body: &mut String, model: &CampaignDetailV1) {
    projection_panel_for(
        body,
        model.projection.correspondence,
        &model.projection.findings,
    );
}

fn projection_panel_for(
    body: &mut String,
    correspondence: ProjectionCorrespondenceV1,
    findings: &[String],
) {
    let class = match correspondence {
        ProjectionCorrespondenceV1::Exact => "projection",
        ProjectionCorrespondenceV1::Partial => "unknown",
        ProjectionCorrespondenceV1::Disagreement => "error",
    };
    let _ = write!(
        body,
        "<details class=\"raw projection-evidence\"{}><summary>Projection correspondence <span class={class}>{:?}</span> <span class=raw-meta>exact owner-source comparison</span></summary><div class=projection-findings>",
        if correspondence == ProjectionCorrespondenceV1::Exact {
            ""
        } else {
            " open"
        },
        correspondence
    );
    for finding in findings {
        let _ = write!(body, "<p class=finding>{}</p>", escape(finding));
    }
    body.push_str("</div></details>");
}

fn overview(
    body: &mut String,
    inspect: &AgInspectV1,
    current: &OccurrenceSnapshotV1,
    selected_is_current: bool,
) {
    let meta = current.state().meta();
    let _ = write!(
        body,
        "<div id=overview class=grid><section class=panel><h2>{}</h2><div class=kv>{}{}{}{}{}</div></section><section class=panel><h2>Runtime and exact work</h2><div class=kv>{}{}{}{}{}</div></section><section class=panel><h2>Bounded continuation</h2><div class=kv>{}</div></section><section class=panel><h2>Residual work</h2>",
        if selected_is_current {
            "Authoritative coordinates"
        } else {
            "Selected historical coordinates"
        },
        kv("campaign", current.key().campaign.as_str()),
        kv("run", &current.key().occurrence.to_string()),
        kv(
            "raw program counter",
            &format!("{:?}", current.program_counter())
        ),
        kv("state digest", current.state_digest().as_str()),
        kv("terminal disposition", &terminal_label(current)),
        kv("profile schema", &inspect.runtime_profile.schema),
        kv("profile digest", inspect.runtime_profile.digest.as_str()),
        kv("program", meta.program().as_str()),
        kv("expected exact work", meta.expected_work().as_str()),
        kv(
            "consumed human decisions",
            &meta
                .used_human_decisions()
                .iter()
                .map(ag_campaign::governed::HumanDecisionIdV1::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        budget_html(meta.budget())
    );
    if meta.residuals().is_empty() {
        body.push_str("<p class=empty>Canonical residual set is empty.</p>");
    } else {
        for residual in meta.residuals().as_slice() {
            let _ = write!(
                body,
                "<div class=residual>{}{}{}</div>",
                kv("residual", residual.residual.as_str()),
                kv("owner", residual.owner.as_str()),
                kv("statement", residual.statement.as_str())
            );
        }
    }
    if let Some(prior) = current.prior_occurrence() {
        let _ = write!(
            body,
            "<h3>Previous run</h3><div class=kv>{}{}{}</div>",
            kv("run", &prior.key.occurrence.to_string()),
            kv("state digest", prior.state_digest.as_str()),
            kv(
                "prior proposal",
                prior
                    .proposal
                    .as_ref()
                    .map_or("unknown", |value| value.as_str())
            )
        );
    }
    body.push_str("</section></div>");
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear verified-journal rendering keeps occurrence boundaries and refusal adjacency visible"
)]
fn timeline(
    body: &mut String,
    model: &CampaignDetailV1,
    current: &OccurrenceSnapshotV1,
    selected: &OccurrenceSnapshotV1,
) {
    body.push_str(
        "<section id=timeline class=\"panel wide\"><h2>Governed transition timeline</h2>",
    );
    if let Some(history) = model.history.value() {
        let first_rendered = history
            .transitions
            .len()
            .saturating_sub(MAX_RENDERED_TRANSITIONS);
        let rendered = &history.transitions[first_rendered..];
        if first_rendered > 0 {
            let _ = write!(
                body,
                "<p class=note><span class=projection>bounded view</span> showing the most recent {} of {} verified transitions. The complete owner response remains under raw sources.</p>",
                rendered.len(),
                history.transitions.len()
            );
        }
        let occurrences = rendered
            .iter()
            .map(|transition| transition.successor.key().occurrence.to_string())
            .collect::<BTreeSet<_>>();
        body.push_str("<nav class=occurrence-jumps aria-label=\"Run jumps\"><span class=eyebrow>Runs</span>");
        for occurrence in &occurrences {
            let _ = write!(
                body,
                "<a href=\"#occurrence-{}\">{}</a>",
                escape(occurrence),
                escape(occurrence)
            );
        }
        body.push_str("</nav><p class=lede>The journal determines the order shown here. Missing transitions are left missing rather than guessed. Each run boundary marks a fresh governed continuation.</p><ol class=timeline>");
        let mut prior_occurrence: Option<String> = None;
        for transition in rendered {
            let is_current = transition.successor_state_digest == *current.state_digest();
            let is_selected = transition.successor_state_digest == *selected.state_digest();
            let occurrence = transition.successor.key().occurrence.to_string();
            if prior_occurrence.as_deref() != Some(occurrence.as_str()) {
                let predecessor = transition.successor.prior_occurrence();
                let occurrence_link = snapshot_link(&transition.successor, false).relative_path();
                let _ = write!(
                    body,
                    "<li id=\"occurrence-{}\" class=occurrence-boundary>Run {}{} <a href=\"{}\">open this exact run</a></li>",
                    escape(&occurrence),
                    escape(&occurrence),
                    predecessor.map_or_else(String::new, |prior| format!(
                        " <span class=k>successor of {}</span>",
                        escape(&prior.key.occurrence.to_string())
                    )),
                    escape(&occurrence_link)
                );
                prior_occurrence = Some(occurrence.clone());
            }
            let counter = transition.successor.program_counter();
            let current_attr = if is_current { " aria-current=step" } else { "" };
            let _ = write!(
                body,
                "<li id=transition-{} class=\"event{} {}\"{}><div class=event-title><a class=seq href=\"#transition-{}\">#{}</a><strong>{:?}</strong><span class=pc>{:?}</span><span class=fact>recorded fact</span>{}{}</div><div class=k>run {} · recorded {} · state {}</div>{}",
                transition.sequence,
                if is_current { " current" } else { "" },
                state_tone_class(counter),
                current_attr,
                transition.sequence,
                transition.sequence,
                transition.kind,
                counter,
                if is_current {
                    "<span class=projection>authoritative now</span>"
                } else {
                    ""
                },
                if is_selected && !is_current {
                    "<span class=fact>selected historical state</span>"
                } else {
                    ""
                },
                escape(&occurrence),
                transition.recorded_at_unix_ms,
                escape(transition.successor_state_digest.as_str()),
                raw_details("canonical transition", transition)
            );
            if let ag_store::campaign::CampaignTransitionEvidenceV1::GovernedIntervention {
                verified,
            } = &transition.evidence
            {
                let _ = write!(
                    body,
                    "<div class=attention-line><span class=projection>operator intent</span> {} — authenticated request evidence, not authorization</div>",
                    intervention_summary(verified)
                );
            }
            if let Some(refusals) = model.refusals.value() {
                for refusal in refusals.refusals.iter().filter(|refusal| {
                    refusal.outcome.at_state_digest == transition.successor_state_digest
                }) {
                    let _ = write!(
                        body,
                        "<div class=attention-line><span class=error>refusal</span> {:?} — no transition or authority was created</div>",
                        refusal.outcome.code
                    );
                }
            }
            body.push_str("</li>");
        }
        body.push_str("</ol>");
    } else {
        body.push_str("<p><span class=unknown>unknown</span> AG history unavailable; no timeline was reconstructed from current fields.</p>");
    }
    body.push_str("</section>");
}

fn intervention_summary(
    verified: &ag_campaign::governed::VerifiedGovernedInterventionV1,
) -> String {
    use ag_campaign::governed::GovernedInterventionClassV1 as I;
    let target = match &verified.request.intervention {
        I::ReconcileAttempt {
            issuance, attempt, ..
        } => format!("reconcile issuance {issuance} / attempt {attempt}"),
        I::RequestProbe {
            exact_probe_work, ..
        } => format!("request bounded read-only probe {exact_probe_work}"),
        I::OpenSuccessor {
            successor_occurrence,
            exact_work,
        } => format!("open successor run {successor_occurrence} for exact work {exact_work}"),
        I::HaltContinuation { reason } => format!("halt continuation: {reason}"),
    };
    format!(
        "{} · request {} · principal {} · target run {}",
        escape(&target),
        escape(verified.request.request.as_str()),
        escape(verified.request.principal.as_str()),
        escape(&verified.request.occurrence.to_string())
    )
}

fn evidence(
    body: &mut String,
    current: &OccurrenceSnapshotV1,
    nightshift: &[RelatedSourceV1<crate::model::NightshiftObservationExportV1>],
    authoring_contexts: &[RelatedSourceV1<crate::model::NightshiftAuthoringContextExportV1>],
    authoring_custody: &[RelatedSourceV1<crate::model::NightshiftAuthoringCustodyExportV1>],
    external_observations: &[RelatedSourceV1<crate::model::ExternalObservationExportV1>],
    observation_acquisitions: &[RelatedSourceV1<crate::model::AcquisitionHistoryV1>],
) {
    body.push_str(
        "<div id=evidence class=grid><section class=panel><h2>Evidence and proposal</h2>",
    );
    let observation = current.observation().or_else(|| {
        current
            .completed()
            .map(ag_campaign::governed::CompletedV1::terminal_observation)
    });
    if let Some(observation) = observation {
        let basis_rows = if let Some(basis) = observation.nightshift_basis() {
            kv(
                "basis atoms",
                &basis.atoms.iter().cloned().collect::<Vec<_>>().join(", "),
            )
        } else if let Some(basis) = observation.typed_basis() {
            format!(
                "{}{}",
                kv("basis type", &basis.basis_type),
                kv("basis identity", basis.basis_identity.as_str())
            )
        } else {
            String::new()
        };
        let _ = write!(
            body,
            "<h3>Observation <span class=fact>canonical projection</span></h3><div class=kv>{}{}{}{}{}{}{}{}</div>",
            kv("identity", observation.observation().as_str()),
            kv("status", observation.status_label()),
            kv("currentness", observation.currentness().as_str()),
            kv("resolver", observation.resolver_id()),
            kv(
                "resolved at",
                &observation.resolved_at_unix_ms().to_string()
            ),
            kv(
                "fresh until (exclusive)",
                &observation.fresh_until_unix_ms().to_string()
            ),
            kv(
                "basis digest",
                observation.normalized_preconditions().as_str()
            ),
            basis_rows
        );
    } else {
        body.push_str("<p><span class=unknown>unknown</span> No observation basis exists in this program-counter state.</p>");
    }
    if let Some(proposal) = current.proposal() {
        let permalink = snapshot_link(current, true).relative_path();
        let permalink_row = format!(
            "<div class=k>permanent record link</div><div class=v><a href=\"{}\">campaign + run + proposal</a></div>",
            escape(&permalink)
        );
        let _ = write!(
            body,
            "<h3>Exact-work proposal <span class=fact>canonical persisted fact</span></h3><div class=kv>{}{}{}{}{}{}{}{}</div>",
            kv("proposal", proposal.reference().as_str()),
            kv(
                "canonical run link",
                &current
                    .occurrence_link()
                    .map_or_else(|| "unknown".to_owned(), |value| format!("{value:?}")),
            ),
            kv("work schema", proposal.work_schema()),
            kv("work", proposal.work().as_str()),
            kv(
                "expected work",
                current.state().meta().expected_work().as_str()
            ),
            kv("subject", proposal.subject().as_str()),
            kv("scope", proposal.scope().as_str()),
            permalink_row
        );
        authoring_context(
            body,
            current,
            proposal.reference().as_str(),
            authoring_contexts,
            authoring_custody,
        );
    } else {
        body.push_str("<p class=empty>No proposal has been recorded for the selected state. No Maude authoring link can be constructed.</p>");
    }
    body.push_str("</section><section class=panel><h2>Nightshift provenance</h2>");
    external_observation(
        body,
        current,
        external_observations,
        observation_acquisitions,
        nightshift,
    );
    if nightshift.is_empty() {
        body.push_str("<p><span class=unknown>unknown</span> No observation lookup identity is available.</p>");
    }
    for related in nightshift {
        let _ = write!(body, "<h3>{}</h3>", escape(&related.identity));
        source_summary(body, &related.result);
    }
    body.push_str("<p class=k>Propagated NQ admission fields are displayed only inside Nightshift’s canonical raw record; this UI does not reinterpret admission.</p></section></div>");
}

fn external_observation(
    body: &mut String,
    current: &OccurrenceSnapshotV1,
    related: &[RelatedSourceV1<crate::model::ExternalObservationExportV1>],
    acquisitions: &[RelatedSourceV1<crate::model::AcquisitionHistoryV1>],
    nightshift: &[RelatedSourceV1<crate::model::NightshiftObservationExportV1>],
) {
    use crate::model::ExternalObservationEvidenceAgeV1;

    let selected_observation = current.observation().or_else(|| {
        current
            .completed()
            .map(ag_campaign::governed::CompletedV1::terminal_observation)
    });
    let composition = selected_observation.and_then(|resolution| {
        resolution.nightshift_basis()?;
        matching_external_composition(nightshift, resolution.observation().as_str())
    });
    let campaign = composition
        .and_then(|value| value.get("source_campaign_id"))
        .or_else(|| composition.and_then(|value| value.pointer("/qualification/campaign_id")))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| current.key().campaign.as_str());
    let occurrence = composition
        .and_then(|value| value.get("source_occurrence_id"))
        .or_else(|| composition.and_then(|value| value.pointer("/qualification/occurrence_id")))
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| current.key().occurrence.to_string(), str::to_owned);
    let identity = format!("{campaign}/{occurrence}");
    acquisition_history(body, &identity, acquisitions);
    let Some(source) = related.iter().find(|source| source.identity == identity) else {
        body.push_str("<p class=k><span class=unknown>application evidence unavailable</span> No exact Nightshift candidate lookup was captured for this run. Inspect raw owner records for source diagnostics.</p>");
        return;
    };
    let SourceResultV1::Available { value, .. } = &source.result else {
        body.push_str("<p class=k><span class=unknown>application evidence unavailable</span> The canonical Nightshift lookup failed; diagnostics remain in raw data.</p>");
        return;
    };
    let Some(item) = value.matches.first() else {
        body.push_str("<p class=k><span class=unknown>application evidence not recorded</span> No workflow-specific world-observation candidate is bound to this run.</p>");
        return;
    };
    let observation = &item.observation;
    let (selected_binding, selected_has_result_basis) =
        external_observation_binding(current, composition, observation, &item.custody);
    if !selected_binding {
        body.push_str("<p class=source-error><span class=error>application-evidence disagreement</span> Nightshift returned a candidate for this run whose proposal/work/issuance/attempt/settlement binding disagrees with the selected AG state. Inspect the raw Nightshift and AG records; no result is inferred.</p>");
        return;
    }
    let age = match item.evidence_age {
        ExternalObservationEvidenceAgeV1::FreshAtEvaluation => "inside display age window",
        ExternalObservationEvidenceAgeV1::StaleAtEvaluation => "outside display age window",
        ExternalObservationEvidenceAgeV1::NotYetObserved => "source time follows evaluation time",
    };
    let _ = write!(
        body,
        "<h3>Historical application/world evidence <span class=fact>custody authenticated</span></h3><p><strong>{:?}</strong> evidence for <strong>{:?}</strong>. <span class=k>Evidence age (display only): {}; evidence age is not currentness.</span></p><div class=kv>{}{}{}{}{}{}{}</div>",
        observation.action,
        observation.outcome,
        age,
        kv("candidate", &observation.observation_id),
        kv("custody", &item.custody.custody_id),
        kv("producer", &item.custody.producer_principal_id),
        kv("attempt", &observation.attempt_id),
        kv("settlement", &observation.settlement_id),
        kv("evidence receipt", &observation.executor_evidence_receipt),
        kv("observed at", &observation.observed_at_unix_ms.to_string()),
    );
    if let (Some(composition), Some(resolution)) = (composition, selected_observation) {
        external_composition(body, composition, resolution);
    } else {
        body.push_str("<p class=k><span class=unknown>not composed</span> This authenticated historical candidate is not the source of the selected canonical observation.</p>");
    }
    external_claims(body, observation);
    if !selected_has_result_basis {
        body.push_str("<p class=note>This historical snapshot does not expose the complete proposal/issuance/attempt/settlement set. The candidate remains scoped to this run. Its exact result IDs remain in the raw owner record and are not copied onto this snapshot.</p>");
    }
}

fn matching_external_composition<'a>(
    nightshift: &'a [RelatedSourceV1<crate::model::NightshiftObservationExportV1>],
    observation_id: &str,
) -> Option<&'a Value> {
    nightshift.iter().find_map(|source| {
        let SourceResultV1::Available { value, .. } = &source.result else {
            return None;
        };
        if value.observation_id != observation_id || value.matches.len() != 1 {
            return None;
        }
        let item = &value.matches[0];
        let schema = item.observation.get("schema").and_then(Value::as_str);
        if item
            .observation
            .get("observation_id")
            .and_then(Value::as_str)
            != Some(observation_id)
            || !matches!(
                schema,
                Some("nightshift.observation_record.v3" | "nightshift.observation_record.v4")
            )
        {
            return None;
        }
        item.observation
            .get("external_evidence")
            .or_else(|| item.observation.get("decision_external_evidence"))
    })
}

fn acquisition_history(
    body: &mut String,
    identity: &str,
    related: &[RelatedSourceV1<crate::model::AcquisitionHistoryV1>],
) {
    let Some(source) = related.iter().find(|source| source.identity == identity) else {
        body.push_str("<h3>Observation acquisition</h3><p class=k><span class=unknown>not configured</span> No exact Maude acquisition-history lookup was captured for this run.</p>");
        return;
    };
    let SourceResultV1::Available { value, .. } = &source.result else {
        body.push_str("<h3>Observation acquisition</h3><p class=k><span class=unknown>unavailable</span> The mechanics ledger could not be read. Nightshift evidence and currentness remain separate owner facts.</p>");
        return;
    };
    if value.acquisitions.is_empty() {
        body.push_str("<h3>Observation acquisition</h3><p class=k><span class=unknown>absent</span> No workflow-specific acquisition trigger is recorded for this exact run.</p>");
        return;
    }
    body.push_str(
        "<h3>Observation acquisition <span class=projection>mechanics provenance</span></h3>",
    );
    for acquisition in &value.acquisitions {
        let trigger = acquisition.get("trigger").unwrap_or(&Value::Null);
        let request = acquisition.get("request").unwrap_or(&Value::Null);
        let text = |object: &Value, field: &str| {
            object
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or("malformed owner projection")
                .to_owned()
        };
        let stages = acquisition
            .get("events")
            .and_then(Value::as_array)
            .map_or_else(
                || "malformed owner projection".to_owned(),
                |events| {
                    events
                        .iter()
                        .filter_map(|event| event.get("kind").and_then(Value::as_str))
                        .map(escape)
                        .collect::<Vec<_>>()
                        .join(" → ")
                },
            );
        let evidence = acquisition
            .pointer("/evidence/handoff/observation/observation_id")
            .and_then(Value::as_str)
            .unwrap_or("not durably acquired");
        let _ = write!(
            body,
            "<div class=kv>{}{}{}{}{}{}{}</div><p class=k>Stages: {}. Acquisition mechanics may cause observation; only Nightshift determines custody composition/currentness.</p>",
            kv("reason", &text(trigger, "reason")),
            kv("trigger", &text(trigger, "trigger_id")),
            kv("request", &text(request, "request_id")),
            kv("adapter", &text(trigger, "adapter_id")),
            kv("settlement", &text(trigger, "settlement_id")),
            kv("evidence candidate", evidence),
            kv("target runtime", &text(trigger, "target_runtime_id")),
            stages,
        );
    }
}

fn external_observation_binding(
    current: &OccurrenceSnapshotV1,
    composition: Option<&Value>,
    observation: &crate::model::ExternalObservationV1,
    custody: &crate::model::ExternalObservationCustodyV1,
) -> (bool, bool) {
    if let Some(composition) = composition {
        if let Some(qualification) = composition.get("qualification") {
            let exact = |field: &str, value: &str| {
                qualification.get(field).and_then(Value::as_str) == Some(value)
            };
            return (
                exact("source_observation_id", &observation.observation_id)
                    && exact("source_custody_id", &custody.custody_id)
                    && exact("campaign_id", &observation.campaign_id)
                    && exact("occurrence_id", &observation.occurrence_id)
                    && exact("proposal_id", &observation.proposal_id)
                    && exact("exact_work_id", &observation.exact_work_id)
                    && exact("issuance_id", &observation.issuance_id)
                    && exact("attempt_id", &observation.attempt_id)
                    && exact("settlement_id", &observation.settlement_id),
                true,
            );
        }
        let exact = |field: &str, value: &str| {
            composition.get(field).and_then(serde_json::Value::as_str) == Some(value)
        };
        return (
            exact("source_observation_id", &observation.observation_id)
                && exact("source_custody_id", &custody.custody_id)
                && exact("source_campaign_id", &observation.campaign_id)
                && exact("source_occurrence_id", &observation.occurrence_id)
                && exact("source_proposal_id", &observation.proposal_id)
                && exact("source_exact_work_id", &observation.exact_work_id)
                && exact("source_issuance_id", &observation.issuance_id)
                && exact("source_attempt_id", &observation.attempt_id)
                && exact("source_settlement_id", &observation.settlement_id),
            true,
        );
    }
    match (
        current.proposal(),
        current.issuance(),
        current.docket_custody(),
        current.settlement(),
    ) {
        (Some(proposal), Some(issuance), Some(custody), Some(settlement)) => (
            proposal.reference().as_str() == observation.proposal_id
                && proposal.work().as_str() == observation.exact_work_id
                && issuance.issuance.as_str() == observation.issuance_id
                && custody.attempt.as_str() == observation.attempt_id
                && settlement.settlement.as_str() == observation.settlement_id,
            true,
        ),
        _ => (true, false),
    }
}

fn external_composition(
    body: &mut String,
    composition: &Value,
    resolution: &ag_campaign::governed::VersionedObservationResolutionV1,
) {
    if let Some(qualification) = composition.get("qualification") {
        let q = |name: &str| {
            qualification
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or("malformed owner projection")
        };
        let scalar = |pointer: &str| {
            composition.pointer(pointer).map_or_else(
                || "malformed owner projection".to_owned(),
                |value| match value {
                    Value::Number(value) => value.to_string(),
                    Value::String(value) => value.clone(),
                    _ => "malformed owner projection".to_owned(),
                },
            )
        };
        let _ = write!(
            body,
            "<h3>Decision-relative evidence <span class=fact>qualification + passive observation</span></h3><p><strong>Historical qualification</strong> records the governed fault test that occurred for the exact artifact. <strong>Current steady-state</strong> records what the passive adapter learned by looking again. No new failure test was performed.</p><div class=kv>{}{}{}{}{}{}{}{}{}{}{}{}{}</div><p class=k>The target PlanDocument label is an owner-established exact match, not a UI inference. Re-observation refreshes only the passive component. Qualification applicability uses exact PlanDocument, compilation, work, subject, and scope identity; its acquisition time is not relabelled as present-world currentness.</p>",
            kv("decision profile", &scalar("/profile/profile_id")),
            kv("qualification", q("qualification_id")),
            kv(
                "target PlanDocument (qualification exact match)",
                q("plan_document_digest")
            ),
            kv("qualified compilation", q("compilation_id")),
            kv("qualified exact work", q("exact_work_id")),
            kv("qualification run", q("occurrence_id")),
            kv(
                "qualification acquired",
                &scalar("/qualification/acquired_at_unix_ms")
            ),
            kv(
                "passive observation",
                &scalar("/steady_state_observation_id")
            ),
            kv("passive custody", &scalar("/steady_state_custody_id")),
            kv(
                "passive observed at",
                &scalar("/steady_state_observed_at_unix_ms")
            ),
            kv(
                "passive horizon (exclusive)",
                &scalar("/fresh_until_unix_ms")
            ),
            kv("canonical observation", resolution.observation().as_str()),
            kv(
                "Nightshift currentness at governed evaluation",
                resolution.status_label()
            ),
        );
        return;
    }
    let field = |name: &str| {
        composition
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("malformed owner projection")
    };
    let purpose = composition
        .pointer("/profile/purpose")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("malformed owner projection");
    let numeric = |pointer: &str| {
        composition
            .pointer(pointer)
            .and_then(serde_json::Value::as_u64)
            .map_or_else(
                || "malformed owner projection".to_owned(),
                |value| value.to_string(),
            )
    };
    let _ = write!(
        body,
        "<h3>Nightshift composition <span class=fact>admitted for {}</span></h3><div class=kv>{}{}{}{}{}{}{}{}{}</div><p class=k>Nightshift admitted the closed claim set for this exact decision profile. The existing DecisionBasis remains the diagnostic condition/delivery projection; composition provenance is bound through the canonical observation identity rather than being relabelled as an NQ atom.</p>",
        escape(purpose),
        kv("composition", field("composition_id")),
        kv(
            "profile",
            composition
                .pointer("/profile/profile_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("malformed owner projection")
        ),
        kv("profile max age ms", &numeric("/profile/max_age_ms")),
        kv("source run", field("source_occurrence_id")),
        kv("source PlanDocument", field("source_plan_document_digest")),
        kv("source compilation", field("source_compilation_id")),
        kv("canonical observation", resolution.observation().as_str()),
        kv(
            "Nightshift currentness at governed evaluation",
            resolution.status_label()
        ),
        kv(
            "evidence horizon (exclusive)",
            &numeric("/fresh_until_unix_ms")
        ),
    );
}

fn external_claims(body: &mut String, observation: &crate::model::ExternalObservationV1) {
    body.push_str("<ul class=facts>");
    for claim in &observation.claims {
        let _ = write!(
            body,
            "<li><strong>{:?}</strong> — {:?} <span class=k>PlanNode {} · {}</span></li>",
            claim.kind,
            claim.status,
            escape(&claim.plan_node_id),
            escape(&claim.compiled_output_identity),
        );
    }
    body.push_str("</ul><p class=k>Docket settlement establishes the exact attempt outcome, not present-world health. Producer authentication establishes custody, not standing or authorization. The candidate remains historical evidence; the separately rendered Nightshift resolution records currentness for its exact governed evaluation and deadline, not an inferred present-time result.</p>");
}

fn authoring_context(
    body: &mut String,
    current: &OccurrenceSnapshotV1,
    proposal_id: &str,
    related: &[RelatedSourceV1<crate::model::NightshiftAuthoringContextExportV1>],
    custody_related: &[RelatedSourceV1<crate::model::NightshiftAuthoringCustodyExportV1>],
) {
    use crate::model::NightshiftAuthoringContextQueryV1;

    let campaign = current.key().campaign.as_str();
    let occurrence = current.key().occurrence.to_string();
    let identity = format!("{campaign}/{occurrence}");
    let source = related.iter().find(|source| {
        source.result.value().is_some_and(|export| {
            matches!(
                &export.query,
                NightshiftAuthoringContextQueryV1::GovernedOccurrence {
                    campaign_id,
                    occurrence_id,
                } if campaign_id == campaign && occurrence_id == &occurrence
            )
        }) || source.identity == identity
    });
    let Some(source) = source else {
        body.push_str("<p class=k><span class=unknown>authoring context unavailable</span> No owner-side lookup was captured for this exact run. No Maude relation is inferred. Inspect raw owner records for source diagnostics.</p>");
        return;
    };
    let SourceResultV1::Available { value, .. } = &source.result else {
        body.push_str("<p class=k><span class=unknown>authoring context unavailable</span> The canonical Nightshift lookup failed; source diagnostics remain in raw data.</p>");
        return;
    };
    match value.matches.as_slice() {
        [] => body.push_str("<p class=k><span class=unknown>authoring context not recorded</span> This run has no recorded authoring link; Phosphor-ng does not inherit or guess a previous run's context.</p>"),
        [record]
            if record
                .validate_for_governed_relationship(
                    campaign,
                    &occurrence,
                    proposal_id,
                    current.state().meta().expected_work().as_str(),
                )
                .is_ok() =>
        {
            let _ = write!(
                body,
                "<h3>Authoring context <span class=fact>canonical Nightshift lineage</span></h3><div class=kv>{}{}{}{}{}{}</div><p class=k>Lineage, not permission. No stable Maude browser address is recorded, so this inspector shows exact context rather than fabricating a backlink.</p>",
                kv("provenance", &record.provenance_id),
                kv("Maude plan", &record.maude_plan_ref),
                kv("Maude session", &record.maude_session_id),
                kv("proposal binding", &record.proposal_id),
                kv("exact work binding", &record.exact_work_id),
                kv("handoff recorded", &record.recorded_at),
            );
            authoring_custody(
                body,
                record,
                campaign,
                &occurrence,
                proposal_id,
                current.state().meta().expected_work().as_str(),
                custody_related,
            );
        }
        [_] => body.push_str("<p class=source-error><span class=error>record disagreement</span> Nightshift returned an authoring relation for this run, but its proposal/work binding does not match the selected AG state. No backlink is shown; inspect both raw owner records.</p>"),
        records => {
            let _ = write!(
                body,
                "<p class=source-error><span class=error>more than one authoring record</span> Nightshift returned {} authoring records for one governed run. No backlink is shown; inspect the raw Nightshift records.</p>",
                records.len()
            );
        }
    }
}

fn authoring_custody(
    body: &mut String,
    authoring: &crate::model::NightshiftAuthoringContextProvenanceV1,
    campaign: &str,
    occurrence: &str,
    proposal: &str,
    exact_work: &str,
    related: &[RelatedSourceV1<crate::model::NightshiftAuthoringCustodyExportV1>],
) {
    let identity = format!("{campaign}/{occurrence}");
    let Some(source) = related.iter().find(|source| source.identity == identity) else {
        body.push_str("<p class=k><span class=unknown>producer custody unavailable</span> No custody lookup was captured. Lineage remains visible, but producer authentication is unknown.</p>");
        return;
    };
    let SourceResultV1::Available { value, .. } = &source.result else {
        body.push_str("<p class=k><span class=unknown>producer custody unavailable</span> The canonical Nightshift custody lookup failed; diagnostics remain in raw data.</p>");
        return;
    };
    match value.matches.as_slice() {
        [] => body.push_str("<p class=k><span class=unknown>custody not recorded</span> This is historical/unlinked custody state. Authentication is not inferred and lineage does not become authority.</p>"),
        [custody]
            if custody
                .validate_for_relationship(
                    authoring,
                    campaign,
                    occurrence,
                    proposal,
                    exact_work,
                )
                .is_ok() =>
        {
            let _ = write!(
                body,
                "<h3>Handoff custody <span class=fact>authenticated at ingress</span></h3><div class=kv>{}{}{}{}{}{}{}{}{}{}</div><p class=k>The session issuer binds the supervised session to exact plan bytes; the distinct handoff producer binds that receipt to the exact Nightshift request. Authentication establishes custody, not permission.</p>",
                kv("custody record", &custody.custody_id),
                kv("handoff", &custody.handoff_id),
                kv("session receipt", &custody.session_record_id),
                kv("session issuer", &custody.session_issuer_principal_id),
                kv("session issuer key", &custody.session_issuer_key_id),
                kv("producer principal", &custody.producer_principal_id),
                kv("producer key", &custody.producer_key_id),
                kv("target Nightshift", &custody.target_runtime_id),
                kv("authentication", &custody.authentication_method),
                kv("recorded at (cycle time)", &custody.recorded_at),
            );
        }
        [_] => body.push_str("<p class=source-error><span class=error>custody disagreement</span> Nightshift returned custody that does not bind the selected lineage/proposal/work. It is not presented as authenticated.</p>"),
        records => {
            let _ = write!(
                body,
                "<p class=source-error><span class=error>more than one custody record</span> Nightshift returned {} custody records for one run. Inspect the raw Nightshift records.</p>",
                records.len()
            );
        }
    }
}

fn authority(body: &mut String, current: &OccurrenceSnapshotV1) {
    body.push_str(
        "<div id=authority class=grid><section class=panel><h2>Standing and admissibility</h2>",
    );
    if let Some(standing) = current.standing_resolution() {
        let _ = write!(
            body,
            "<div class=kv>{}{}{}{}{}{}{}</div>",
            kv("standing status", &format!("{:?}", standing.status)),
            kv("resolution", standing.resolution.as_str()),
            kv("currentness", standing.currentness.as_str()),
            kv("mandate", standing.mandate.as_str()),
            kv("resolver", &standing.resolver_id),
            kv("resolved at", &standing.resolved_at_unix_ms.to_string()),
            kv(
                "expires at (exclusive)",
                &standing.expires_at_unix_ms.to_string()
            )
        );
    } else {
        body.push_str("<p><span class=unknown>unknown</span> No standing resolution is retained in this state.</p>");
    }
    if let Some(decision) = current.admission_decision() {
        let _ = write!(
            body,
            "<h3>Admissibility</h3><div class=kv>{}{}{}{}</div>",
            kv("disposition", &format!("{:?}", decision.disposition)),
            kv("decision", decision.decision.as_str()),
            kv("policy basis", decision.policy_basis.as_str()),
            kv("proposal", decision.proposal.as_str())
        );
    } else {
        body.push_str("<p class=empty>No admissibility decision exists in this state.</p>");
    }
    authority_lifecycle(body, current);
    body.push_str("</section></div>");
}

fn authority_lifecycle(body: &mut String, current: &OccurrenceSnapshotV1) {
    let authority_tone =
        if current.ag_spend().is_some() || current.state().authority_history().ag_spend.is_some() {
            " danger"
        } else {
            ""
        };
    let _ = write!(
        body,
        "</section><section class=\"panel{authority_tone}\"><h2>AG authority lifecycle</h2>"
    );
    let retained = current.state().authority_history();
    match current.program_counter() {
        ProgramCounterV1::AdmissiblePendingAuthorization => body.push_str("<p><span class=projection>pending</span> Exact work is admissible, but no AG authorization has been spent.</p>"),
        ProgramCounterV1::AuthorizationConsumed => body.push_str("<p class=note><span class=spent>consumed</span> Authorization is spent and cannot be reused. Issuance is durable. AG does not report Docket custody or dispatch yet.</p>"),
        ProgramCounterV1::Dispatched | ProgramCounterV1::ReconciliationRequired | ProgramCounterV1::SettledObservationRequired => body.push_str("<p><span class=spent>consumed</span> Authorization is historical evidence only; it is not available.</p>"),
        ProgramCounterV1::Halted | ProgramCounterV1::Completed if retained.ag_spend.is_some() => body.push_str("<p><span class=spent>consumed</span> Terminal state retains historical authority identities only; none is available.</p>"),
        _ if current.ag_spend().is_none() => body.push_str("<p><span class=unknown>none</span> No AG authorization spend exists in this state.</p>"),
        _ => body.push_str("<p><span class=spent>consumed</span> Retained authority history is not reusable.</p>"),
    }
    if let Some(spend) = current.ag_spend() {
        let _ = write!(
            body,
            "<div class=kv>{}{}{}{}{}{}</div>",
            kv("authorization", spend.authorization.as_str()),
            kv("spend", spend.spend.as_str()),
            kv("run", &spend.key.occurrence.to_string()),
            kv("proposal", spend.proposal.as_str()),
            kv("observation", spend.observation.as_str()),
            kv("consumed at", &spend.consumed_at_unix_ms.to_string())
        );
    }
    if let Some(issuance) = current.issuance() {
        let _ = write!(
            body,
            "<h3>Durable issuance</h3><div class=kv>{}{}{}{}{}</div>",
            kv("issuance", issuance.issuance.as_str()),
            kv("work", issuance.work.as_str()),
            kv("work schema", &issuance.work_schema),
            kv("subject", issuance.subject.as_str()),
            kv("scope", issuance.scope.as_str())
        );
    }
    if current.ag_spend().is_none() && retained.ag_spend.is_some() {
        let _ = write!(
            body,
            "<h3>Terminal authority history</h3><div class=kv>{}{}{}{}{}</div>",
            kv(
                "AG spend",
                retained
                    .ag_spend
                    .as_ref()
                    .map_or("unknown", |value| value.as_str())
            ),
            kv(
                "Docket attempt",
                retained
                    .docket_attempt
                    .as_ref()
                    .map_or("unknown", |value| value.as_str())
            ),
            kv(
                "settlement",
                retained
                    .settlement
                    .as_ref()
                    .map_or("unknown", |value| value.as_str())
            ),
            kv(
                "receipt",
                retained
                    .receipt
                    .as_ref()
                    .map_or("unknown", |value| value.as_str())
            ),
            kv("authority availability", "consumed / not available")
        );
    }
}

fn execution(
    body: &mut String,
    current: &OccurrenceSnapshotV1,
    docket: &[RelatedSourceV1<DocketInspectionV1>],
) {
    let tone = match current.program_counter() {
        ProgramCounterV1::Dispatched => " unknown-outcome",
        ProgramCounterV1::ReconciliationRequired => " danger",
        _ => "",
    };
    let _ = write!(
        body,
        "<section id=execution class=\"panel wide{tone}\"><h2>Docket custody and outcome</h2>"
    );
    if let Some(custody) = current.docket_custody() {
        let _ = write!(
            body,
            "<p><span class=fact>custody accepted</span> Docket owns the one attempt.</p><div class=kv>{}{}{}{}{}{}</div>",
            kv("issuance", custody.issuance.as_str()),
            kv("attempt", custody.attempt.as_str()),
            kv("executor marker", custody.executor_marker.as_str()),
            kv("execution standing", custody.execution_standing.as_str()),
            kv(
                "standing currentness",
                custody.standing_currentness.as_str()
            ),
            kv("accepted at", &custody.accepted_at_unix_ms.to_string())
        );
    } else {
        body.push_str("<p><span class=unknown>unknown/not present</span> No Docket custody fact exists in AG’s current snapshot.</p>");
    }
    match current.program_counter() {
        ProgramCounterV1::Dispatched => body.push_str("<p class=note><span class=unknown>outcome unknown</span> Docket accepted custody, but AG has no settlement record. The work may or may not have occurred. A missing receipt is not a failure result, and this page offers no repeat action. Inspect the Docket source records below.</p>"),
        ProgramCounterV1::ReconciliationRequired => body.push_str("<p class=note><span class=error>reconciliation required</span> The outcome is indeterminate. Repeat dispatch is not authorized. Inspect the exact issuance, attempt, evidence, and raw owner records below.</p>"),
        ProgramCounterV1::SettledObservationRequired => body.push_str("<p class=note><span class=fact>outcome recorded</span> Docket recorded the prior run's outcome; see the outcome field below. Settlement alone does not mean success or present health, and it does not authorize continuation. A fresh independent observation is required.</p>"),
        _ => {}
    }
    if let Some(indeterminate) = current.indeterminate() {
        let _ = write!(
            body,
            "<div class=kv>{}{}{}</div>",
            kv("reconciliation", indeterminate.reconciliation.as_str()),
            kv("attempt", indeterminate.attempt.as_str()),
            kv("evidence", indeterminate.evidence.as_str())
        );
    }
    if let Some(settlement) = current.settlement() {
        let _ = write!(
            body,
            "<div class=kv>{}{}{}{}{}</div>",
            kv("settlement", settlement.settlement.as_str()),
            kv("outcome", &format!("{:?}", settlement.outcome)),
            kv("receipt", settlement.receipt.as_str()),
            kv("attempt", settlement.attempt.as_str()),
            kv("settled at", &settlement.settled_at_unix_ms.to_string())
        );
    }
    for related in docket {
        let _ = write!(
            body,
            "<h3>Docket source: {}</h3>",
            escape(&related.identity)
        );
        match &related.result {
            SourceResultV1::Available { value, .. } => {
                if let Some(record) = &value.record {
                    let status = match record.status {
                        DocketRecordStatusV1::Accepted => "accepted — outcome unknown",
                        DocketRecordStatusV1::Settled => "settled — outcome recorded (not necessarily success)",
                        DocketRecordStatusV1::Indeterminate => {
                            "indeterminate — reconciliation required"
                        }
                    };
                    let _ = write!(
                        body,
                        "<div class=kv>{}{}{}{}{}</div>",
                        kv("Docket record", status),
                        kv("issuer principal", &record.authentication.issuer_principal),
                        kv("signer key", &record.authentication.signer_key_id),
                        kv("executor binding", &record.executor_binding),
                        kv("executor program", &record.executor_program_digest)
                    );
                } else {
                    body.push_str("<p><span class=fact>canonical fact</span> Docket reports no accepted custody for this issuance.</p>");
                }
            }
            SourceResultV1::Unavailable { .. } => source_summary(body, &related.result),
        }
    }
    body.push_str("</section>");
}

fn raw_sources(body: &mut String, model: &CampaignDetailV1) {
    body.push_str("<section id=raw class=\"panel wide\"><h2>Raw canonical data and source diagnostics</h2><p class=note>These are the complete bounded owner responses used above. Expand a source to verify what the owner actually said.</p>");
    source_summary(body, &model.inspect);
    source_summary(body, &model.status);
    source_summary(body, &model.replay);
    source_summary(body, &model.history);
    source_summary(body, &model.refusals);
    if let Some(source) = &model.intervention_submissions {
        source_summary(body, source);
    }
    for source in &model.nightshift {
        source_summary(body, &source.result);
    }
    for source in &model.authoring_contexts {
        source_summary(body, &source.result);
    }
    for source in &model.authoring_custody {
        source_summary(body, &source.result);
    }
    for source in &model.external_observations {
        source_summary(body, &source.result);
    }
    for source in &model.observation_acquisitions {
        source_summary(body, &source.result);
    }
    for source in &model.docket {
        source_summary(body, &source.result);
    }
    body.push_str("</section>");
}

fn source_summary<T: Serialize>(body: &mut String, source: &SourceResultV1<T>) {
    match source {
        SourceResultV1::Available {
            source,
            command,
            captured_at_unix_ms,
            raw,
            ..
        } => {
            let schema = raw
                .get("schema")
                .and_then(Value::as_str)
                .unwrap_or("schema not present");
            let _ = write!(
                body,
                "<details class=raw><summary><span class=fact>available</span> {} / {:?} <span class=schema>{}</span> <span class=raw-meta>captured {}</span></summary><pre tabindex=0 aria-label=\"Raw canonical JSON\">{}</pre></details>",
                escape(source),
                command,
                escape(schema),
                captured_at_unix_ms,
                escape(&pretty(raw))
            );
        }
        SourceResultV1::Unavailable {
            source,
            command,
            captured_at_unix_ms,
            error_kind,
            detail,
            exit_status,
        } => {
            let _ = write!(
                body,
                "<div class=source-error><p><span class=error>unavailable</span> {} / {:?} · {:?} · captured {} · exit {}</p><pre>{}</pre></div>",
                escape(source),
                command,
                error_kind,
                captured_at_unix_ms,
                exit_status.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                escape(detail)
            );
        }
    }
}

fn terminal_label(snapshot: &OccurrenceSnapshotV1) -> String {
    if let Some(halted) = snapshot.halted() {
        format!("halted: {}", halted.reason())
    } else if let Some(completed) = snapshot.completed() {
        format!("completed: {}", completed.terminal_witness())
    } else {
        "nonterminal".to_owned()
    }
}

fn budget_html(budget: ag_campaign::governed::LoopBudgetV1) -> String {
    format!(
        "{}{}{}",
        kv(
            "retry runs",
            &format!("{} / {}", budget.retries_used, budget.retry_limit)
        ),
        kv(
            "read-only probes",
            &format!("{} / {}", budget.probes_used, budget.probe_limit)
        ),
        kv(
            "escalations",
            &format!("{} / {}", budget.escalations_used, budget.escalation_limit)
        )
    )
}

fn pc(value: ProgramCounterV1) -> String {
    escape(&format!("{value:?}"))
}

fn snapshot_link(snapshot: &OccurrenceSnapshotV1, include_proposal: bool) -> GovernedRuntimeLinkV1 {
    GovernedRuntimeLinkV1 {
        campaign: snapshot.key().campaign.as_digest().clone(),
        occurrence: snapshot.key().occurrence,
        proposal: include_proposal
            .then(|| {
                snapshot
                    .proposal()
                    .map(|proposal| proposal.reference().as_digest().clone())
            })
            .flatten(),
    }
}

fn immediate_condition(snapshot: &OccurrenceSnapshotV1) -> &'static str {
    immediate_condition_for(snapshot.program_counter())
}

fn immediate_condition_for(counter: ProgramCounterV1) -> &'static str {
    match counter {
        ProgramCounterV1::ObservationRequired => {
            "<span class=projection>fresh observation required</span> no proposal or authority has been recorded"
        }
        ProgramCounterV1::ProposalRecorded => {
            "<span class=projection>proposal recorded</span> standing has not yet been established"
        }
        ProgramCounterV1::StandingRequired => {
            "<span class=projection>standing required</span> no authorization exists"
        }
        ProgramCounterV1::AdmissiblePendingAuthorization => {
            "<span class=projection>authorization pending</span> the work passed admission, but no authorization has been used"
        }
        ProgramCounterV1::AuthorizationConsumed => {
            "<span class=spent>authority consumed</span> an issuance is recorded; dispatch is not recorded"
        }
        ProgramCounterV1::Dispatched => {
            "<span class=unknown>outcome unknown</span> Docket custody is recorded, but no settlement is recorded; this is not a failure result"
        }
        ProgramCounterV1::ReconciliationRequired => {
            "<span class=error>reconciliation required</span> the work may have occurred; repeat dispatch is unavailable"
        }
        ProgramCounterV1::SettledObservationRequired => {
            "<span class=fact>outcome recorded</span> inspect the outcome, then obtain a fresh independent observation before continuation"
        }
        ProgramCounterV1::Halted => {
            "<span class=error>halted</span> inspect the durable reason and refusal provenance"
        }
        ProgramCounterV1::Completed => {
            "<span class=terminal-badge>completed</span> terminal witness is retained"
        }
    }
}

fn state_tone_class(value: ProgramCounterV1) -> &'static str {
    match value {
        ProgramCounterV1::AuthorizationConsumed | ProgramCounterV1::ReconciliationRequired => {
            "danger-step"
        }
        ProgramCounterV1::Dispatched => "unknown-step",
        ProgramCounterV1::Halted | ProgramCounterV1::Completed => "terminal-step",
        _ => "",
    }
}

fn kv(key: &str, value: &str) -> String {
    format!(
        "<div class=k>{}</div><div class=v>{}</div>",
        escape(key),
        escape(value)
    )
}

fn raw_details(label: &str, value: &impl Serialize) -> String {
    let raw = serde_json::to_value(value).unwrap_or(Value::Null);
    format!(
        "<details class=raw><summary>{}</summary><pre tabindex=0 aria-label=\"Raw canonical JSON\">{}</pre></details>",
        escape(label),
        escape(&pretty(&raw))
    )
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "<serialization unavailable>".to_owned())
}

fn page_with_mode(title: &str, body: &str, source_mode: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>{}</title><link rel=stylesheet href=/style.css></head><body><a class=skip href=#main>Skip to content</a><header class=topbar><a href=/phosphor-ng><strong>Phosphor-ng</strong></a><span class=k>governed-runtime inspector</span><span class=projection>read only</span><span class=k>canonical facts, visible uncertainty</span><span class=mode>{}</span></header><main id=main>{}</main></body></html>",
        escape(title),
        escape(source_mode),
        body
    )
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn campaign_source_label(locator: &str) -> &str {
    Path::new(locator)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or(locator)
}

fn compact_campaign_identity(identity: &str) -> String {
    let Some(digest) = identity.strip_prefix("sha256:") else {
        return identity.to_owned();
    };
    if digest.len() != 64 || !digest.bytes().all(|value| value.is_ascii_hexdigit()) {
        return identity.to_owned();
    }
    format!("sha256:{}…{}", &digest[..8], &digest[digest.len() - 8..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_consumed_vocabulary_remain_distinct() {
        assert!(STYLE.contains("--unknown"));
        assert_ne!(
            pc(ProgramCounterV1::AuthorizationConsumed),
            pc(ProgramCounterV1::Dispatched)
        );
    }

    #[test]
    fn campaign_columns_wrap_long_terminal_identifiers() {
        assert!(STYLE.contains(".campaign>div{min-width:0;overflow-wrap:anywhere}"));
        assert!(STYLE.contains(".campaign .k,.campaign .pc"));
        assert!(STYLE.contains("word-break:break-word"));
    }

    #[test]
    fn escaping_prevents_canonical_data_from_becoming_markup() {
        assert_eq!(escape("<widget>&\"'"), "&lt;widget&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn campaign_index_compacts_only_canonical_digest_typography() {
        let identity = format!("sha256:{}", "0123456789abcdef".repeat(4));
        assert_eq!(
            compact_campaign_identity(&identity),
            "sha256:01234567…89abcdef"
        );
        assert_eq!(
            compact_campaign_identity("campaign-alpha"),
            "campaign-alpha"
        );
        assert_eq!(
            campaign_source_label("/tmp/corpus/reconciliation-exact-attempt.sqlite"),
            "reconciliation-exact-attempt.sqlite"
        );
    }

    #[test]
    fn index_controls_accept_only_closed_presentation_values() {
        assert!(matches!(
            IndexViewV1::parse("view=reconciliation&sort=state"),
            IndexViewV1::Reconciliation
        ));
        assert!(matches!(
            IndexSortV1::parse("view=reconciliation&sort=state"),
            IndexSortV1::ProgramCounter
        ));
        assert!(matches!(
            IndexViewV1::parse("view=healthy"),
            IndexViewV1::All
        ));
    }

    #[test]
    fn critical_counter_copy_never_collapses_consumed_and_unknown() {
        assert!(
            immediate_condition_for(ProgramCounterV1::AuthorizationConsumed)
                .contains("authority consumed")
        );
        assert!(immediate_condition_for(ProgramCounterV1::Dispatched).contains("outcome unknown"));
        assert!(
            immediate_condition_for(ProgramCounterV1::ReconciliationRequired)
                .contains("reconciliation required")
        );
    }

    #[test]
    fn contextual_run_links_are_read_only_navigation() {
        let mut body = String::new();
        local_navigation(&mut body);
        assert!(body.contains("Inspect this run"));
        assert!(body.contains("evidence and proposal"));
        assert!(body.contains("raw owner records"));
        assert!(!body.contains("retry"));
    }

    #[test]
    fn exact_projection_correspondence_is_progressively_disclosed() {
        let mut exact = String::new();
        projection_panel_for(
            &mut exact,
            ProjectionCorrespondenceV1::Exact,
            &["all canonical coordinates agree".to_owned()],
        );
        assert!(exact.starts_with("<details class=\"raw projection-evidence\">"));
        assert!(!exact.starts_with("<details class=\"raw projection-evidence\" open>"));
        assert!(exact.contains("all canonical coordinates agree"));

        let mut disagreement = String::new();
        projection_panel_for(
            &mut disagreement,
            ProjectionCorrespondenceV1::Disagreement,
            &["canonical sources disagree".to_owned()],
        );
        assert!(disagreement.starts_with("<details class=\"raw projection-evidence\" open>"));
        assert!(disagreement.contains("canonical sources disagree"));
    }

    #[test]
    fn ingress_receipts_distinguish_delivery_from_governed_acceptance() {
        let target = Digest::hash_bytes(b"runtime");
        let submission = Digest::hash_bytes(b"submission");
        let received = crate::model::InterventionSubmissionReceiptProjectionV1 {
            schema: "ag.governed-loop.intervention-submission-receipt/v1".to_owned(),
            receipt: Digest::hash_bytes(b"receipt"),
            submission: Some(submission.clone()),
            presentation_digest: Digest::hash_bytes(b"presentation"),
            request: Some(Digest::hash_bytes(b"request")),
            target_runtime_profile: Some(target.clone()),
            submitting_principal: Some("maude-submitter".to_owned()),
            result: serde_json::json!({"status": "received", "custody_verification": Digest::hash_bytes(b"custody")}),
            previous_receipt: None,
            recorded_at_unix_ms: 1,
        };
        let source = SourceResultV1::Available {
            source: "AG intervention ingress".to_owned(),
            command: crate::model::ReadCommandNameV1::AgInterventionSubmissions,
            captured_at_unix_ms: 2,
            raw: serde_json::json!({}),
            value: crate::model::InterventionSubmissionHistoryProjectionV1 {
                schema: crate::model::AG_INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1.to_owned(),
                target_runtime_profile: target,
                submission: Some(submission),
                receipts: vec![received],
            },
        };
        let mut body = String::new();
        intervention_submissions(&mut body, Some(&source));
        assert!(body.contains("received"));
        assert!(body.contains("delivery is not authorization"));
        assert!(!body.contains("approved"));
    }

    #[test]
    fn acquisition_projection_keeps_mechanics_separate_from_currentness() {
        let campaign = Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-4000-8000-000000000000";
        let id = |label: &[u8]| Digest::hash_bytes(label).to_string();
        let request_id = id(b"request");
        let acquisition = serde_json::json!({
            "schema": "maude.external-evidence-acquisition-export/v1",
            "trigger": {
                "reason": "post_settlement",
                "trigger_id": id(b"trigger"),
                "adapter_id": "maude.local-compose-observation-adapter",
                "settlement_id": id(b"settlement"),
                "target_runtime_id": "nightshift:local"
            },
            "request": {"request_id": request_id},
            "events": [
                {"kind": "trigger_recorded"},
                {"kind": "adapter_returned_evidence"},
                {"kind": "custody_outcome_unknown"}
            ],
            "evidence": {"handoff": {"observation": {"observation_id": id(b"observation")}}}
        });
        let history = crate::model::AcquisitionHistoryV1 {
            schema: crate::model::MAUDE_ACQUISITION_HISTORY_SCHEMA_V1.to_owned(),
            campaign_id: campaign.clone(),
            occurrence_id: occurrence.to_owned(),
            acquisitions: vec![acquisition.clone()],
        };
        let related = vec![RelatedSourceV1 {
            identity: format!("{campaign}/{occurrence}"),
            result: SourceResultV1::Available {
                source: "Maude acquisition orchestrator".to_owned(),
                command: crate::model::ReadCommandNameV1::MaudeExportObservationAcquisitions,
                captured_at_unix_ms: 1,
                raw: serde_json::to_value(&history).unwrap(),
                value: history,
            },
        }];
        let mut body = String::new();
        acquisition_history(&mut body, &format!("{campaign}/{occurrence}"), &related);
        assert!(body.contains("mechanics provenance"));
        assert!(
            body.contains("trigger_recorded → adapter_returned_evidence → custody_outcome_unknown")
        );
        assert!(body.contains("only Nightshift determines custody composition/currentness"));
        assert!(!body.contains("monitoring status"));
    }

    #[test]
    fn qualification_view_keeps_target_generation_and_passive_time_distinct() {
        let source = include_str!("render.rs");
        assert!(source.contains("target PlanDocument (qualification exact match)"));
        assert!(source.contains("qualification run"));
        assert!(source.contains("qualified exact work"));
        assert!(source.contains("No new failure test was performed"));
        assert!(source.contains(
            "The target PlanDocument label is an owner-established exact match, not a UI inference"
        ));
        let forbidden_claim = ["qualification", " carried", " forward"].concat();
        assert!(!source.contains(&forbidden_claim));
    }
}
