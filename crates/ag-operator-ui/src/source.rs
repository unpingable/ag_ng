//! Closed read-command adapter and campaign read-model assembly.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ag_campaign::governed::OccurrenceSnapshotV1;
use ag_store::campaign::{
    CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1, CAMPAIGN_TRANSITION_HISTORY_SCHEMA_V1,
    CampaignRefusalHistoryV1, CampaignReplayReportV1, CampaignTransitionHistoryV1,
};
use serde::{Deserialize as _, de::DeserializeOwned};
use serde_json::Value;

use crate::links::GovernedRuntimeLinkV1;
use crate::model::{
    AG_INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1, AgInspectV1, CAMPAIGN_DETAIL_SCHEMA_V1,
    CAMPAIGN_INDEX_SCHEMA_V1, CampaignDetailV1, CampaignIndexEntryV1, CampaignIndexV1,
    DEMO_CORPUS_SCHEMA_V1, DOCKET_INSPECTION_SCHEMA_V1, DemoCorpusV1, DocketInspectionV1,
    ExternalObservationExportV1, InterventionSubmissionHistoryProjectionV1,
    NightshiftAuthoringContextExportV1, NightshiftAuthoringContextQueryV1,
    NightshiftAuthoringCustodyExportV1, NightshiftObservationExportV1, ProjectionCheckV1,
    ProjectionCorrespondenceV1, ReadCommandNameV1, RelatedSourceV1, SourceErrorKindV1,
    SourceResultV1,
};

const MAX_STDOUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: u64 = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const RELATED_SOURCE_PROCESS_LIMIT: usize = 128;
const MAX_DEMO_CORPUS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEMO_CAMPAIGNS: usize = 512;
/// Presentation-only evidence-age window passed transparently to Nightshift.
/// It is never used as canonical cycle currentness or AG authority.
const EXTERNAL_OBSERVATION_DISPLAY_TTL_MS: u64 = 5 * 60 * 1_000;

/// Optional Nightshift read-source coordinates.
#[derive(Clone, Debug)]
pub struct NightshiftReadSourceV1 {
    /// Exact canonical Nightshift CLI.
    pub program: PathBuf,
    /// Existing canonical Nightshift store.
    pub store: PathBuf,
}

/// Optional Docket read-source coordinates.
#[derive(Clone, Debug)]
pub struct DocketReadSourceV1 {
    /// Exact canonical Docket CLI.
    pub program: PathBuf,
    /// Existing Docket state directory.
    pub state: PathBuf,
}

/// Closed local operator backend configuration.
#[derive(Clone, Debug)]
pub struct OperatorSourceConfigV1 {
    /// Root whose immediate regular `.sqlite` children are campaign stores.
    pub campaign_root: PathBuf,
    /// Exact canonical AG controller.
    pub ag_loopctl: PathBuf,
    /// Optional Nightshift observation-provenance source.
    pub nightshift: Option<NightshiftReadSourceV1>,
    /// Optional Docket custody/outcome source.
    pub docket: Option<DocketReadSourceV1>,
}

impl OperatorSourceConfigV1 {
    /// Validates locators and exact program names without invoking anything.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing campaign root or a noncanonical binary
    /// coordinate.
    pub fn validate(&self) -> Result<(), String> {
        require_program_name(&self.ag_loopctl, "ag-loopctl")?;
        if !self.campaign_root.is_dir() {
            return Err(format!(
                "campaign root is not a directory: {}",
                self.campaign_root.display()
            ));
        }
        if let Some(source) = &self.nightshift {
            require_program_name(&source.program, "nightshift")?;
        }
        if let Some(source) = &self.docket {
            require_program_name(&source.program, "docket")?;
        }
        Ok(())
    }
}

/// Closed read requests. No variant accepts an arbitrary verb or argument
/// list, which makes the process boundary mechanically non-extensible without
/// changing this enum and its structural test.
#[derive(Clone, Debug)]
enum CanonicalReadRequestV1 {
    AgInspect(PathBuf),
    AgStatus(PathBuf),
    AgReplay(PathBuf),
    AgHistory(PathBuf),
    AgRefusals(PathBuf),
    AgInterventionSubmissions(PathBuf),
    NightshiftExportObservation(String),
    NightshiftExportAuthoringContext {
        campaign: String,
        occurrence: String,
    },
    NightshiftExportAuthoringCustody {
        campaign: String,
        occurrence: String,
    },
    NightshiftExportExternalObservation {
        campaign: String,
        occurrence: String,
        evaluated_at_unix_ms: i64,
        evidence_ttl_ms: u64,
    },
    DocketInspect(String),
}

impl CanonicalReadRequestV1 {
    const fn name(&self) -> ReadCommandNameV1 {
        match self {
            Self::AgInspect(_) => ReadCommandNameV1::AgInspect,
            Self::AgStatus(_) => ReadCommandNameV1::AgStatus,
            Self::AgReplay(_) => ReadCommandNameV1::AgReplay,
            Self::AgHistory(_) => ReadCommandNameV1::AgHistory,
            Self::AgRefusals(_) => ReadCommandNameV1::AgRefusals,
            Self::AgInterventionSubmissions(_) => ReadCommandNameV1::AgInterventionSubmissions,
            Self::NightshiftExportObservation(_) => ReadCommandNameV1::NightshiftExportObservation,
            Self::NightshiftExportAuthoringContext { .. } => {
                ReadCommandNameV1::NightshiftExportAuthoringContext
            }
            Self::NightshiftExportAuthoringCustody { .. } => {
                ReadCommandNameV1::NightshiftExportAuthoringCustody
            }
            Self::NightshiftExportExternalObservation { .. } => {
                ReadCommandNameV1::NightshiftExportExternalObservation
            }
            Self::DocketInspect(_) => ReadCommandNameV1::DocketGovernedLoopInspect,
        }
    }
}

#[derive(Debug)]
struct CaptureFailureV1 {
    kind: SourceErrorKindV1,
    detail: String,
    exit_status: Option<i32>,
}

#[derive(Debug)]
struct CapturedJsonV1 {
    captured_at_unix_ms: u64,
    raw: Value,
}

/// Production read-model assembler. It owns only canonical read-command
/// coordinates and never opens a runtime database itself.
#[derive(Clone, Debug)]
enum OperatorReaderBackendV1 {
    Canonical(OperatorSourceConfigV1),
    Demo(Arc<DemoCorpusV1>),
}

/// Read-only live-command or deterministic-corpus projection source.
#[derive(Clone, Debug)]
pub struct OperatorReaderV1 {
    backend: OperatorReaderBackendV1,
}

impl OperatorReaderV1 {
    /// Constructs one validated read-only source adapter.
    ///
    /// # Errors
    ///
    /// Returns a configuration validation error.
    pub fn new(config: OperatorSourceConfigV1) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            backend: OperatorReaderBackendV1::Canonical(config),
        })
    }

    /// Opens one bounded deterministic read-model corpus. This mode executes
    /// no subprocess and is visibly labeled by the renderer; it exists only
    /// to exercise presentation against captured canonical schemas.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, malformed, drifted, or internally
    /// inconsistent corpus.
    pub fn from_demo_corpus(path: &Path) -> Result<Self, String> {
        let metadata =
            fs::metadata(path).map_err(|error| format!("read demo corpus metadata: {error}"))?;
        if !metadata.is_file() || metadata.len() > MAX_DEMO_CORPUS_BYTES {
            return Err("demo corpus must be a regular file no larger than 64 MiB".to_owned());
        }
        let bytes = fs::read(path).map_err(|error| format!("read demo corpus: {error}"))?;
        let corpus: DemoCorpusV1 = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse typed demo corpus: {error}"))?;
        validate_demo_corpus(&corpus)?;
        Ok(Self {
            backend: OperatorReaderBackendV1::Demo(Arc::new(corpus)),
        })
    }

    /// Presentation-only source-mode label.
    #[must_use]
    pub const fn mode_label(&self) -> &'static str {
        match self.backend {
            OperatorReaderBackendV1::Canonical(_) => "live canonical commands",
            OperatorReaderBackendV1::Demo(_) => "deterministic demo corpus",
        }
    }

    /// Lists all immediate regular campaign databases. Each failed canonical
    /// read remains a visible index entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured campaign root cannot be listed.
    pub fn campaign_index(&self) -> Result<CampaignIndexV1, String> {
        if let OperatorReaderBackendV1::Demo(corpus) = &self.backend {
            return Ok(corpus.index.clone());
        }
        let config = self.canonical_config()?;
        let mut stores = discover_stores(&config.campaign_root)?;
        stores.sort_by(|left, right| left.0.cmp(&right.0));
        let campaigns = stores
            .into_iter()
            .map(|(token, locator, database)| {
                let inspect = self.ag_inspect(&database);
                let history = self.ag_history(&database);
                let refusals = self.ag_refusals(&database);
                let projection = projection_check(
                    inspect.value(),
                    None,
                    None,
                    history.value(),
                    refusals.value(),
                    &[
                        inspect.is_available(),
                        history.is_available(),
                        refusals.is_available(),
                    ],
                );
                CampaignIndexEntryV1 {
                    locator_token: token,
                    locator,
                    inspect,
                    history,
                    refusals,
                    projection,
                }
            })
            .collect();
        Ok(CampaignIndexV1 {
            schema: CAMPAIGN_INDEX_SCHEMA_V1.to_owned(),
            campaigns,
        })
    }

    /// Loads one exact configured-root child through all canonical sources.
    ///
    /// # Errors
    ///
    /// Returns an error when the locator is not one of the root's immediate
    /// regular campaign stores.
    pub fn campaign_detail(&self, locator_token: &str) -> Result<CampaignDetailV1, String> {
        if let OperatorReaderBackendV1::Demo(corpus) = &self.backend {
            return corpus
                .campaigns
                .iter()
                .find(|campaign| campaign.locator_token == locator_token)
                .cloned()
                .ok_or_else(|| "nonexistent demo campaign locator".to_owned());
        }
        let (locator, database) = self.resolve_store(locator_token)?;
        let inspect = self.ag_inspect(&database);
        let status = self.ag_status(&database);
        let replay = self.ag_replay(&database);
        let history = self.ag_history(&database);
        let refusals = self.ag_refusals(&database);
        let intervention_submissions = self.ag_intervention_submissions(&database);
        let availability = [
            inspect.is_available(),
            status.is_available(),
            replay.is_available(),
            history.is_available(),
            refusals.is_available(),
        ];
        let projection = projection_check(
            inspect.value(),
            status.value(),
            replay.value(),
            history.value(),
            refusals.value(),
            &availability,
        );

        let mut observations = BTreeSet::new();
        let mut issuances = BTreeSet::new();
        let mut occurrences = BTreeSet::new();
        if let Some(value) = history.value() {
            for transition in &value.transitions {
                collect_related(&transition.successor, &mut observations, &mut issuances);
                collect_occurrence(&transition.successor, &mut occurrences);
            }
        } else if let Some(value) = inspect.value() {
            collect_related(&value.current, &mut observations, &mut issuances);
            collect_occurrence(&value.current, &mut occurrences);
        } else if let Some(value) = status.value() {
            collect_related(value, &mut observations, &mut issuances);
            collect_occurrence(value, &mut occurrences);
        }

        let nightshift = self.collect_nightshift_sources(observations);
        let authoring_contexts = self.collect_authoring_sources(occurrences.clone());
        let authoring_custody = self.collect_authoring_custody_sources(occurrences.clone());
        let external_observations = self.collect_external_observations(occurrences);
        let docket = self.collect_docket_sources(issuances);

        Ok(CampaignDetailV1 {
            schema: CAMPAIGN_DETAIL_SCHEMA_V1.to_owned(),
            locator_token: locator_token.to_owned(),
            locator,
            inspect,
            status,
            replay,
            history,
            refusals,
            intervention_submissions: Some(intervention_submissions),
            projection,
            nightshift,
            authoring_contexts,
            authoring_custody,
            external_observations,
            docket,
        })
    }

    fn collect_nightshift_sources(
        &self,
        observations: BTreeSet<String>,
    ) -> Vec<RelatedSourceV1<NightshiftObservationExportV1>> {
        observations
            .into_iter()
            .enumerate()
            .map(|(index, identity)| RelatedSourceV1 {
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_export(&identity)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportObservation,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
                identity,
            })
            .collect()
    }

    fn collect_authoring_sources(
        &self,
        occurrences: BTreeSet<(String, String)>,
    ) -> Vec<RelatedSourceV1<NightshiftAuthoringContextExportV1>> {
        occurrences
            .into_iter()
            .enumerate()
            .map(|(index, (campaign, occurrence))| RelatedSourceV1 {
                identity: format!("{campaign}/{occurrence}"),
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_authoring_export(&campaign, &occurrence)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportAuthoringContext,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
            })
            .collect()
    }

    fn collect_docket_sources(
        &self,
        issuances: BTreeSet<String>,
    ) -> Vec<RelatedSourceV1<DocketInspectionV1>> {
        issuances
            .into_iter()
            .enumerate()
            .map(|(index, identity)| RelatedSourceV1 {
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.docket_inspect(&identity)
                } else {
                    unavailable(
                        "Docket",
                        ReadCommandNameV1::DocketGovernedLoopInspect,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
                identity,
            })
            .collect()
    }

    fn collect_authoring_custody_sources(
        &self,
        occurrences: BTreeSet<(String, String)>,
    ) -> Vec<RelatedSourceV1<NightshiftAuthoringCustodyExportV1>> {
        occurrences
            .into_iter()
            .enumerate()
            .map(|(index, (campaign, occurrence))| RelatedSourceV1 {
                identity: format!("{campaign}/{occurrence}"),
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_authoring_custody_export(&campaign, &occurrence)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportAuthoringCustody,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
            })
            .collect()
    }

    fn collect_external_observations(
        &self,
        occurrences: BTreeSet<(String, String)>,
    ) -> Vec<RelatedSourceV1<ExternalObservationExportV1>> {
        occurrences
            .into_iter()
            .enumerate()
            .map(|(index, (campaign, occurrence))| RelatedSourceV1 {
                identity: format!("{campaign}/{occurrence}"),
                result: if index < RELATED_SOURCE_PROCESS_LIMIT {
                    self.nightshift_external_observation_export(&campaign, &occurrence)
                } else {
                    unavailable(
                        "Nightshift",
                        ReadCommandNameV1::NightshiftExportExternalObservation,
                        SourceErrorKindV1::Unavailable,
                        "related-source process limit exceeded; fact not queried".to_owned(),
                        None,
                    )
                },
            })
            .collect()
    }

    /// Resolves one navigation-only semantic link without accepting a
    /// database path or treating the URL as authority.
    ///
    /// # Errors
    ///
    /// Returns an error when no exact identity binding exists or when more
    /// than one live campaign store claims the same semantic coordinates.
    pub fn campaign_detail_for_link(
        &self,
        link: &GovernedRuntimeLinkV1,
    ) -> Result<CampaignDetailV1, String> {
        if let OperatorReaderBackendV1::Demo(corpus) = &self.backend {
            let target = corpus
                .semantic_link_targets
                .iter()
                .find(|target| demo_target_matches(target, link))
                .ok_or_else(|| "demo corpus has no exact semantic link target".to_owned())?;
            return self.campaign_detail(&target.locator_token);
        }

        let index = self.campaign_index()?;
        let candidates = index
            .campaigns
            .iter()
            .filter(|entry| index_entry_matches_link(entry, link))
            .collect::<Vec<_>>();
        let [candidate] = candidates.as_slice() else {
            return Err(match candidates.len() {
                0 => "no campaign occurrence matches the canonical semantic link".to_owned(),
                count => format!(
                    "{count} campaign stores match the semantic link; refusing ambiguous locator resolution"
                ),
            });
        };
        let detail = self.campaign_detail(&candidate.locator_token)?;
        if !detail_matches_link(&detail, link) {
            return Err("campaign changed while resolving semantic link".to_owned());
        }
        Ok(detail)
    }

    fn resolve_store(&self, token: &str) -> Result<(String, PathBuf), String> {
        discover_stores(&self.canonical_config()?.campaign_root)?
            .into_iter()
            .find(|candidate| candidate.0 == token)
            .map(|(_, locator, path)| (locator, path))
            .ok_or_else(|| "nonexistent campaign source locator".to_owned())
    }

    fn ag_inspect(&self, database: &Path) -> SourceResultV1<AgInspectV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgInspect(database.to_owned()),
            |value: &AgInspectV1| value.validate(),
        )
    }

    fn ag_status(&self, database: &Path) -> SourceResultV1<OccurrenceSnapshotV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgStatus(database.to_owned()),
            |value: &OccurrenceSnapshotV1| {
                value
                    .validate_integrity()
                    .map_err(|error| format!("AG status snapshot integrity: {error}"))
            },
        )
    }

    fn ag_replay(&self, database: &Path) -> SourceResultV1<CampaignReplayReportV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgReplay(database.to_owned()),
            |_| Ok(()),
        )
    }

    fn ag_history(&self, database: &Path) -> SourceResultV1<CampaignTransitionHistoryV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgHistory(database.to_owned()),
            |value: &CampaignTransitionHistoryV1| {
                if value.schema != CAMPAIGN_TRANSITION_HISTORY_SCHEMA_V1 {
                    return Err(format!("unsupported AG history schema {}", value.schema));
                }
                for (index, transition) in value.transitions.iter().enumerate() {
                    let expected = u64::try_from(index + 1)
                        .map_err(|_| "AG history sequence overflow".to_owned())?;
                    transition
                        .successor
                        .validate_integrity()
                        .map_err(|error| format!("AG history snapshot integrity: {error}"))?;
                    if transition.sequence != expected
                        || transition.successor.state_digest() != &transition.successor_state_digest
                    {
                        return Err("AG history ordering/binding mismatch".to_owned());
                    }
                }
                let last = value
                    .transitions
                    .last()
                    .ok_or_else(|| "AG history is empty".to_owned())?;
                if last.successor_state_digest != value.current_state_digest {
                    return Err("AG history current-state binding mismatch".to_owned());
                }
                Ok(())
            },
        )
    }

    fn ag_refusals(&self, database: &Path) -> SourceResultV1<CampaignRefusalHistoryV1> {
        self.capture_typed(
            "AG",
            &CanonicalReadRequestV1::AgRefusals(database.to_owned()),
            |value: &CampaignRefusalHistoryV1| {
                if value.schema != CAMPAIGN_REFUSAL_HISTORY_SCHEMA_V1 {
                    return Err(format!(
                        "unsupported AG refusal-history schema {}",
                        value.schema
                    ));
                }
                if value
                    .refusals
                    .iter()
                    .any(|refusal| refusal.outcome.key.campaign != value.campaign)
                {
                    return Err("AG refusal-history campaign binding mismatch".to_owned());
                }
                Ok(())
            },
        )
    }

    fn ag_intervention_submissions(
        &self,
        database: &Path,
    ) -> SourceResultV1<InterventionSubmissionHistoryProjectionV1> {
        self.capture_typed(
            "AG intervention ingress",
            &CanonicalReadRequestV1::AgInterventionSubmissions(database.to_owned()),
            |value: &InterventionSubmissionHistoryProjectionV1| {
                if value.schema != AG_INTERVENTION_SUBMISSION_HISTORY_SCHEMA_V1 {
                    return Err(format!(
                        "unsupported AG intervention submission schema {}",
                        value.schema
                    ));
                }
                if value.receipts.iter().any(|receipt| {
                    receipt
                        .target_runtime_profile
                        .as_ref()
                        .is_some_and(|target| target != &value.target_runtime_profile)
                }) {
                    return Err("intervention receipt target-runtime mismatch".to_owned());
                }
                Ok(())
            },
        )
    }

    fn nightshift_export(
        &self,
        observation: &str,
    ) -> SourceResultV1<NightshiftObservationExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportObservation,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportObservation(observation.to_owned()),
            |value: &NightshiftObservationExportV1| value.validate(observation),
        )
    }

    fn nightshift_authoring_export(
        &self,
        campaign: &str,
        occurrence: &str,
    ) -> SourceResultV1<NightshiftAuthoringContextExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportAuthoringContext,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportAuthoringContext {
                campaign: campaign.to_owned(),
                occurrence: occurrence.to_owned(),
            },
            |value: &NightshiftAuthoringContextExportV1| {
                value.validate_for_occurrence(campaign, occurrence)
            },
        )
    }

    fn docket_inspect(&self, issuance: &str) -> SourceResultV1<DocketInspectionV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.docket.as_ref())
        else {
            return unavailable(
                "Docket",
                ReadCommandNameV1::DocketGovernedLoopInspect,
                SourceErrorKindV1::NotConfigured,
                "Docket source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Docket",
            &CanonicalReadRequestV1::DocketInspect(issuance.to_owned()),
            |value: &DocketInspectionV1| validate_docket(value, issuance),
        )
    }

    fn nightshift_authoring_custody_export(
        &self,
        campaign: &str,
        occurrence: &str,
    ) -> SourceResultV1<NightshiftAuthoringCustodyExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportAuthoringCustody,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportAuthoringCustody {
                campaign: campaign.to_owned(),
                occurrence: occurrence.to_owned(),
            },
            |value: &NightshiftAuthoringCustodyExportV1| {
                value.validate_for_occurrence(campaign, occurrence)
            },
        )
    }

    fn nightshift_external_observation_export(
        &self,
        campaign: &str,
        occurrence: &str,
    ) -> SourceResultV1<ExternalObservationExportV1> {
        let Some(_) = &self
            .canonical_config()
            .ok()
            .and_then(|value| value.nightshift.as_ref())
        else {
            return unavailable(
                "Nightshift",
                ReadCommandNameV1::NightshiftExportExternalObservation,
                SourceErrorKindV1::NotConfigured,
                "Nightshift source is not configured".to_owned(),
                None,
            );
        };
        let evaluated_at_unix_ms = i64::try_from(capture_time()).unwrap_or(i64::MAX);
        self.capture_typed(
            "Nightshift",
            &CanonicalReadRequestV1::NightshiftExportExternalObservation {
                campaign: campaign.to_owned(),
                occurrence: occurrence.to_owned(),
                evaluated_at_unix_ms,
                evidence_ttl_ms: EXTERNAL_OBSERVATION_DISPLAY_TTL_MS,
            },
            |value: &ExternalObservationExportV1| {
                value.validate_for_occurrence(campaign, occurrence)
            },
        )
    }

    fn capture_typed<T>(
        &self,
        source: &str,
        request: &CanonicalReadRequestV1,
        validate: impl FnOnce(&T) -> Result<(), String>,
    ) -> SourceResultV1<T>
    where
        T: DeserializeOwned,
    {
        let command = request.name();
        match self.capture_json(request) {
            Ok(captured) => {
                let typed = match serde_json::from_value::<T>(captured.raw.clone()) {
                    Ok(value) => value,
                    Err(error) => {
                        return unavailable_at(
                            source,
                            command,
                            captured.captured_at_unix_ms,
                            SourceErrorKindV1::MalformedOutput,
                            format!("typed canonical output refused: {error}"),
                            None,
                        );
                    }
                };
                if let Err(error) = validate(&typed) {
                    return unavailable_at(
                        source,
                        command,
                        captured.captured_at_unix_ms,
                        SourceErrorKindV1::IncompatibleSchema,
                        error,
                        None,
                    );
                }
                SourceResultV1::Available {
                    source: source.to_owned(),
                    command,
                    captured_at_unix_ms: captured.captured_at_unix_ms,
                    value: typed,
                    raw: captured.raw,
                }
            }
            Err(error) => unavailable(source, command, error.kind, error.detail, error.exit_status),
        }
    }

    fn capture_json(
        &self,
        request: &CanonicalReadRequestV1,
    ) -> Result<CapturedJsonV1, CaptureFailureV1> {
        let config = self.canonical_config().map_err(|detail| CaptureFailureV1 {
            kind: SourceErrorKindV1::Unavailable,
            detail,
            exit_status: None,
        })?;
        let mut command = canonical_command(config, request)?;
        let bytes = run_bounded(&mut command)?;
        let captured_at_unix_ms = capture_time();
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let raw = Value::deserialize(&mut deserializer).map_err(|error| CaptureFailureV1 {
            kind: SourceErrorKindV1::MalformedOutput,
            detail: format!("canonical command output is not JSON: {error}"),
            exit_status: Some(0),
        })?;
        deserializer.end().map_err(|error| CaptureFailureV1 {
            kind: SourceErrorKindV1::MalformedOutput,
            detail: format!("canonical command output has trailing data: {error}"),
            exit_status: Some(0),
        })?;
        Ok(CapturedJsonV1 {
            captured_at_unix_ms,
            raw,
        })
    }

    fn canonical_config(&self) -> Result<&OperatorSourceConfigV1, String> {
        match &self.backend {
            OperatorReaderBackendV1::Canonical(config) => Ok(config),
            OperatorReaderBackendV1::Demo(_) => {
                Err("demo corpus has no executable canonical source".to_owned())
            }
        }
    }
}

fn canonical_command(
    config: &OperatorSourceConfigV1,
    request: &CanonicalReadRequestV1,
) -> Result<Command, CaptureFailureV1> {
    let command = match request {
        CanonicalReadRequestV1::AgInspect(database)
        | CanonicalReadRequestV1::AgStatus(database)
        | CanonicalReadRequestV1::AgReplay(database)
        | CanonicalReadRequestV1::AgHistory(database)
        | CanonicalReadRequestV1::AgRefusals(database)
        | CanonicalReadRequestV1::AgInterventionSubmissions(database) => {
            let verb = match request {
                CanonicalReadRequestV1::AgInspect(_) => "inspect",
                CanonicalReadRequestV1::AgStatus(_) => "status",
                CanonicalReadRequestV1::AgReplay(_) => "replay",
                CanonicalReadRequestV1::AgHistory(_) => "history",
                CanonicalReadRequestV1::AgRefusals(_) => "refusals",
                CanonicalReadRequestV1::AgInterventionSubmissions(_) => "intervention-submissions",
                _ => unreachable!(),
            };
            let mut command = Command::new(&config.ag_loopctl);
            command.args([verb, "--database"]).arg(database);
            command
        }
        CanonicalReadRequestV1::NightshiftExportObservation(observation) => {
            let source = require_nightshift_source(config)?;
            let mut command = Command::new(&source.program);
            command.args(["--store"]).arg(&source.store).args([
                "cycle",
                "export-observation",
                "--observation-id",
                observation,
            ]);
            command
        }
        CanonicalReadRequestV1::NightshiftExportAuthoringContext {
            campaign,
            occurrence,
        }
        | CanonicalReadRequestV1::NightshiftExportAuthoringCustody {
            campaign,
            occurrence,
        } => {
            let source = require_nightshift_source(config)?;
            let verb = match request {
                CanonicalReadRequestV1::NightshiftExportAuthoringContext { .. } => {
                    "export-authoring-context"
                }
                CanonicalReadRequestV1::NightshiftExportAuthoringCustody { .. } => {
                    "export-authoring-custody"
                }
                _ => unreachable!(),
            };
            let mut command = Command::new(&source.program);
            command.args(["--store"]).arg(&source.store).args([
                "cycle",
                verb,
                "--campaign-id",
                campaign,
                "--occurrence-id",
                occurrence,
            ]);
            command
        }
        CanonicalReadRequestV1::NightshiftExportExternalObservation {
            campaign,
            occurrence,
            evaluated_at_unix_ms,
            evidence_ttl_ms,
        } => {
            let source = require_nightshift_source(config)?;
            let mut command = Command::new(&source.program);
            let evaluated_at_unix_ms = evaluated_at_unix_ms.to_string();
            let evidence_ttl_ms = evidence_ttl_ms.to_string();
            command.args(["--store"]).arg(&source.store).args([
                "external-observation",
                "export",
                "--campaign-id",
                campaign,
                "--occurrence-id",
                occurrence,
                "--evaluated-at-unix-ms",
                &evaluated_at_unix_ms,
                "--evidence-ttl-ms",
                &evidence_ttl_ms,
            ]);
            command
        }
        CanonicalReadRequestV1::DocketInspect(issuance) => {
            let source = config.docket.as_ref().ok_or_else(|| CaptureFailureV1 {
                kind: SourceErrorKindV1::NotConfigured,
                detail: "Docket source is not configured".to_owned(),
                exit_status: None,
            })?;
            let mut command = Command::new(&source.program);
            command
                .args(["governed-loop", "inspect", "--state"])
                .arg(&source.state)
                .args(["--issuance", issuance]);
            command
        }
    };
    Ok(command)
}

fn require_nightshift_source(
    config: &OperatorSourceConfigV1,
) -> Result<&NightshiftReadSourceV1, CaptureFailureV1> {
    config.nightshift.as_ref().ok_or_else(|| CaptureFailureV1 {
        kind: SourceErrorKindV1::NotConfigured,
        detail: "Nightshift source is not configured".to_owned(),
        exit_status: None,
    })
}

fn validate_demo_corpus(corpus: &DemoCorpusV1) -> Result<(), String> {
    if corpus.schema != DEMO_CORPUS_SCHEMA_V1
        || corpus.index.schema != CAMPAIGN_INDEX_SCHEMA_V1
        || corpus.campaigns.len() > MAX_DEMO_CAMPAIGNS
    {
        return Err("unsupported or oversized demo corpus".to_owned());
    }
    let details = corpus
        .campaigns
        .iter()
        .map(|detail| (detail.locator_token.as_str(), detail))
        .collect::<BTreeMap<_, _>>();
    if details.len() != corpus.campaigns.len()
        || details.len() != corpus.index.campaigns.len()
        || corpus.index.campaigns.iter().any(|entry| {
            details
                .get(entry.locator_token.as_str())
                .is_none_or(|detail| detail.locator != entry.locator)
        })
    {
        return Err("demo corpus index/detail locator binding mismatch".to_owned());
    }
    for detail in &corpus.campaigns {
        validate_demo_detail(detail)?;
    }
    let mut semantic_keys = BTreeSet::new();
    for target in &corpus.semantic_link_targets {
        let key = (
            target.campaign.as_str().to_owned(),
            target.occurrence.to_string(),
            target
                .proposal
                .as_ref()
                .map(|proposal| proposal.as_str().to_owned()),
        );
        if !semantic_keys.insert(key) {
            return Err("duplicate demo semantic link target".to_owned());
        }
        let detail = details
            .get(target.locator_token.as_str())
            .ok_or_else(|| "demo semantic link target names an unknown locator".to_owned())?;
        let link = GovernedRuntimeLinkV1 {
            campaign: target.campaign.as_digest().clone(),
            occurrence: target.occurrence,
            proposal: target
                .proposal
                .as_ref()
                .map(|proposal| proposal.as_digest().clone()),
        };
        if !detail_matches_link(detail, &link) {
            return Err("demo semantic link target does not bind its exact identities".to_owned());
        }
    }
    Ok(())
}

fn demo_target_matches(
    target: &crate::model::DemoSemanticLinkTargetV1,
    link: &GovernedRuntimeLinkV1,
) -> bool {
    target.campaign.as_digest() == &link.campaign
        && target.occurrence == link.occurrence
        && target
            .proposal
            .as_ref()
            .map(ag_campaign::governed::ProposalRefV1::as_digest)
            == link.proposal.as_ref()
}

fn index_entry_matches_link(entry: &CampaignIndexEntryV1, link: &GovernedRuntimeLinkV1) -> bool {
    entry
        .inspect
        .value()
        .and_then(|inspect| snapshot_for_link(&inspect.current, entry.history.value(), link))
        .is_some()
}

fn detail_matches_link(detail: &CampaignDetailV1, link: &GovernedRuntimeLinkV1) -> bool {
    selected_snapshot(detail, link).is_some()
}

/// Selects the most recent verified snapshot of the exact linked occurrence.
/// A supplied proposal identity must match that snapshot exactly.
#[must_use]
pub fn selected_snapshot<'a>(
    detail: &'a CampaignDetailV1,
    link: &GovernedRuntimeLinkV1,
) -> Option<&'a OccurrenceSnapshotV1> {
    let current = detail.inspect.value().map(|inspect| &inspect.current)?;
    snapshot_for_link(current, detail.history.value(), link)
}

fn snapshot_for_link<'a>(
    current: &'a OccurrenceSnapshotV1,
    history: Option<&'a CampaignTransitionHistoryV1>,
    link: &GovernedRuntimeLinkV1,
) -> Option<&'a OccurrenceSnapshotV1> {
    let candidate = if current.key().occurrence == link.occurrence {
        Some(current)
    } else {
        history.and_then(|history| {
            history
                .transitions
                .iter()
                .rev()
                .map(|transition| &transition.successor)
                .find(|snapshot| snapshot.key().occurrence == link.occurrence)
        })
    }?;
    if candidate.key().campaign.as_digest() != &link.campaign {
        return None;
    }
    if let Some(expected) = &link.proposal {
        let actual = candidate.proposal()?.reference();
        if actual.as_digest() != expected {
            return None;
        }
    }
    Some(candidate)
}

fn validate_demo_detail(detail: &CampaignDetailV1) -> Result<(), String> {
    if detail.schema != CAMPAIGN_DETAIL_SCHEMA_V1 {
        return Err("unsupported demo campaign-detail schema".to_owned());
    }
    validate_source_raw(&detail.inspect)?;
    validate_source_raw(&detail.status)?;
    validate_source_raw(&detail.replay)?;
    validate_source_raw(&detail.history)?;
    validate_source_raw(&detail.refusals)?;
    if let Some(value) = detail.inspect.value() {
        value.validate()?;
    }
    if let Some(value) = detail.status.value() {
        value
            .validate_integrity()
            .map_err(|error| format!("demo status integrity: {error}"))?;
    }
    for related in &detail.nightshift {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            value.validate(&related.identity)?;
        }
    }
    for related in &detail.authoring_contexts {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            let NightshiftAuthoringContextQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } = &value.query
            else {
                return Err("demo authoring-context query is not occurrence-scoped".to_owned());
            };
            value.validate_for_occurrence(campaign_id, occurrence_id)?;
            if related.identity != format!("{campaign_id}/{occurrence_id}") {
                return Err("demo authoring-context related identity drift".to_owned());
            }
        }
    }
    for related in &detail.authoring_custody {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            let NightshiftAuthoringContextQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } = &value.query
            else {
                return Err("demo authoring-custody query is not occurrence-scoped".to_owned());
            };
            value.validate_for_occurrence(campaign_id, occurrence_id)?;
            if related.identity != format!("{campaign_id}/{occurrence_id}") {
                return Err("demo authoring-custody related identity drift".to_owned());
            }
        }
    }
    for related in &detail.external_observations {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            let crate::model::ExternalObservationQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } = &value.query
            else {
                return Err("demo external-observation query is not occurrence-scoped".to_owned());
            };
            value.validate_for_occurrence(campaign_id, occurrence_id)?;
            if related.identity != format!("{campaign_id}/{occurrence_id}") {
                return Err("demo external-observation related identity drift".to_owned());
            }
        }
    }
    for related in &detail.docket {
        validate_source_raw(&related.result)?;
        if let Some(value) = related.result.value() {
            validate_docket(value, &related.identity)?;
        }
    }
    Ok(())
}

fn validate_source_raw<T: serde::Serialize>(source: &SourceResultV1<T>) -> Result<(), String> {
    if let SourceResultV1::Available { value, raw, .. } = source
        && serde_json::to_value(value).map_err(|error| error.to_string())? != *raw
    {
        return Err("demo typed value/raw canonical capture drift".to_owned());
    }
    Ok(())
}

fn require_program_name(path: &Path, expected: &str) -> Result<(), String> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some(expected) {
        return Err(format!(
            "read source must be the absolute canonical {expected} executable"
        ));
    }
    Ok(())
}

fn discover_stores(root: &Path) -> Result<Vec<(String, String, PathBuf)>, String> {
    let mut stores = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| format!("read campaign root: {error}"))? {
        let entry = entry.map_err(|error| format!("read campaign entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read campaign entry type: {error}"))?;
        if !file_type.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("sqlite")
        {
            continue;
        }
        let name = entry.file_name();
        let token = hex_encode(name.as_bytes());
        stores.push((token, name.to_string_lossy().into_owned(), entry.path()));
    }
    Ok(stores)
}

fn collect_related(
    snapshot: &OccurrenceSnapshotV1,
    observations: &mut BTreeSet<String>,
    issuances: &mut BTreeSet<String>,
) {
    if let Some(observation) = snapshot.observation() {
        observations.insert(observation.observation.as_str().to_owned());
    }
    if let Some(completed) = snapshot.completed() {
        observations.insert(
            completed
                .terminal_observation()
                .observation
                .as_str()
                .to_owned(),
        );
    }
    if let Some(issuance) = snapshot.issuance() {
        issuances.insert(issuance.issuance.as_str().to_owned());
    }
}

fn collect_occurrence(
    snapshot: &OccurrenceSnapshotV1,
    occurrences: &mut BTreeSet<(String, String)>,
) {
    occurrences.insert((
        snapshot.key().campaign.to_string(),
        snapshot.key().occurrence.to_string(),
    ));
}

fn projection_check(
    inspect: Option<&AgInspectV1>,
    status: Option<&OccurrenceSnapshotV1>,
    replay: Option<&CampaignReplayReportV1>,
    history: Option<&CampaignTransitionHistoryV1>,
    refusals: Option<&CampaignRefusalHistoryV1>,
    availability: &[bool],
) -> ProjectionCheckV1 {
    let mut coordinates = Vec::new();
    if let Some(value) = inspect {
        coordinates.push((
            "inspect",
            value.current.key().campaign.as_str(),
            value.current.state_digest().as_str(),
        ));
    }
    if let Some(value) = status {
        coordinates.push((
            "status",
            value.key().campaign.as_str(),
            value.state_digest().as_str(),
        ));
    }
    if let Some(value) = replay {
        coordinates.push((
            "replay",
            value.campaign.as_str(),
            value.current_state_digest.as_str(),
        ));
    }
    if let Some(value) = history {
        coordinates.push((
            "history",
            value.campaign.as_str(),
            value.current_state_digest.as_str(),
        ));
    }
    if let Some(value) = refusals {
        coordinates.push((
            "refusals",
            value.campaign.as_str(),
            value.verified_at_state_digest.as_str(),
        ));
    }
    let disagreement = coordinates
        .windows(2)
        .any(|pair| pair[0].1 != pair[1].1 || pair[0].2 != pair[1].2);
    let correspondence = if disagreement {
        ProjectionCorrespondenceV1::Disagreement
    } else if availability.iter().all(|available| *available) {
        ProjectionCorrespondenceV1::Exact
    } else {
        ProjectionCorrespondenceV1::Partial
    };
    let mut findings = coordinates
        .iter()
        .map(|(source, campaign, digest)| {
            format!("{source}: campaign={campaign}, current_state={digest}")
        })
        .collect::<Vec<_>>();
    if availability.iter().any(|available| !*available) {
        findings.push("one or more canonical AG projections are unavailable".to_owned());
    }
    if disagreement {
        findings.push("canonical AG projections disagree; no value was reconciled".to_owned());
    }
    ProjectionCheckV1 {
        correspondence,
        findings,
    }
}

fn validate_docket(value: &DocketInspectionV1, issuance: &str) -> Result<(), String> {
    if value.schema != DOCKET_INSPECTION_SCHEMA_V1 {
        return Err(format!(
            "unsupported Docket inspection schema {}",
            value.schema
        ));
    }
    if value.requested_issuance != issuance {
        return Err("Docket inspection substituted issuance identity".to_owned());
    }
    let Some(record) = &value.record else {
        return Ok(());
    };
    if record.issuance.issuance.as_str() != issuance
        || record.custody.issuance.as_str() != issuance
        || record.custody.ag_spend != record.issuance.spend
    {
        return Err("Docket inspection issuance/custody binding mismatch".to_owned());
    }
    match record.status {
        crate::model::DocketRecordStatusV1::Accepted => {
            if record.settlement.is_some() || record.indeterminate.is_some() {
                return Err("Docket accepted record has outcome fields".to_owned());
            }
        }
        crate::model::DocketRecordStatusV1::Settled => {
            let settlement = record
                .settlement
                .as_ref()
                .ok_or_else(|| "Docket settled record lacks settlement".to_owned())?;
            if record.indeterminate.is_some()
                || settlement.issuance.as_str() != issuance
                || settlement.attempt != record.custody.attempt
            {
                return Err("Docket custody/settlement binding mismatch".to_owned());
            }
        }
        crate::model::DocketRecordStatusV1::Indeterminate => {
            let indeterminate = record
                .indeterminate
                .as_ref()
                .ok_or_else(|| "Docket indeterminate record lacks evidence".to_owned())?;
            if record.settlement.is_some()
                || indeterminate.issuance.as_str() != issuance
                || indeterminate.attempt != record.custody.attempt
            {
                return Err("Docket custody/indeterminate binding mismatch".to_owned());
            }
        }
    }
    Ok(())
}

fn run_bounded(command: &mut Command) -> Result<Vec<u8>, CaptureFailureV1> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CaptureFailureV1 {
            kind: if error.kind() == std::io::ErrorKind::NotFound {
                SourceErrorKindV1::Missing
            } else {
                SourceErrorKindV1::Unavailable
            },
            detail: format!("canonical command could not start: {error}"),
            exit_status: None,
        })?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || read_bounded(stdout, MAX_STDOUT_BYTES));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES));
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CaptureFailureV1 {
                    kind: SourceErrorKindV1::Timeout,
                    detail: "canonical read command exceeded 5 seconds".to_owned(),
                    exit_status: None,
                });
            }
            Err(error) => {
                return Err(CaptureFailureV1 {
                    kind: SourceErrorKindV1::Unavailable,
                    detail: format!("canonical command wait failed: {error}"),
                    exit_status: None,
                });
            }
        }
    };
    let stdout = stdout_reader.join().map_err(|_| CaptureFailureV1 {
        kind: SourceErrorKindV1::Unavailable,
        detail: "canonical command stdout reader failed".to_owned(),
        exit_status: status.code(),
    })??;
    let stderr = stderr_reader.join().map_err(|_| CaptureFailureV1 {
        kind: SourceErrorKindV1::Unavailable,
        detail: "canonical command stderr reader failed".to_owned(),
        exit_status: status.code(),
    })??;
    if !status.success() {
        return Err(CaptureFailureV1 {
            kind: SourceErrorKindV1::CommandRefused,
            detail: format!(
                "canonical command refused: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
            exit_status: status.code(),
        });
    }
    Ok(stdout)
}

fn read_bounded(mut stream: impl Read, limit: u64) -> Result<Vec<u8>, CaptureFailureV1> {
    let mut bytes = Vec::new();
    stream
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CaptureFailureV1 {
            kind: SourceErrorKindV1::Unavailable,
            detail: format!("canonical command output read failed: {error}"),
            exit_status: None,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(CaptureFailureV1 {
            kind: SourceErrorKindV1::OutputTooLarge,
            detail: format!("canonical command output exceeded {limit} bytes"),
            exit_status: None,
        });
    }
    Ok(bytes)
}

fn unavailable<T>(
    source: &str,
    command: ReadCommandNameV1,
    error_kind: SourceErrorKindV1,
    detail: String,
    exit_status: Option<i32>,
) -> SourceResultV1<T> {
    unavailable_at(
        source,
        command,
        capture_time(),
        error_kind,
        detail,
        exit_status,
    )
}

fn unavailable_at<T>(
    source: &str,
    command: ReadCommandNameV1,
    captured_at_unix_ms: u64,
    error_kind: SourceErrorKindV1,
    detail: String,
    exit_status: Option<i32>,
) -> SourceResultV1<T> {
    SourceResultV1::Unavailable {
        source: source.to_owned(),
        command,
        captured_at_unix_ms,
        error_kind,
        detail,
        exit_status,
    }
}

fn capture_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

/// Encodes an operational locator into an opaque URL token.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[allow(dead_code, reason = "kept adjacent to encoding for route-level tests")]
fn decode_locator(token: &str) -> Result<OsString, String> {
    if !token.len().is_multiple_of(2) || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid locator token".to_owned());
    }
    let mut bytes = Vec::with_capacity(token.len() / 2);
    for pair in token.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| "invalid locator token".to_owned())?;
        bytes.push(u8::from_str_radix(text, 16).map_err(|_| "invalid locator token".to_owned())?);
    }
    Ok(OsString::from_vec(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn locator_token_round_trips_without_becoming_campaign_identity() {
        let locator = OsString::from_vec(b"campaign one.sqlite".to_vec());
        let token = hex_encode(locator.as_bytes());
        assert_eq!(decode_locator(&token).unwrap(), locator);
        assert!(decode_locator("../campaign.sqlite").is_err());
    }

    #[test]
    fn configured_program_names_are_closed() {
        assert!(require_program_name(Path::new("/opt/ag-loopctl"), "ag-loopctl").is_ok());
        assert!(require_program_name(Path::new("/opt/other"), "ag-loopctl").is_err());
        assert!(require_program_name(Path::new("ag-loopctl"), "ag-loopctl").is_err());
    }

    #[test]
    fn malformed_canonical_output_stays_visible_and_is_not_inferred() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("campaign.sqlite"), b"not a database").unwrap();
        let program = root.path().join("ag-loopctl");
        std::fs::write(&program, b"#!/bin/sh\nprintf '{} trailing'\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: program,
            nightshift: None,
            docket: None,
        })
        .unwrap();
        let index = reader.campaign_index().unwrap();
        assert_eq!(index.campaigns.len(), 1);
        assert!(matches!(
            index.campaigns[0].inspect,
            SourceResultV1::Unavailable {
                error_kind: SourceErrorKindV1::MalformedOutput,
                ..
            }
        ));
        assert_eq!(
            index.campaigns[0].projection.correspondence,
            ProjectionCorrespondenceV1::Partial
        );
    }

    #[test]
    fn owner_schema_and_identity_substitution_are_refused() {
        let nightshift = NightshiftObservationExportV1 {
            schema: "nightshift.observation_export.v2".to_owned(),
            observation_id: "observation-b".to_owned(),
            matches: Vec::new(),
        };
        assert!(nightshift.validate("observation-a").is_err());

        let docket = DocketInspectionV1 {
            schema: DOCKET_INSPECTION_SCHEMA_V1.to_owned(),
            requested_issuance: "issuance-b".to_owned(),
            record: None,
        };
        assert!(validate_docket(&docket, "issuance-a").is_err());
    }

    #[test]
    fn authoring_context_uses_only_the_closed_nightshift_read_verb() {
        let root = tempfile::tempdir().unwrap();
        let ag = root.path().join("ag-loopctl");
        std::fs::write(&ag, b"#!/bin/sh\nexit 1\n").unwrap();
        let nightshift = root.path().join("nightshift");
        let arguments = root.path().join("nightshift-arguments");
        let campaign = ag_primitives::Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-0000-0000-000000000001";
        let payload = serde_json::json!({
            "schema": crate::model::NIGHTSHIFT_AUTHORING_CONTEXT_EXPORT_SCHEMA_V1,
            "query": {
                "by": "governed_occurrence",
                "campaign_id": campaign,
                "occurrence_id": occurrence,
            },
            "matches": [],
        });
        std::fs::write(
            &nightshift,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                payload
            )
            .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&ag, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nightshift, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: ag,
            nightshift: Some(NightshiftReadSourceV1 {
                program: nightshift,
                store: root.path().join("nightshift.sqlite"),
            }),
            docket: None,
        })
        .unwrap();
        let result = reader.nightshift_authoring_export(&campaign, occurrence);
        assert!(matches!(
            result,
            SourceResultV1::Available {
                command: ReadCommandNameV1::NightshiftExportAuthoringContext,
                value: NightshiftAuthoringContextExportV1 { matches, .. },
                ..
            } if matches.is_empty()
        ));
        assert_eq!(
            std::fs::read_to_string(arguments).unwrap(),
            format!(
                "--store\n{}\ncycle\nexport-authoring-context\n--campaign-id\n{}\n--occurrence-id\n{}\n",
                root.path().join("nightshift.sqlite").display(),
                campaign,
                occurrence,
            )
        );
    }

    #[test]
    fn authoring_custody_uses_only_the_closed_nightshift_read_verb() {
        let root = tempfile::tempdir().unwrap();
        let ag = root.path().join("ag-loopctl");
        std::fs::write(&ag, b"#!/bin/sh\nexit 1\n").unwrap();
        let nightshift = root.path().join("nightshift");
        let arguments = root.path().join("nightshift-arguments");
        let campaign = ag_primitives::Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-0000-0000-000000000001";
        let payload = serde_json::json!({
            "schema": crate::model::NIGHTSHIFT_AUTHORING_CUSTODY_EXPORT_SCHEMA_V1,
            "query": {
                "by": "governed_occurrence",
                "campaign_id": campaign,
                "occurrence_id": occurrence,
            },
            "matches": [],
        });
        std::fs::write(
            &nightshift,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                payload
            )
            .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&ag, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nightshift, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: ag,
            nightshift: Some(NightshiftReadSourceV1 {
                program: nightshift,
                store: root.path().join("nightshift.sqlite"),
            }),
            docket: None,
        })
        .unwrap();
        let result = reader.nightshift_authoring_custody_export(&campaign, occurrence);
        assert!(matches!(
            result,
            SourceResultV1::Available {
                command: ReadCommandNameV1::NightshiftExportAuthoringCustody,
                value: NightshiftAuthoringCustodyExportV1 { matches, .. },
                ..
            } if matches.is_empty()
        ));
        assert_eq!(
            std::fs::read_to_string(arguments).unwrap(),
            format!(
                "--store\n{}\ncycle\nexport-authoring-custody\n--campaign-id\n{}\n--occurrence-id\n{}\n",
                root.path().join("nightshift.sqlite").display(),
                campaign,
                occurrence,
            )
        );
    }

    #[test]
    fn external_observation_uses_only_occurrence_scoped_read_verb() {
        let root = tempfile::tempdir().unwrap();
        let ag = root.path().join("ag-loopctl");
        std::fs::write(&ag, b"#!/bin/sh\nexit 1\n").unwrap();
        let nightshift = root.path().join("nightshift");
        let arguments = root.path().join("nightshift-arguments");
        let campaign = ag_primitives::Digest::hash_bytes(b"campaign").to_string();
        let occurrence = "00000000-0000-0000-0000-000000000001";
        let payload = serde_json::json!({
            "schema": crate::model::NIGHTSHIFT_EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1,
            "query": {
                "kind": "governed_occurrence",
                "campaign_id": campaign,
                "occurrence_id": occurrence,
            },
            "matches": [],
        });
        std::fs::write(
            &nightshift,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
                arguments.display(),
                payload
            )
            .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&ag, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nightshift, std::fs::Permissions::from_mode(0o700)).unwrap();
        let reader = OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: root.path().to_owned(),
            ag_loopctl: ag,
            nightshift: Some(NightshiftReadSourceV1 {
                program: nightshift,
                store: root.path().join("nightshift.sqlite"),
            }),
            docket: None,
        })
        .unwrap();
        let result = reader.nightshift_external_observation_export(&campaign, occurrence);
        assert!(matches!(
            result,
            SourceResultV1::Available {
                command: ReadCommandNameV1::NightshiftExportExternalObservation,
                value: ExternalObservationExportV1 { matches, .. },
                ..
            } if matches.is_empty()
        ));
        let arguments = std::fs::read_to_string(arguments).unwrap();
        assert!(arguments.contains("\nexternal-observation\nexport\n"));
        assert!(arguments.contains(&format!(
            "--campaign-id\n{campaign}\n--occurrence-id\n{occurrence}\n"
        )));
        assert!(arguments.contains(&format!(
            "--evidence-ttl-ms\n{EXTERNAL_OBSERVATION_DISPLAY_TTL_MS}\n"
        )));
        assert!(!arguments.contains("cycle\nrun"));
    }

    #[test]
    fn deterministic_corpus_is_typed_bounded_and_does_not_need_commands() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corpus.json");
        let corpus = DemoCorpusV1 {
            schema: DEMO_CORPUS_SCHEMA_V1.to_owned(),
            generated_by: "test".to_owned(),
            canonical_schemas: vec![crate::model::AG_INSPECT_SCHEMA_V1.to_owned()],
            index: CampaignIndexV1 {
                schema: CAMPAIGN_INDEX_SCHEMA_V1.to_owned(),
                campaigns: Vec::new(),
            },
            campaigns: Vec::new(),
            semantic_link_targets: Vec::new(),
        };
        std::fs::write(&path, serde_json::to_vec(&corpus).unwrap()).unwrap();
        let reader = OperatorReaderV1::from_demo_corpus(&path).unwrap();
        assert_eq!(reader.mode_label(), "deterministic demo corpus");
        assert!(reader.campaign_index().unwrap().campaigns.is_empty());
    }

    #[test]
    fn corpus_index_detail_drift_is_refused() {
        let corpus = DemoCorpusV1 {
            schema: DEMO_CORPUS_SCHEMA_V1.to_owned(),
            generated_by: "test".to_owned(),
            canonical_schemas: Vec::new(),
            index: CampaignIndexV1 {
                schema: CAMPAIGN_INDEX_SCHEMA_V1.to_owned(),
                campaigns: Vec::new(),
            },
            campaigns: vec![],
            semantic_link_targets: Vec::new(),
        };
        let mut drifted = corpus;
        drifted.index.campaigns.push(CampaignIndexEntryV1 {
            locator_token: "00".to_owned(),
            locator: "missing.sqlite".to_owned(),
            inspect: unavailable(
                "AG",
                ReadCommandNameV1::AgInspect,
                SourceErrorKindV1::Missing,
                "fixture".to_owned(),
                None,
            ),
            history: unavailable(
                "AG",
                ReadCommandNameV1::AgHistory,
                SourceErrorKindV1::Missing,
                "fixture".to_owned(),
                None,
            ),
            refusals: unavailable(
                "AG",
                ReadCommandNameV1::AgRefusals,
                SourceErrorKindV1::Missing,
                "fixture".to_owned(),
                None,
            ),
            projection: ProjectionCheckV1 {
                correspondence: ProjectionCorrespondenceV1::Partial,
                findings: Vec::new(),
            },
        });
        assert!(validate_demo_corpus(&drifted).is_err());
    }
}
