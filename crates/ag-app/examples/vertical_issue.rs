//! Vertical harness: run one real authorization through AG ng's issuance path.
//! Not part of the shipped surface; used to produce the vertical specimen.
use ag_app::docket_issuance::{
    AuthorizationPremiseV1, DocketIssuanceOffice, DocketTargetCatalogV1, DocketTargetDefinitionV1,
    IssuanceDecisionContextV1, IssuanceDecisionLedger, IssuanceSigner, ResidualObligationsV1,
    ResidualStatusV1, decode_request,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::collections::BTreeMap;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request_path = &args[0];
    let out_path = &args[1];
    let trust_out = &args[2];
    let repo = &args[3];
    let target_ref = &args[4];
    let now: u64 = args[5].parse().unwrap();
    let bytes = std::fs::read(request_path).unwrap();
    let req = match decode_request(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("REFUSED decode: {e}");
            std::process::exit(2);
        }
    };
    let mut targets = BTreeMap::new();
    targets.insert(
        "docket-vertical".to_string(),
        DocketTargetDefinitionV1 {
            target_id: "docket-vertical".into(),
            repository: repo.clone(),
            target_ref: target_ref.clone(),
            effect_class: "git-ref-update:v1".into(),
            admitted_actors: vec!["operator".into()],
            admitted_path_prefixes: vec!["docs".into(), "README.md".into()],
        },
    );
    let catalog = DocketTargetCatalogV1 {
        identity: "sha256:vertical-catalog-v1".into(),
        targets,
    };
    let office = DocketIssuanceOffice {
        catalog: &catalog,
        context: IssuanceDecisionContextV1 {
            authority_domain: "vertical.local".into(),
            epoch: 1,
            lifecycle_nonce: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f".into(),
            catalog_identity: "sha256:vertical-catalog-v1".into(),
        },
        principal_chain: vec!["root".into(), "issuer".into()],
        issuer_principal: "issuer".into(),
    };
    let decision = match office.decide(&req) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("REFUSED decide: {e}");
            std::process::exit(3);
        }
    };
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signer = IssuanceSigner::from_pkcs8("vertical-issuer-1", doc.as_ref()).unwrap();
    let mut ledger = IssuanceDecisionLedger::new();
    let env = office.issue(&req, &bytes, &decision, &mut ledger, &signer,
        now, now + 3_600_000,
        vec![AuthorizationPremiseV1 {
            kind: "principal_authentication".into(),
            statement: "the principal chain was authenticated by the local transport and is not re-verified at issuance".into(),
        }, AuthorizationPremiseV1 {
            kind: "target_catalog_binding".into(),
            statement: "the root-owned target catalog correctly describes the governed repository and reference".into(),
        }],
        ResidualObligationsV1 { status: ResidualStatusV1::Unrepresented, items: vec![] },
    ).unwrap();
    // Second issuance for the same decision must refuse: authority burns once.
    let second = office.issue(
        &req,
        &bytes,
        &decision,
        &mut ledger,
        &signer,
        now,
        now + 1000,
        vec![],
        ResidualObligationsV1 {
            status: ResidualStatusV1::Unrepresented,
            items: vec![],
        },
    );
    eprintln!("second_issuance_refused: {}", second.is_err());
    eprintln!("decision_id: {}", decision.decision_id());
    std::fs::write(out_path, serde_json::to_vec_pretty(&env).unwrap()).unwrap();
    std::fs::write(
        trust_out,
        serde_json::to_vec_pretty(&serde_json::json!({
            "issuers": [{
                "issuer_principal": "issuer",
                "key_id": "vertical-issuer-1",
                "public_key": signer.public_key_base64url(),
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    println!("issued");
}
