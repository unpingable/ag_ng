//! Downstream compile and structural specimens for the single production AG
//! governed-repair seam. These checks make private mutable engines and raw
//! issuance signing unavailable to an external crate.

use std::fs;
use std::process::Command;

fn write_downstream_fixture(root: &std::path::Path) {
    let ag_app = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::create_dir_all(root.join("src/bin")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname='ag-product-boundary-specimen'\nversion='0.0.0'\nedition='2024'\n\n[dependencies]\nag-app={{path={:?}}}\nag-store={{path={:?}}}\nag-campaign={{path={:?}}}\n",
            ag_app.display().to_string(),
            ag_app.join("../ag-store").display().to_string(),
            ag_app.join("../ag-campaign").display().to_string(),
        ),
    )
    .unwrap();
    fs::write(
        root.join("src/bin/product.rs"),
        r"use ag_app::governed_product::{GovernedCampaignServiceV1, OccurrencePageRequestV1};
fn main() {
    let _ = core::mem::size_of::<GovernedCampaignServiceV1>();
    let _ = core::mem::size_of::<OccurrencePageRequestV1>();
}
",
    )
    .unwrap();
    fs::write(
        root.join("src/bin/forbidden.rs"),
        r"use ag_app::governed_loop::CampaignEngineV1;
use ag_app::governed_ports::AgIssuanceSignerV2;
use ag_store::campaign::CampaignStoreV1;
fn main() {
    let _ = core::mem::size_of::<CampaignEngineV1>();
    let _ = core::mem::size_of::<AgIssuanceSignerV2>();
    let _ = core::mem::size_of::<CampaignStoreV1>();
}
",
    )
    .unwrap();
}

fn cargo_check(root: &std::path::Path, binary: &str) -> std::process::Output {
    Command::new(env!("CARGO"))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .args(["check", "--offline", "--quiet", "--bin", binary])
        .output()
        .unwrap()
}

#[test]
fn downstream_can_compile_product_dtos_but_not_mutable_engines_or_raw_signers() {
    let directory = tempfile::tempdir().unwrap();
    write_downstream_fixture(directory.path());

    let product = cargo_check(directory.path(), "product");
    assert!(
        product.status.success(),
        "product contract must compile downstream: {}",
        String::from_utf8_lossy(&product.stderr)
    );

    let forbidden = cargo_check(directory.path(), "forbidden");
    assert!(!forbidden.status.success());
    let diagnostic = String::from_utf8_lossy(&forbidden.stderr);
    assert!(diagnostic.contains("module `governed_loop` is private"));
    assert!(diagnostic.contains("module `governed_ports` is private"));
    assert!(diagnostic.contains("could not find `campaign` in `ag_store`"));
}

#[test]
fn structural_surface_has_one_product_root_and_no_retired_mutator_or_bypass_feature() {
    let manifest = include_str!("../Cargo.toml");
    let library = include_str!("../src/lib.rs");
    let engine = include_str!("../src/governed_loop.rs");
    let ports = include_str!("../src/governed_ports.rs");
    let store = include_str!("../src/governed_store.rs");

    assert!(library.contains("pub mod governed_product;"));
    assert!(library.contains("mod governed_loop;"));
    assert!(library.contains("mod governed_ports;"));
    assert!(library.contains("mod governed_store;"));
    assert!(!library.contains("pub mod governed_loop;"));
    assert!(!library.contains("pub mod governed_ports;"));
    assert!(!library.contains("pub mod governed_store;"));
    assert!(!engine.contains("pub fn apply_human_disposition"));
    assert!(!store.contains("pub fn commit_human_disposition"));
    assert!(!ports.contains("pub struct AgIssuanceSignerV2"));
    assert!(!ports.contains("pub fn sign("));
    for forbidden in [
        "no-governor",
        "raw-signing",
        "legacy-repair",
        "authority-bypass",
    ] {
        assert!(!manifest.contains(forbidden));
    }

    let binary_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin");
    let product_clients = fs::read_dir(binary_root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|value| value == "rs"))
        .filter(|entry| {
            fs::read_to_string(entry.path())
                .unwrap()
                .contains("GovernedCampaignServiceV1")
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(product_clients, vec!["ag-loopctl.rs"]);
}
