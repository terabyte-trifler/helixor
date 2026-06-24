// =============================================================================
// programs/certificate-issuer/tests/h05_signer_diversity.rs
//
// H-5 — fault-domain diversity in the threshold quorum.
//
// THE AUDIT FINDING
// -----------------
// verify_threshold_signatures tallied DISTINCT PUBKEYS >= threshold. Two
// cluster keys on a single compromised host both counted, so a single-host
// (or K-colluding-key) compromise could forge arbitrary cert content. The
// config stored bare pubkeys, foreclosing any on-chain diversity enforcement.
//
// THE FIX
// -------
// IssuerConfig gains cluster_key_domains (one fault-domain id per key). The
// quorum is now counted over DISTINCT DOMAINS: a quorum must span at least
// `threshold` independent host/region domains, so one compromised domain
// contributes at most one to the tally. initialize_config / rotate_cluster_keys
// require one domain per key and at least `threshold` distinct domains
// (otherwise the config is unsatisfiable).
//
// WHAT THIS FILE PINS (runtime-free)
// ----------------------------------
// The pure domain-tally helpers the on-chain gate is built on; the gate itself
// (verify_threshold_signatures) is exercised by the on-chain smoke path.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use certificate_issuer::state::IssuerConfig;

fn cfg(cluster_keys: Vec<Pubkey>, domains: Vec<u16>, threshold: u8) -> IssuerConfig {
    IssuerConfig {
        cluster_keys,
        cluster_key_domains: domains,
        threshold,
        ..Default::default()
    }
}

#[test]
fn config_distinct_domain_count_dedups() {
    assert_eq!(IssuerConfig::config_distinct_domain_count(&[0, 1, 2, 3, 4]), 5);
    assert_eq!(IssuerConfig::config_distinct_domain_count(&[0, 0, 1, 1, 2]), 3);
    assert_eq!(IssuerConfig::config_distinct_domain_count(&[7, 7, 7]), 1);
    assert_eq!(IssuerConfig::config_distinct_domain_count(&[]), 0);
}

#[test]
fn domain_of_key_maps_by_index() {
    let keys: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
    let c = cfg(keys.clone(), vec![10, 20, 20], 2);
    assert_eq!(c.domain_of_key(&keys[0]), Some(10));
    assert_eq!(c.domain_of_key(&keys[1]), Some(20));
    assert_eq!(c.domain_of_key(&keys[2]), Some(20));
    assert_eq!(c.domain_of_key(&Pubkey::new_unique()), None);
}

#[test]
fn two_keys_one_domain_count_once() {
    // The headline H-5 case: a 5-key cluster where keys 0,1 share domain A
    // (e.g. two HSMs on one host). A signer set of {k0, k1} spans ONE domain.
    let keys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
    // domains: A,A,B,C,D  (threshold 3)
    let c = cfg(keys.clone(), vec![0, 0, 1, 2, 3], 3);

    // A compromised single host holding k0+k1 -> 2 distinct PUBKEYS but only
    // ONE domain. Under the old rule this was 2 toward the threshold; now it
    // is 1, so it can never reach threshold 3 alone.
    assert_eq!(c.distinct_domain_count(&[keys[0], keys[1]]), 1);

    // Adding a second host (domain B) -> 2 domains; still short of 3.
    assert_eq!(c.distinct_domain_count(&[keys[0], keys[1], keys[2]]), 2);

    // Three independent domains (A, B, C) -> 3, meets threshold.
    assert_eq!(c.distinct_domain_count(&[keys[0], keys[2], keys[3]]), 3);
}

#[test]
fn distinct_domain_count_ignores_non_cluster_keys() {
    let keys: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
    let c = cfg(keys.clone(), vec![0, 1, 2], 2);
    let stranger = Pubkey::new_unique();
    // A non-cluster key contributes no domain.
    assert_eq!(c.distinct_domain_count(&[keys[0], stranger, keys[1]]), 2);
}

#[test]
fn legacy_empty_domain_map_degrades_to_pubkey_count() {
    // A pre-H-5 config (no domain map) must keep working: the diversity gate
    // degrades to the distinct-cluster-key count.
    let keys: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
    let c = cfg(keys.clone(), Vec::new(), 2); // empty domains
    assert_eq!(c.distinct_domain_count(&[keys[0], keys[1], keys[2]]), 3);
    let stranger = Pubkey::new_unique();
    assert_eq!(c.distinct_domain_count(&[keys[0], stranger]), 1);
}

#[test]
fn malformed_domain_map_also_degrades_safely() {
    // domains length != keys length -> treated as unconfigured (degrade).
    let keys: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
    let c = cfg(keys.clone(), vec![0, 1], 2); // wrong length
    assert_eq!(c.distinct_domain_count(&[keys[0], keys[1], keys[2]]), 3);
}
