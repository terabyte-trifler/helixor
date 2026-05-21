use trident_fuzz::fuzzing::*;

/// Storage for all account addresses used in fuzz testing.
///
/// This struct serves as a centralized repository for account addresses,
/// enabling their reuse across different instruction flows and test scenarios.
///
/// Docs: https://ackee.xyz/trident/docs/latest/trident-api-macro/trident-types/fuzz-accounts/
#[derive(Default)]
pub struct AccountAddresses {
    pub certificate: AddressStorage,

    pub issuer_config: AddressStorage,

    pub admin: AddressStorage,

    pub system_program: AddressStorage,

    pub baseline_stats: AddressStorage,

    pub issuer: AddressStorage,

    pub instructions_sysvar: AddressStorage,
}
