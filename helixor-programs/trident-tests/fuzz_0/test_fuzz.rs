use fuzz_accounts::*;
use trident_fuzz::fuzzing::*;
mod fuzz_accounts;
mod types;
use types::certificate_issuer::{
    program_id, InitializeConfigInstruction, InitializeConfigInstructionAccounts,
    InitializeConfigInstructionData,
};

#[derive(FuzzTestMethods)]
struct FuzzTest {
    /// Trident client for interacting with the Solana program
    trident: Trident,
    /// Storage for all account addresses used in fuzz testing
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl FuzzTest {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // Perform any initialization here, this method will be executed
        // at the start of each iteration
    }

    #[flow]
    fn flow1(&mut self) {
        let admin = self.trident.payer().pubkey();
        let issuer_config = self.fuzz_accounts.issuer_config.insert(
            &mut self.trident,
            Some(PdaSeeds::new(&[b"issuer_config"], program_id())),
        );
        let mut cluster_keys = vec![admin];
        for _ in 0..self.trident.random_from_range(0..6usize) {
            cluster_keys.push(Pubkey::new_unique());
        }
        let threshold = self.trident.random_from_range(0..7usize) as u8;
        let ix = InitializeConfigInstruction::data(InitializeConfigInstructionData::new(
            admin,
            cluster_keys,
            threshold,
        ))
        .accounts(InitializeConfigInstructionAccounts::new(issuer_config, admin))
        .instruction();
        let _ = self
            .trident
            .process_transaction(&[ix], Some("initialize_config"));
    }

    #[flow]
    fn flow2(&mut self) {
        // Re-run the same initialized/config flow. The expected result is
        // either success on a fresh PDA or a typed Anchor error on reuse; never
        // a panic.
        self.flow1();
    }

    #[end]
    fn end(&mut self) {
        // Perform any cleanup here, this method will be executed
        // at the end of each iteration
    }
}

fn main() {
    let iterations = std::env::var("HELIXOR_TRIDENT_ITERATIONS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1000);
    FuzzTest::fuzz(iterations, 100);
}
