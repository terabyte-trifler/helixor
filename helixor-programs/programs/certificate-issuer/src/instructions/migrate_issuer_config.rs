// =============================================================================
// migrate_issuer_config -- resize an existing pre-Day-27 IssuerConfig.
//
// Devnet carried an older 73-byte IssuerConfig account from the single-issuer
// era. Day 27 extended the account with cluster_keys + threshold, increasing
// its required size to IssuerConfig::SPACE. Because PDAs cannot be deleted by
// an operator wallet, the safe migration path is an authority-signed realloc.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::state::IssuerConfig;

#[derive(Accounts)]
pub struct MigrateIssuerConfig<'info> {
    /// CHECK: read/write raw account data so migration can handle the old
    /// smaller layout, which cannot be deserialized as the new IssuerConfig.
    #[account(
        mut,
        seeds = [IssuerConfig::SEED],
        bump,
        owner = crate::ID,
    )]
    pub issuer_config: UncheckedAccount<'info>,

    /// The current authority / issuer. For the legacy account this is the
    /// first Pubkey after the Anchor discriminator; for already-migrated
    /// accounts this is the `authority` field.
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:          Context<MigrateIssuerConfig>,
    issuer_node:  Pubkey,
    cluster_keys: Vec<Pubkey>,
    threshold:    u8,
) -> Result<()> {
    validate_cluster(&cluster_keys, threshold)?;

    let info = ctx.accounts.issuer_config.to_account_info();
    let old_len = info.data_len();

    require!(old_len >= 8 + 32, CertificateError::MalformedIssuerConfig);
    {
        let data = info.try_borrow_data()?;
        let legacy_authority = Pubkey::new_from_array(
            data[8..40]
                .try_into()
                .map_err(|_| error!(CertificateError::MalformedIssuerConfig))?,
        );
        require!(
            legacy_authority == ctx.accounts.authority.key(),
            CertificateError::NotIssuerAuthority,
        );
    }

    if old_len < IssuerConfig::SPACE {
        info.realloc(IssuerConfig::SPACE, false)?;
    }

    let mut data = info.try_borrow_mut_data()?;
    let mut cursor = std::io::Cursor::new(&mut data[8..]);
    let migrated = IssuerConfig {
        authority:    ctx.accounts.authority.key(),
        issuer_node,
        cluster_keys,
        threshold,
        bump:         ctx.bumps.issuer_config,
    };
    migrated
        .try_serialize(&mut cursor)
        .map_err(|_| error!(CertificateError::MalformedIssuerConfig))?;

    msg!(
        "issuer config migrated: old_len={} new_len={} threshold={}/{}",
        old_len,
        IssuerConfig::SPACE,
        migrated.threshold,
        migrated.cluster_keys.len(),
    );
    Ok(())
}

fn validate_cluster(cluster_keys: &[Pubkey], threshold: u8) -> Result<()> {
    require!(
        !cluster_keys.is_empty() && cluster_keys.len() <= IssuerConfig::MAX_CLUSTER_KEYS,
        CertificateError::InvalidClusterSize,
    );
    require!(cluster_keys.len() != 2, CertificateError::InvalidClusterSize);
    for i in 0..cluster_keys.len() {
        for j in (i + 1)..cluster_keys.len() { // audit: i is bounded by MAX_CLUSTER_KEYS (5), so i + 1 cannot overflow.
            require!(cluster_keys[i] != cluster_keys[j], CertificateError::DuplicateClusterKey);
        }
    }
    let n = cluster_keys.len() as u8;
    require!(threshold >= 1 && threshold <= n, CertificateError::InvalidThreshold);
    if n >= 3 {
        require!(
            threshold as usize >= (cluster_keys.len() / 2 + 1),
            CertificateError::InvalidThreshold,
        );
    }
    Ok(())
}
