// Synthetic vulnerable Solana program for testing.
// Triggers security scanner patterns (SOL-001..010, AST-001..003).

use anchor_lang::prelude::*;

// SOL-001: Missing Signer Constraint + AST-001: Unchecked AccountInfo
#[derive(Accounts)]
pub struct VulnerableAccounts<'info> {
    pub authority: AccountInfo<'info>,
    #[account()]
    pub vault: Account<'info, Vault>,
}

// AST-001: Unchecked AccountInfo (second instance)
#[derive(Accounts)]
pub struct MoreVulnerable<'info> {
    pub unchecked: AccountInfo<'info>,
}

pub struct Vault {
    pub balance: u64,
}

// SOL-003: Unchecked arithmetic
pub fn bad_math(amount: u64, balance: u64) -> u64 {
    amount + balance
}

// SOL-004: Unvalidated remaining_accounts
pub fn use_remaining(ctx: Context<VulnerableAccounts>) {
    let _account = ctx.remaining_accounts[0].clone();
}

// SOL-005: PDA bump not stored
pub fn create_pda(program_id: &Pubkey) {
    let (_pda, _bump) = Pubkey::find_program_address(&[b"seed"], program_id);
}

// SOL-006: Account closed without zeroing
pub fn close_account(account: &AccountInfo) {
    **account.lamports.borrow_mut() = 0;
}

// SOL-007: Arbitrary CPI target
pub fn arbitrary_cpi(target_program: &AccountInfo) {
    invoke(&target_program, &[]);
}

// SOL-008: Type cosplay (missing discriminator)
pub fn deserialize_unsafe(data: &[u8]) -> Vault {
    Vault::try_from_slice(data).unwrap()
}

// SOL-009: Division before multiplication
pub fn bad_precision(amount: u64, rate: u64, factor: u64) -> u64 {
    (amount / rate) * factor
}

// SOL-010: Missing Token-2022 handling
pub fn old_transfer() {
    spl_token::instruction::transfer(program_id, src, dst, auth, &[], amount);
}

// AST-002: Verbose key logging
fn log_keys(account: &AccountInfo) {
    msg!("{}", account.key());
}

// AST-003: Unsafe block
fn dangerous_op(ptr: *mut u8, value: u8) {
    unsafe {
        std::ptr::write(ptr, value);
    }
}
