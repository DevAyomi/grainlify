#![no_std]
//! # Program Escrow Smart Contract (v2)
//!
//! Adds ProgramStatus::Draft and publish_program() to the lifecycle.
//!
//! Lifecycle:
//!   Draft --publish_program()--> Active --complete_program()--> Completed
//!   Draft or Active --cancel_program()--> Cancelled

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, Env, String, Symbol, Vec, token,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotInitialized     = 1,
    AlreadyInitialized = 2,
    Unauthorized       = 3,
    ProgramNotFound    = 4,
    InvalidStatus      = 5,
    AlreadyExists      = 6,
    InvalidAmount      = 7,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Lifecycle state of a program.
///
/// Storage discriminant (u32):
///   Draft     = 0  (NEW in v2)
///   Active    = 1
///   Completed = 2
///   Cancelled = 3
///
/// IMPORTANT: never reorder or remove variants after deployment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramStatus {
    /// Created but not yet published. No deposits accepted.
    Draft,
    /// Live — deposits open.
    Active,
    /// All payouts made; funds released.
    Completed,
    /// Cancelled; funds refunded.
    Cancelled,
}

/// Core program data stored on-chain.
///
/// v2 changes:
/// - `status` now starts as Draft (was Active)
/// - `published_at` is new; None while in Draft
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProgramData {
    pub program_id:   String,
    pub name:         String,
    pub organizer:    Address,
    pub status:       ProgramStatus,
    pub token:        Address,
    pub balance:      i128,
    pub created_at:   u64,
    /// Ledger timestamp when publish_program() was called. None in Draft.
    pub published_at: Option<u64>,
}

// Storage keys
#[contracttype]
pub enum DataKey {
    Admin,
    Program(String),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ProgramEscrowContract;

#[contractimpl]
impl ProgramEscrowContract {

    /// Initialise the contract with an admin address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Program management
    // -----------------------------------------------------------------------

    /// Create a new program in **Draft** status.
    ///
    /// # Errors
    /// - `AlreadyExists`  – program_id already taken.
    /// - `Unauthorized`   – caller is not the admin.
    pub fn create_program(
        env:        Env,
        program_id: String,
        name:       String,
        token:      Address,
    ) -> Result<(), Error> {
        let admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = DataKey::Program(program_id.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }

        let program = ProgramData {
            program_id:   program_id.clone(),
            name,
            organizer:    admin,
            status:       ProgramStatus::Draft,   // v2: starts as Draft
            token,
            balance:      0,
            created_at:   env.ledger().timestamp(),
            published_at: None,                   // v2: new field
        };

        env.storage().persistent().set(&key, &program);
        env.events().publish(
            (Symbol::new(&env, "program_created"), program_id),
            ProgramStatus::Draft,
        );
        Ok(())
    }

    /// Transition a program from **Draft** → **Active**.
    ///
    /// Once published a program cannot return to Draft.
    ///
    /// # Errors
    /// - `ProgramNotFound` – unknown program_id.
    /// - `InvalidStatus`   – program is not in Draft.
    /// - `Unauthorized`    – caller is not the admin.
    pub fn publish_program(
        env:        Env,
        program_id: String,
    ) -> Result<(), Error> {
        let admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = DataKey::Program(program_id.clone());
        let mut program: ProgramData = env.storage().persistent()
            .get(&key)
            .ok_or(Error::ProgramNotFound)?;

        if program.status != ProgramStatus::Draft {
            return Err(Error::InvalidStatus);
        }

        program.status       = ProgramStatus::Active;
        program.published_at = Some(env.ledger().timestamp());
        env.storage().persistent().set(&key, &program);

        env.events().publish(
            (Symbol::new(&env, "program_published"), program_id),
            ProgramStatus::Active,
        );
        Ok(())
    }

    /// Deposit tokens into an **Active** program.
    ///
    /// # Errors
    /// - `InvalidStatus`  – program is not Active.
    /// - `InvalidAmount`  – amount <= 0.
    pub fn deposit_funds(
        env:        Env,
        program_id: String,
        from:       Address,
        amount:     i128,
    ) -> Result<(), Error> {
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        from.require_auth();

        let key = DataKey::Program(program_id.clone());
        let mut program: ProgramData = env.storage().persistent()
            .get(&key)
            .ok_or(Error::ProgramNotFound)?;

        if program.status != ProgramStatus::Active {
            return Err(Error::InvalidStatus);
        }

        let token_client = token::Client::new(&env, &program.token);
        token_client.transfer(&from, &env.current_contract_address(), &amount);

        program.balance += amount;
        env.storage().persistent().set(&key, &program);
        Ok(())
    }

    /// Complete a program, releasing balance to the organizer.
    ///
    /// # Errors
    /// - `InvalidStatus` – program is not Active.
    /// - `Unauthorized`  – caller is not the admin.
    pub fn complete_program(
        env:        Env,
        program_id: String,
    ) -> Result<(), Error> {
        let admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = DataKey::Program(program_id.clone());
        let mut program: ProgramData = env.storage().persistent()
            .get(&key)
            .ok_or(Error::ProgramNotFound)?;

        if program.status != ProgramStatus::Active {
            return Err(Error::InvalidStatus);
        }

        if program.balance > 0 {
            let token_client = token::Client::new(&env, &program.token);
            token_client.transfer(
                &env.current_contract_address(),
                &program.organizer,
                &program.balance,
            );
        }

        program.status  = ProgramStatus::Completed;
        program.balance = 0;
        env.storage().persistent().set(&key, &program);

        env.events().publish(
            (Symbol::new(&env, "program_completed"), program_id),
            ProgramStatus::Completed,
        );
        Ok(())
    }

    /// Cancel a Draft or Active program, refunding balance.
    ///
    /// # Errors
    /// - `InvalidStatus` – program is Completed or already Cancelled.
    /// - `Unauthorized`  – caller is not the admin.
    pub fn cancel_program(
        env:            Env,
        program_id:     String,
        refund_address: Address,
    ) -> Result<(), Error> {
        let admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = DataKey::Program(program_id.clone());
        let mut program: ProgramData = env.storage().persistent()
            .get(&key)
            .ok_or(Error::ProgramNotFound)?;

        if matches!(program.status, ProgramStatus::Completed | ProgramStatus::Cancelled) {
            return Err(Error::InvalidStatus);
        }

        if program.balance > 0 {
            let token_client = token::Client::new(&env, &program.token);
            token_client.transfer(
                &env.current_contract_address(),
                &refund_address,
                &program.balance,
            );
        }

        program.status  = ProgramStatus::Cancelled;
        program.balance = 0;
        env.storage().persistent().set(&key, &program);

        env.events().publish(
            (Symbol::new(&env, "program_cancelled"), program_id),
            ProgramStatus::Cancelled,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // View methods
    // -----------------------------------------------------------------------

    /// Return the data for a program, or None if not found.
    pub fn get_program(env: Env, program_id: String) -> Option<ProgramData> {
        env.storage().persistent().get(&DataKey::Program(program_id))
    }

    /// Return the admin address.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }
}

#[cfg(test)]
mod test_lifecycle;
