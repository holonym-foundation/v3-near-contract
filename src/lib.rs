use std::str::FromStr;

// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, Vector, LookupSet};
use near_sdk::env::{log_str, block_timestamp, attached_deposit, keccak256};
use near_sdk::{near_bindgen, AccountId, require};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Verifier, VerifyingKey, Signature};

/// Byte representation of an element in the finite field of the 254-bit BN254 prime
pub type FrBytes = [u8; 32];
pub type CircuitId = [u8; 32];

#[derive(BorshDeserialize, BorshSerialize)]
pub struct SBT {
    expiry: u64,
    public_values: Vec<FrBytes>
}


// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Contract {
    pub sbt_owners: LookupMap<(AccountId, CircuitId), SBT>,
    pub used_nullifiers: LookupSet<FrBytes>,
    pub verifier_pubkey: [u8; PUBLIC_KEY_LENGTH]
}

// Define the default, which automatically initializes the contract
impl Default for Contract {
    fn default() -> Self {
        Self { 
            sbt_owners: LookupMap::new(b"sbt_owners".to_vec()), 
            used_nullifiers: LookupSet::new(b"used_nullifiers".to_vec()), 
            verifier_pubkey: [0; PUBLIC_KEY_LENGTH] 
        }
    }
}

// Implement the contract structure
#[near_bindgen]
impl Contract {
    // Public method - accepts a greeting, such as "howdy", and records it
    pub fn set_sbt(
        &mut self,
        circuit_id: CircuitId,
        // proof_ipfs_cid: String,
        sbt_owner: String,
        expiry: u64,
        custom_fee: u128,
        nullifier: FrBytes,
        public_values: Vec<FrBytes>,
        signature: Vec<u8>
    ) {
        // Require the payment
        require!(attached_deposit() == custom_fee, "Attached deposit must be equal to fee");
        
        // Require the signature
        let msg = (&[&circuit_id, sbt_owner.as_bytes(), &expiry.to_be_bytes(), &custom_fee.to_be_bytes(), &nullifier, &public_values.concat()].concat());
        let sig = Signature::from_bytes(
            &signature.try_into().expect("Invalid length for signature")
        );
        let pubkey = VerifyingKey::from_bytes(&self.verifier_pubkey).expect("Invalid public key");
        require!(pubkey.verify(&msg, &sig).is_ok(), "The Verifier did not sign the provided arguments in the provided order");

        // Require the nullifier uniqueness, unless it is 0 (a nullifier of 0 should only be signed when this type of proof does not involve a nullifier)
        if nullifier != [0; 32] {
            require!(!self.used_nullifiers.contains(&nullifier), "This has already been proven");
            self.used_nullifiers.insert(&nullifier);
        }

        // Store the SBT
        self.sbt_owners.insert(&
            (
                AccountId::from_str(&sbt_owner).expect("Invalid account ID"), 
                circuit_id
            ), 
            &SBT { expiry, public_values });

        // log_str(&format!("Log: {circuit_id}"));
    }


    // IMPORTANT: make sure you check the public values such as actionId from this. Someone can forge a proof if you don't check the public values
    /// e.g., by using a different issuer or actionId
    pub fn get_sbt(&self, owner: AccountId, circuit_id: CircuitId) -> SBT {
        let sbt = self.sbt_owners.get(&(owner, circuit_id)).expect("SBT does not exist");
        require!(sbt.expiry >= block_timestamp(), "SBT is expired");
        sbt
    }
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_default_greeting() {
        let contract = Contract::default();
        // this test did not call set_greeting so should return the default "Hello" greeting
        assert_eq!(
            contract.get_greeting(),
            "Hello".to_string()
        );
    }

    #[test]
    fn set_then_get_greeting() {
        let mut contract = Contract::default();
        contract.set_greeting("howdy".to_string());
        assert_eq!(
            contract.get_greeting(),
            "howdy".to_string()
        );
    }
}
