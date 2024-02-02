use std::str::FromStr;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::env::{block_timestamp, attached_deposit};
use near_sdk::{near_bindgen, AccountId, require};
use serde::Serialize;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, Verifier, VerifyingKey, Signature};

/// Byte representation of an element in the finite field of the 254-bit BN254 prime
pub type FrBytes = [u8; 32];
pub type CircuitId = [u8; 32];

#[derive(Serialize, PartialEq, Debug, BorshDeserialize, BorshSerialize)]
pub struct SBT {
    expiry: u64,
    public_values: Vec<FrBytes>
}


// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Contract {
    /// The SBTs are stored in a map with their owner and circuit ID as the key
    pub sbt_owners: LookupMap<(AccountId, CircuitId), SBT>,
    /// In situations where the AccountId or CircuitId are not known, a used nullifier can be looked up to find the account and circuit ID it was used with
    pub nullifiers_lookup: LookupMap<FrBytes, (AccountId, CircuitId)>,
    /// This set keeps track of which nullifiers have been used so they cannot be used again
    pub used_nullifiers: LookupSet<FrBytes>,
    /// The public key of the semi-trusted entity who can verify the proofs off-chain to save gas for expensive ZKP verification
    pub verifier_pubkey: [u8; PUBLIC_KEY_LENGTH]
}

// Define the default, which automatically initializes the contract
impl Default for Contract {
    fn default() -> Self {
        Self { 
            sbt_owners: LookupMap::new(b"sbt_owners".to_vec()), 
            used_nullifiers: LookupSet::new(b"used_nullifiers".to_vec()), 
            nullifiers_lookup: LookupMap::new(b"nullifiers_lookup".to_vec()),
            verifier_pubkey: hex::decode("8abb54a589fd33af1e42617939bcf58f30674c20d9e1a8342e6abe078280a70c").expect("Invalid hex for pubkey").try_into().expect("Invalid length for pubkey") // Testing value: ec1169505a31c34288953b77e707ff1c5390d1f9b63150a17afb7fb44531b11c. Production value: 8abb54a589fd33af1e42617939bcf58f30674c20d9e1a8342e6abe078280a70c
        }
    }
}

// Implement the contract structure
#[near_bindgen]
impl Contract {
    /// `circuit_id` is the ID of the circuit and also the SBT
    /// `proof_ipfs_cid` is a currently unused parameter set to the empty string. It can be used to check the proof oneself instead of trusting the verifier.
    /// `sbt_owner` is the address the verifier specifies to recieve the SBT. 
    /// `expiry` is an expiration date the verifier can set.
    /// `custom_fee` is a fee the verifier can set that the user must pay to submit the transaction.
    /// `nullifier` is an optional field (set to 0 if unused) which prevents the same ID from being used for >1 proof. Again this is given by the verifier but can be checked if the Verifier posts the proof to IPFS
    /// `public_values` are the proofs' public inputs and outputs. They are stored with the SBT. Again, these can be checked if the proof is put in IPFS
    /// To migrate SBT owners from the previous contract, the initially centralized trusted verifier can simply add them one-by-one
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
        let msg = &[&circuit_id, sbt_owner.as_bytes(), &expiry.to_be_bytes(), &custom_fee.to_be_bytes(), &nullifier, &public_values.concat()].concat();


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
        let account_id = AccountId::from_str(&sbt_owner).expect("Invalid account ID");
        self.sbt_owners.insert(&
            (account_id.clone(), circuit_id), 
            &SBT { expiry, public_values }
        );
        self.nullifiers_lookup.insert(&
            nullifier,
            &(account_id, circuit_id)
        );
    }

    fn _get_sbt(&self, owner: AccountId, circuit_id: CircuitId) -> SBT{
        let sbt = self.sbt_owners.get(&(owner, circuit_id)).expect("SBT does not exist");
        require!(sbt.expiry >= block_timestamp() / 1_000_000_000, "SBT is expired");
        sbt
    }

    // IMPORTANT: make sure you check the public values such as actionId from this. Someone can forge a proof if you don't check the public values
    /// e.g., by using a different issuer or actionId
    pub fn get_sbt(&self, owner: String, circuit_id: CircuitId) -> SBT {
        let owner = AccountId::from_str(&owner).expect("Invalid account ID");
        self._get_sbt(owner, circuit_id)
    }

     // IMPORTANT: make sure you check the public values such as actionId from this. Someone can forge a proof if you don't check the public values
    /// e.g., by using a different issuer or actionId
    pub fn get_sbt_by_nullifier(&self, nullifier: FrBytes) -> SBT {
        let (account_id, circuit_id) = self.nullifiers_lookup.get(&nullifier).expect("Nullifier could not be found");
        self._get_sbt(account_id, circuit_id)
    }
}


#[cfg(test)]
mod tests {
    use ethers_core::types::U256;
    use serde_json::Value;
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, VMContext};

    fn get_context(timestamp: u64) -> VMContext {
        VMContextBuilder::new()
            .signer_account_id("bob_near".parse().unwrap())
            .block_timestamp(timestamp)
            .is_view(false)
            .build()
    }

    #[test]
    fn get_set_sbt() {
        let context = get_context(1706572582000000000);
        testing_env!(context);

        let mut contract = Contract::default();
        // Assert getting a non-existent SBT causes panic
        assert!(
            std::panic::catch_unwind(||
                contract.get_sbt(
                    "testaccount.testnet".to_string(),
                    hex::decode("bce052cf723dca06a21bd3cf838bc518931730fb3db7859fc9cc86f0d5483495").unwrap().try_into().unwrap()
                )
            ).is_err()
        );

        let server_response = serde_json::from_str::<Value>(
            "{\"values\":{\"circuit_id\":\"0xbce052cf723dca06a21bd3cf838bc518931730fb3db7859fc9cc86f0d5483495\",\"sbt_reciever\":\"testaccount.testnet\",\"expiration\":\"0x6773e0bb\",\"custom_fee\":\"0x00\",\"nullifier\":\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"public_values\":[\"0x6773e0bb\",\"0x746573746163636f756e742e746573746e6574\",\"0x25f7bd02f163928099df325ec1cb1\",\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"0x2cf7ee166e16db45608361744b945755faafc389d377594c50232105b5b2f29f\"],\"chain_id\":\"NEAR\"},\"sig\":\"0x9d2554a7337e3c1b5a41c2fa13db6799bb8d01187d44249a6099d61a9d759a63cc529791a7a41b99b95ac717cd7e73667a52e66177b5c82a1f168764ea4b650e\"}"
        ).expect("Invalid JSON");
        assert_eq!(
            contract.set_sbt(
                hex::decode(server_response["values"]["circuit_id"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap(),
                // server_response["values"]["proof_ipfs_cid"].as_str().expect("Invalid proof_ipfs_cid").to_string(),
                server_response["values"]["sbt_reciever"].as_str().unwrap().to_string(),
                u64::from_str_radix(&server_response["values"]["expiration"].as_str().unwrap().replace("0x", ""), 16).unwrap(),
                u128::from_str_radix(&server_response["values"]["custom_fee"].as_str().unwrap().replace("0x", ""), 16).unwrap(),
                hex::decode(server_response["values"]["nullifier"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap(),
                server_response["values"]["public_values"].as_array().expect("Invalid public_values").iter().map(|x| {
                    let mut bytes = [0u8; 32];
                    x.as_str().unwrap().parse::<U256>().unwrap().to_big_endian(&mut bytes);
                    bytes
                }).collect(),
                hex::decode(server_response["sig"].as_str().unwrap().replace("0x", "")).expect("Invalid hex for signature")
            ),
            ()
        );

        assert_ne!(contract.get_sbt(
                "testaccount.testnet".to_string(),
                hex::decode("bce052cf723dca06a21bd3cf838bc518931730fb3db7859fc9cc86f0d5483495").unwrap().try_into().unwrap()
            ).expiry, 
            0
        );
    }

    // This could have more comprehensive coverage of edge cases :)
    #[test]
    fn everything_covered_by_sig() {
        todo!("Find an elegant way to iterate over input arguments and modify them without hundreds of lines of code");
        // let server_response = serde_json::from_str::<Value>(
        //     "{\"values\":{\"circuit_id\":\"0x729d660e1c02e4e419745e617d643f897a538673ccf1051e093bbfa58b0a120b\",\"sbt_reciever\":\"testaccount.near\",\"expiration\":\"0xeb22926a\",\"custom_fee\":\"0x00\",\"nullifier\":\"0x10618764ddaf4a294979b4987e1236eeb5b279a798810ce53b4acedb1e1c0d79\",\"public_values\":[\"0xeb22926a\",\"0x746573746163636f756e742e6e656172\",\"0x25f7bd02f163928099df325ec1cb1\",\"0x10618764ddaf4a294979b4987e1236eeb5b279a798810ce53b4acedb1e1c0d79\",\"0x2a0ec27e1e1ba005e10ae32cba78d8e922460f26dc28350056a6a71ed108fab7\"],\"chain_id\":\"NEAR\"},\"sig\":\"0x415302ac36922c692d7f80e2c7a9d812b5fc55a4050a433e8c1ee6510457c46c7c3b47352834bef57ae3f325088be3f31cf5a861150660ccf7f1b4a1827f8e00\"}"
        // ).expect("Invalid JSON");
        // let circuit_id = hex::decode(server_response["values"]["circuit_id"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        // let sbt_reciever = server_response["values"]["sbt_reciever"].as_str().unwrap().to_string();
        // let expiry = u64::from_str_radix(&server_response["values"]["expiration"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        // let fee = u128::from_str_radix(&server_response["values"]["custom_fee"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        // let nullifier = hex::decode(server_response["values"]["nullifier"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        // let pub_vals = server_response["values"]["public_values"].as_array().expect("Invalid public_values").iter().map(|x| {
        //     let mut bytes = [0u8; 32];
        //     x.as_str().unwrap().parse::<U256>().unwrap().to_big_endian(&mut bytes);
        //     bytes
        // }).collect();
        // let sig = hex::decode(server_response["sig"].as_str().unwrap().replace("0x", "")).expect("Invalid hex for signature");

        // let mut contract = Contract::default();
        // I really don't think there's a way to do this in rust without hundreds of lines of code
        // for item in [circuit_id,
        //     sbt_reciever,
        //     expiry,
        //     fee,
        //     nullifier,
        //     pub_vals,
        //     sig] 
        //     {
        //         ... modify one value
        //         assert_panic!(
        //             contract.set_sbt(
        //                 circuit_id,
        //                 sbt_reciever,
        //                 expiry,
        //                 fee,
        //                 nullifier,
        //                 pub_vals,
        //                 sig
        //             ),
        //             ()
        //         );
        //     }
        
    }

    #[test]
    #[should_panic(expected = "This has already been proven")]
    fn nullifier_reuse() {
        let context = get_context(1706572582000000000);
        testing_env!(context);

        let server_response = serde_json::from_str::<Value>(
            "{\"values\":{\"circuit_id\":\"0xbce052cf723dca06a21bd3cf838bc518931730fb3db7859fc9cc86f0d5483495\",\"sbt_reciever\":\"testaccount.testnet\",\"expiration\":\"0x6773e0bb\",\"custom_fee\":\"0x00\",\"nullifier\":\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"public_values\":[\"0x6773e0bb\",\"0x746573746163636f756e742e746573746e6574\",\"0x25f7bd02f163928099df325ec1cb1\",\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"0x2cf7ee166e16db45608361744b945755faafc389d377594c50232105b5b2f29f\"],\"chain_id\":\"NEAR\"},\"sig\":\"0x9d2554a7337e3c1b5a41c2fa13db6799bb8d01187d44249a6099d61a9d759a63cc529791a7a41b99b95ac717cd7e73667a52e66177b5c82a1f168764ea4b650e\"}"
        ).expect("Invalid JSON");
        let circuit_id = hex::decode(server_response["values"]["circuit_id"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        let sbt_reciever = server_response["values"]["sbt_reciever"].as_str().unwrap().to_string();
        let expiry = u64::from_str_radix(&server_response["values"]["expiration"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        let fee = u128::from_str_radix(&server_response["values"]["custom_fee"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        let nullifier = hex::decode(server_response["values"]["nullifier"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        let pub_vals = server_response["values"]["public_values"].as_array().expect("Invalid public_values").iter().map(|x| {
            let mut bytes = [0u8; 32];
            x.as_str().unwrap().parse::<U256>().unwrap().to_big_endian(&mut bytes);
            bytes
        }).collect::<Vec<FrBytes>>();
        let sig = hex::decode(server_response["sig"].as_str().unwrap().replace("0x", "")).expect("Invalid hex for signature");

        let mut contract = Contract::default();

        assert_eq!(
            contract.set_sbt(
                circuit_id,
                sbt_reciever.clone(),
                expiry,
                fee,
                nullifier,
                pub_vals.clone(),
                sig.clone()
            ),
            ()
        );

        // This should panic and be caught by #[should_panic(expected = "This has already been proven")]
        contract.set_sbt(
            circuit_id,
            sbt_reciever,
            expiry,
            fee,
            nullifier,
            pub_vals,
            sig
        );

    }

    #[test]
    #[should_panic(expected = "SBT is expired")]
    fn expiration() {
        let context = get_context(1706572582000000000 + 365*24*60*60*1_000_000_000);
        testing_env!(context);
        let server_response = serde_json::from_str::<Value>(
            "{\"values\":{\"circuit_id\":\"0xbce052cf723dca06a21bd3cf838bc518931730fb3db7859fc9cc86f0d5483495\",\"sbt_reciever\":\"testaccount.testnet\",\"expiration\":\"0x6773e0bb\",\"custom_fee\":\"0x00\",\"nullifier\":\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"public_values\":[\"0x6773e0bb\",\"0x746573746163636f756e742e746573746e6574\",\"0x25f7bd02f163928099df325ec1cb1\",\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"0x2cf7ee166e16db45608361744b945755faafc389d377594c50232105b5b2f29f\"],\"chain_id\":\"NEAR\"},\"sig\":\"0x9d2554a7337e3c1b5a41c2fa13db6799bb8d01187d44249a6099d61a9d759a63cc529791a7a41b99b95ac717cd7e73667a52e66177b5c82a1f168764ea4b650e\"}"
        ).expect("Invalid JSON");
        let circuit_id = hex::decode(server_response["values"]["circuit_id"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        let sbt_reciever = server_response["values"]["sbt_reciever"].as_str().unwrap().to_string();
        let expiry = u64::from_str_radix(&server_response["values"]["expiration"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        let fee = u128::from_str_radix(&server_response["values"]["custom_fee"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        let nullifier = hex::decode(server_response["values"]["nullifier"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        let pub_vals = server_response["values"]["public_values"].as_array().expect("Invalid public_values").iter().map(|x| {
            let mut bytes = [0u8; 32];
            x.as_str().unwrap().parse::<U256>().unwrap().to_big_endian(&mut bytes);
            bytes
        }).collect::<Vec<FrBytes>>();
        let sig = hex::decode(server_response["sig"].as_str().unwrap().replace("0x", "")).expect("Invalid hex for signature");

        let mut contract = Contract::default();

        assert_eq!(
            contract.set_sbt(
                circuit_id,
                sbt_reciever.clone(),
                expiry,
                fee,
                nullifier,
                pub_vals.clone(),
                sig.clone()
            ),
            ()
        );

        // This should panic and be caught by should_panic macro:
        contract.get_sbt(
            "testaccount.testnet".to_string(),
            hex::decode("bce052cf723dca06a21bd3cf838bc518931730fb3db7859fc9cc86f0d5483495").unwrap().try_into().unwrap()
        );

        // // This should panic and be caught by should_panic macro:
        // contract.set_sbt(
        //     circuit_id,
        //     sbt_reciever,
        //     expiry,
        //     fee,
        //     nullifier,
        //     pub_vals,
        //     sig
        // );
    }

    #[test]
    #[should_panic(expected = "Nullifier could not be found")]
    fn nullifier_mapping() {
        let server_response = serde_json::from_str::<Value>(
            "{\"values\":{\"circuit_id\":\"0xbce052cf723dca06a21bd3cf838bc518931730fb3db7859fc9cc86f0d5483495\",\"sbt_reciever\":\"testaccount.testnet\",\"expiration\":\"0x6773e0bb\",\"custom_fee\":\"0x00\",\"nullifier\":\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"public_values\":[\"0x6773e0bb\",\"0x746573746163636f756e742e746573746e6574\",\"0x25f7bd02f163928099df325ec1cb1\",\"0x26eda727613ae02a38128bd4e0917fb8a567caf041057408942a101da493ebfb\",\"0x2cf7ee166e16db45608361744b945755faafc389d377594c50232105b5b2f29f\"],\"chain_id\":\"NEAR\"},\"sig\":\"0x9d2554a7337e3c1b5a41c2fa13db6799bb8d01187d44249a6099d61a9d759a63cc529791a7a41b99b95ac717cd7e73667a52e66177b5c82a1f168764ea4b650e\"}"
        ).expect("Invalid JSON");
        let circuit_id = hex::decode(server_response["values"]["circuit_id"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        let sbt_reciever = server_response["values"]["sbt_reciever"].as_str().unwrap().to_string();
        let expiry = u64::from_str_radix(&server_response["values"]["expiration"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        let fee = u128::from_str_radix(&server_response["values"]["custom_fee"].as_str().unwrap().replace("0x", ""), 16).unwrap();
        let nullifier = hex::decode(server_response["values"]["nullifier"].as_str().unwrap().replace("0x", "")).unwrap().try_into().unwrap();
        let pub_vals = server_response["values"]["public_values"].as_array().expect("Invalid public_values").iter().map(|x| {
            let mut bytes = [0u8; 32];
            x.as_str().unwrap().parse::<U256>().unwrap().to_big_endian(&mut bytes);
            bytes
        }).collect::<Vec<FrBytes>>();
        let sig = hex::decode(server_response["sig"].as_str().unwrap().replace("0x", "")).expect("Invalid hex for signature");
        
        let mut contract = Contract::default();
        
        assert_eq!(
            contract.set_sbt(
                circuit_id,
                sbt_reciever.clone(),
                expiry,
                fee,
                nullifier,
                pub_vals.clone(),
                sig.clone()
            ),
            ()
        );

        // get_sbt_by_nullifier should have the same result as get_sbt
        assert_eq!(
            contract.get_sbt_by_nullifier(nullifier),
            contract.get_sbt(sbt_reciever, circuit_id)
        );

        // Should fail for an unused nullifier
        contract.get_sbt_by_nullifier([42; 32]);
    }
}
