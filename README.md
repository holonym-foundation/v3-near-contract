# Holonym V3 Hub
This contains a smart contract where all signed proofs can be posted. It exposes one method, `set_sbt` where you can set the SBT with the verifier's sigature that the proof is valid. At the time of writing this, the verifier automatically relays proofs that involve credentials signed by trusted issuers.

# Convenience methods
To see whether an address has a government ID or phone SBT you can use the `has_gov_id_sbt` or `has_phone_sbt` methods.

```bash
NEAR_ENV=mainnet near view verifier.holonym_id.near has_gov_id_sbt --args '{"owner": "<YOUR ACCOUNT>.near" }'
```
```bash
NEAR_ENV=mainnet near view verifier.holonym_id.near has_phone_sbt --args '{"owner": "<YOUR ACCOUNT>.near" }'
```

