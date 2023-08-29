# mediterraneus-issuer-rs

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Iota](https://img.shields.io/badge/iota-29334C?style=for-the-badge&logo=iota&logoColor=white)

Issuer of verifiable credentials using the **IOTA Identity** framework. Sample implementation for the Mediterraneus Protocol.

## Issuer initialization
The issuer must posses an SSI comprising of at least a DID. At application start up the issuer creates a new identity or retrieves it from the local database. 
This is an insecure implementation due to the clear-text storage of the sensitive information of its identity. This must be solved with the usage of secure storage solutions like Stronghold.

## Verifiable Credential Issuance
Before issuing a VC the Issuer must perform the following operations:

1. Resolve the requester's DID and retrieve the verification method public key.

## Running the Application
```sh
cd mediterraneus-issuer-rs/src

cargo run main
```

## Recommendation

When utilizing the Rust GNU toolchain, ensure that the 'rocksdb' feature in iota-wallet is disabled. This can be accomplished by correctly including this dependency in the following manner:

```
iota-wallet = {version = "1.0.0-rc.6", default-features = false, features = [ "storage", "stronghold" ] }
```

## Useful links
https://github.com/actix/examples/blob/master/databases/postgres/src/main.rs

https://docs.rs/ethers/latest/ethers/contract/struct.ContractInstance.html