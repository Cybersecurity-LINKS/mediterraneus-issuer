use std::vec;
use deadpool_postgres::Client;
use identity_iota::core::Timestamp;
use tokio_pg_mapper::FromTokioPostgresRow;

use crate::{db::models::Identity, errors::my_errors::MyError};

use super::models::{VerifiableCredential, ChallengeRequest};

pub async fn get_identity_did(client: &Client) -> Result<Identity, MyError> {
    let stmt = include_str!("./sql/get_identity_did.sql");
    let stmt = stmt.replace("$table_fields", &Identity::sql_table_fields());
    let stmt = client.prepare(&stmt).await.unwrap();

    let results = match client
        .query_one(&stmt, &[])
        .await {
            Ok(row ) => Identity::from_row_ref(&row).unwrap(),
            Err(db_error) => {
                log::info!("Issuer identity not present in DB: {:?}", db_error);
                Identity{did: "".to_string(), privkey: vec![0]}
            }
        };
    Ok(results)
}

pub async fn insert_identity_issuer(client: &Client, identity_info: Identity) -> Result<Identity, MyError> {
    let _stmt = include_str!("./sql/insert_identity_issuer.sql");
    let _stmt = _stmt.replace("$table_fields", &Identity::sql_table_fields());
    let stmt = client.prepare(&_stmt).await.unwrap();

    client
            .query(
                &stmt,
                &[
                    &identity_info.did,
                    &identity_info.privkey,
                ],
            )
            .await?
            .iter()
            .map(|row| Identity::from_row_ref(row).unwrap())
            .collect::<Vec<Identity>>()
            .pop()
            .ok_or(MyError::NotFound) // more applicable for SELECTs
}

pub async fn insert_vc(client: &Client) -> Result<VerifiableCredential, MyError>{
    let _stmt = include_str!("./sql/insert_vc.sql");
    // let _stmt = _stmt.replace("$table_fields", &HolderRequest::sql_table_fields());
    let stmt = client.prepare(&_stmt).await.unwrap();

    let row = client
            .query(
                &stmt,
                &[],
            )
            .await?;



    let vc_result = VerifiableCredential::from_row_ref(row.first().unwrap()).unwrap();

    Ok(vc_result)
}

pub async fn check_vc_is_present(client: &Client, vc_id: i32) -> Result<(), MyError> {
    let _stmt = include_str!("./sql/check_vc_is_present.sql");
    // let _stmt = _stmt.replace("$table_fields", &HolderRequest::sql_table_fields());
    let stmt = client.prepare(&_stmt).await.unwrap();

    let row = client
            .query(
                &stmt,
                &[&vc_id],
            )
            .await?;

    if row.is_empty() {
        Err(MyError::NotFound)
    } else {
        Ok(())
    }
}

pub async fn get_challenge_req(client: &Client, did: String) ->  Result<ChallengeRequest, MyError> {
    let _stmt = include_str!("./sql/get_challenge_request.sql");
    let _stmt = _stmt.replace("$table_fields", &ChallengeRequest::sql_table_fields());
    let stmt = client.prepare(&_stmt).await.unwrap();

    let challenge_req = match client.query_one(
        &stmt, 
        &[
            &did
        ],
    ).await {
        Ok(challenge_req_row) => ChallengeRequest::from_row_ref(&challenge_req_row).unwrap(),
        Err(db_error) => {
            log::info!("Issuer identity not present in DB: {:?}", db_error);
            // ChallengeRequest {did: "".to_string(), challenge: "".to_string(), expiration: "".to_string()}
            return Err(MyError::NotFound)
        },
    };
        
    Ok(challenge_req)
}

pub async fn update_challenge_req(client: &Client, did: String, challenge: String, expiration: Timestamp) -> Result<ChallengeRequest, MyError> {
    let _stmt = include_str!("./sql/update_challenge_request.sql");
    let _stmt = _stmt.replace("$table_fields", &ChallengeRequest::sql_table_fields());
    let stmt = client.prepare(&_stmt).await.unwrap();

    let challenge_req = match client.query_one(
        &stmt, 
        &[
            &did,
            &challenge,
            &expiration.to_rfc3339()
        ],
    ).await {
        Ok(challenge_req_row) => ChallengeRequest::from_row_ref(&challenge_req_row).unwrap(),
        Err(db_error) => {
            log::info!("Issuer identity not present in DB: {:?}", db_error);
            // ChallengeRequest {did: "".to_string(), challenge: "".to_string(), expiration: "".to_string()}
            return Err(MyError::NotFound)
        },
    };
        
    Ok(challenge_req)
}


pub async fn insert_challenge_req(client: &Client, did: String, challenge: String, expiration: Timestamp) -> Result<ChallengeRequest, MyError> {
    let _stmt = include_str!("./sql/insert_challenge_request.sql");
    let _stmt = _stmt.replace("$table_fields", &ChallengeRequest::sql_table_fields());
    let stmt = client.prepare(&_stmt).await.unwrap();

    let challenge_req = match client.query_one(
        &stmt, 
        &[
            &did,
            &challenge,
            &expiration.to_rfc3339()
        ],
    ).await {
        Ok(challenge_req_row) => ChallengeRequest::from_row_ref(&challenge_req_row).unwrap(),
        Err(db_error) => {
            log::info!("Issuer identity not present in DB: {:?}", db_error);
            // ChallengeRequest {did: "".to_string(), challenge: "".to_string(), expiration: "".to_string()}
            return Err(MyError::NotFound)
        },
    };
        
    Ok(challenge_req)
}