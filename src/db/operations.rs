use std::vec;
use deadpool_postgres::Client;
use identity_iota::core::Timestamp;
use tokio_pg_mapper::FromTokioPostgresRow;

use crate::{db::models::Identity, errors::my_errors::MyError};

use super::models::VerifiableCredential;

// use super::models::HolderRequest;

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

// pub async fn get_holder_request_by_did(client: &Client, did: String) -> Result<HolderRequest, MyError> {
//     let _stmt = include_str!("./sql/get_request_by_did.sql");
//     let _stmt = _stmt.replace("$table_fields", &HolderRequest::sql_table_fields());
//     let stmt = client.prepare(&_stmt).await.unwrap();

//     let holder_request_row = match client.query_one(
//         &stmt, 
//         &[
//             &did
//         ],
//     ).await {
//         Ok(holder_request) => HolderRequest::from_row_ref(&holder_request).unwrap(),
//         Err(db_error) => {
//             log::info!("Issuer identity not present in DB: {:?}", db_error);
//             HolderRequest {did: "".to_string(), vchash: "".to_string(), request_expiration: "".to_string(), vc: "".to_string() }
//         },
//     };
        
//     Ok(holder_request_row)
// }

// pub async fn get_holder_request_by_vc_hash(client: &Client, vchash: String) -> Result<HolderRequest, MyError> {
//     let _stmt = include_str!("./sql/get_request_by_vc_hash.sql");
//     let _stmt = _stmt.replace("$table_fields", &HolderRequest::sql_table_fields());
//     let stmt = client.prepare(&_stmt).await.unwrap();

//     let holder_request_row = match client.query_one(
//         &stmt, 
//         &[
//             &vchash
//         ],
//     ).await {
//         Ok(holder_request) => HolderRequest::from_row_ref(&holder_request).unwrap(),
//         Err(db_error) => {
//             log::info!("Issuer identity not present in DB: {:?}", db_error);
//             HolderRequest {did: "".to_string(), vchash: "".to_string(), request_expiration: "".to_string(), vc: "".to_string() }
//         },
//     };
        
//     Ok(holder_request_row)
// }

// pub async fn insert_holder_request(client: &Client, vc: String, vc_hash: String, did: String, expiration: Timestamp) -> Result<HolderRequest, MyError>{
//     let _stmt = include_str!("./sql/insert_holder_request.sql");
//     let _stmt = _stmt.replace("$table_fields", &HolderRequest::sql_table_fields());
//     let stmt = client.prepare(&_stmt).await.unwrap();

//     client
//             .query(
//                 &stmt,
//                 &[
//                     &vc_hash,
//                     &did,
//                     &expiration.to_rfc3339(),
//                     &vc
//                 ],
//             )
//             .await?
//             .iter()
//             .map(|row| HolderRequest::from_row_ref(row).unwrap())
//             .collect::<Vec<HolderRequest>>()
//             .pop()
//             .ok_or(MyError::NotFound) // more applicable for SELECTs
// }

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

// pub async fn remove_holder_request_by_did(client: &Client, did: String) {
//     let _stmt = include_str!("./sql/remove_holder_request_by_did.sql");
//     let stmt = client.prepare(&_stmt).await.unwrap();

//     client.query(&stmt, &[
//         &did
//     ]).await.unwrap();
// }

// pub async fn remove_holder_request_by_vchash(client: &Client, vchash: String) {
//     let _stmt = include_str!("./sql/remove_holder_request_by_vchash.sql");
//     let stmt = client.prepare(&_stmt).await.unwrap();

//     client.query(&stmt, &[
//         &vchash
//     ]).await.unwrap();
// }