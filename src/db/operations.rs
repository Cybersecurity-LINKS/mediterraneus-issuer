use std::vec;
use deadpool_postgres::Client;
use tokio_pg_mapper::FromTokioPostgresRow;

use crate::{db::models::Identity, errors::my_errors::MyError};

use super::models::VerifiableCredential;

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