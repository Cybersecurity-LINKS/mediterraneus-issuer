use std::vec;
use deadpool_postgres::Client;
use tokio_pg_mapper::FromTokioPostgresRow;

use crate::{models::models::Identity, errors::my_errors::MyError};

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