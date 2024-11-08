// SPDX-FileCopyrightText: 2024 Fondazione LINKS
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::time::Duration;

use anyhow::Result;

use deadpool_postgres::{ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

use crate::utils::configs::DatabaseConfig;

use super::operations::HoldersChallengesExt;

/// Clean challenges from the database every hour
async fn cleanup_loop(pool: Pool)
{   
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    if let Ok(client) = pool.get().await {
        loop
        {
            // cleanup loop
            interval.tick().await;
            let result = client.cleanup_challenges().await;
            match result {
                Ok(_) => log::info!("SQL cleanup completed"),
                Err(err) => log::error!("SQL cleanup error: {}", err.to_string())
            }
        }       
    }
    else {
        log::error!("Cannot access DB pool. Cleanup disabled");
    }

}

pub async fn init(configuration: DatabaseConfig) -> Result<Pool> {
    log::info!("init database");

    let mut config = deadpool_postgres::Config::new();
    config.user = Some(configuration.db_user);
    config.password = Some(configuration.db_password.value());
    config.dbname = Some(configuration.db_name);
    config.host = Some(configuration.db_host);
    config.port = Some(configuration.db_port);

    config.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    let pool = config.create_pool(None, NoTls)?;
    log::info!("pool database");

    tokio::spawn(cleanup_loop(pool.clone()));
    Ok(pool)
}
