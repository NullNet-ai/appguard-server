use std::sync::{Arc, Mutex};

use serial_test::serial;

use appguard_server::config::Config;
use appguard_server::constants::BLACKLIST_PATH;
use appguard_server::db::tables::DbTable;
use appguard_server::ip_info::ip_info_handler;
use appguard_server::proto::appguard::AppGuardIpInfo;
use appguard_server::proto::appguard::AppGuardTcpConnection;

use crate::config::write_config_to_file;
use crate::helpers::{
    client_setup, count_rows_in_table, db_setup, server_clean, server_setup, NUM_ITER,
};
use crate::ip_info::retrieve_stored_ipinfos;
use crate::tcp_connection::{
    retrieve_stored_tcp_connections, sample_tcp_connection, sample_tcp_connection_2,
};

mod config;
mod helpers;
mod ip_info;
mod tcp_connection;

// run tests with:
// cargo test
//
// run tests and get code coverage with:
// cargo coverage

#[tokio::test]
#[serial]
async fn test_grpc_server_durable_storage() {
    // start the server
    server_setup();

    // create a client
    let mut client = client_setup().await;

    // create a connection to the sqlite database
    let conn = db_setup();

    // verify tables are empty
    for table_name in DbTable::ALL.iter().map(|t| t.to_str()) {
        assert_eq!(count_rows_in_table(&conn, table_name), 0);
    }

    for _ in 1..=NUM_ITER {
        // handle_tcp_connection
        client
            .handle_tcp_connection(None, sample_tcp_connection("HTTP".to_string()))
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    // assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 1);
    for table in &[DbTable::TcpConnection] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored connections
    let stored_connections = retrieve_stored_tcp_connections(&conn);
    assert_eq!(stored_connections.len(), NUM_ITER as usize);
    for stored_connection in stored_connections.iter() {
        assert_eq!(
            stored_connection.appguard_tcp_connection,
            sample_tcp_connection("HTTP".to_string())
        );
    }

    // verify stored ipinfos
    let ip_info_handler = ip_info_handler();
    let blacklist_conn = Arc::new(Mutex::new(
        rusqlite::Connection::open(BLACKLIST_PATH).expect("Test"),
    ));
    let stored_ipinfos = retrieve_stored_ipinfos(&conn);
    // assert_eq!(stored_ipinfos.len(), 1);
    for stored_ipinfo in stored_ipinfos.iter() {
        assert_eq!(
            stored_ipinfo.ip_info,
            AppGuardIpInfo::lookup(&stored_ipinfo.ip_info.ip, &ip_info_handler, &blacklist_conn)
                .await
                .unwrap()
        );
    }

    // stop the server
    server_clean();
}

#[tokio::test]
#[serial]
async fn test_grpc_server_durable_storage_with_more_data_and_then_expire() {
    // start the server
    server_setup();

    // create a client
    let mut client = client_setup().await;

    // create a connection to the sqlite database
    let conn = db_setup();

    // verify tables are empty
    for table_name in DbTable::ALL.iter().map(|t| t.to_str()) {
        assert_eq!(count_rows_in_table(&conn, table_name), 0);
    }

    for i in 1..=NUM_ITER * 2 {
        // handle_tcp_connection
        let tcp_connection = if i % 2 == 0 {
            sample_tcp_connection("HTTP".to_string())
        } else {
            sample_tcp_connection_2("HTTP".to_string())
        };
        client
            .handle_tcp_connection(None, tcp_connection)
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // verify the number of rows in tables
    // assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 2);
    for table in &[DbTable::TcpConnection] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER * 2);
    }

    // verify stored connections
    let stored_connections = retrieve_stored_tcp_connections(&conn);
    assert_eq!(stored_connections.len(), 2 * NUM_ITER as usize);
    for (i, stored_connection) in stored_connections.iter().enumerate() {
        let i = 1 + i as u32;
        assert_eq!(
            stored_connection.appguard_tcp_connection,
            if i % 2 == 0 {
                sample_tcp_connection("HTTP".to_string())
            } else {
                sample_tcp_connection_2("HTTP".to_string())
            }
        );
    }

    // verify stored ipinfos
    let ip_info_handler = ip_info_handler();
    let blacklist_conn = Arc::new(Mutex::new(
        rusqlite::Connection::open(BLACKLIST_PATH).expect("Test"),
    ));
    let stored_ipinfos = retrieve_stored_ipinfos(&conn);
    // assert_eq!(stored_ipinfos.len(), 2);
    for (i, stored_ipinfo) in stored_ipinfos.iter().enumerate() {
        let i = 1 + i as u32;
        assert_eq!(
            stored_ipinfo.ip_info,
            AppGuardIpInfo::lookup(&stored_ipinfo.ip_info.ip, &ip_info_handler, &blacklist_conn)
                .await
                .unwrap()
        );
        if i % 2 == 0 {
            assert!(stored_ipinfo.ip_info.country.is_none());
            assert!(stored_ipinfo.ip_info.asn.is_none());
            assert!(stored_ipinfo.ip_info.org.is_none());
            assert!(stored_ipinfo.ip_info.continent_code.is_none());
            assert!(stored_ipinfo.ip_info.region.is_none());
            assert!(stored_ipinfo.ip_info.city.is_none());
            assert!(stored_ipinfo.ip_info.postal.is_none());
            assert!(stored_ipinfo.ip_info.timezone.is_none());
        } else {
            assert!(stored_ipinfo.ip_info.country.is_some());
            assert!(stored_ipinfo.ip_info.asn.is_some());
            assert!(stored_ipinfo.ip_info.org.is_some());
            assert!(stored_ipinfo.ip_info.continent_code.is_some());
            assert!(stored_ipinfo.ip_info.region.is_some());
            assert!(stored_ipinfo.ip_info.city.is_some());
            assert!(stored_ipinfo.ip_info.postal.is_some());
            assert!(stored_ipinfo.ip_info.timezone.is_some());
        }
    }

    // set retention to 5 seconds
    write_config_to_file(&Config {
        retention_sec: 5,
        ..Config::default()
    });

    // verify that the there is still some data
    for table in &[DbTable::TcpConnection, DbTable::IpInfo] {
        assert!(count_rows_in_table(&conn, table.to_str()) > 0);
    }

    // wait for the data to expire and verify that tables are empty
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    for table_name in DbTable::ALL.iter().map(|t| t.to_str()) {
        assert_eq!(count_rows_in_table(&conn, table_name), 0);
    }

    // stop the server
    server_clean();
}

#[tokio::test]
#[serial]
async fn test_grpc_server_durable_storage_with_empty_data() {
    // start the server
    server_setup();

    // create a client
    let mut client = client_setup().await;

    // create a connection to the sqlite database
    let conn = db_setup();

    // verify tables are empty
    for table_name in DbTable::ALL.iter().map(|t| t.to_str()) {
        assert_eq!(count_rows_in_table(&conn, table_name), 0);
    }

    for _ in 1..=NUM_ITER {
        // handle_tcp_connection
        client
            .handle_tcp_connection(None, AppGuardTcpConnection::default())
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 0);
    for table in &[DbTable::TcpConnection] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored connections
    let stored_connections = retrieve_stored_tcp_connections(&conn);
    assert_eq!(stored_connections.len(), NUM_ITER as usize);
    for stored_connection in stored_connections.iter() {
        assert_eq!(
            stored_connection.appguard_tcp_connection,
            AppGuardTcpConnection::default()
        );
    }

    // verify stored ipinfos
    let stored_ipinfos = retrieve_stored_ipinfos(&conn);
    assert_eq!(stored_ipinfos.len(), 0);

    // stop the server
    server_clean();
}

#[tokio::test]
#[serial]
async fn test_grpc_server_with_log_requests_disabled() {
    // start the server
    server_setup();

    // create a client
    let mut client = client_setup().await;

    // create a connection to the sqlite database
    let conn = db_setup();

    // verify tables are empty
    for table_name in DbTable::ALL.iter().map(|t| t.to_str()) {
        assert_eq!(count_rows_in_table(&conn, table_name), 0);
    }

    // disable log_requests
    write_config_to_file(&Config {
        log_requests: false,
        ..Config::default()
    });
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    for _ in 1..=NUM_ITER {
        // handle_tcp_connection
        client
            .handle_tcp_connection(None, AppGuardTcpConnection::default())
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 0);
    for table in &[DbTable::TcpConnection] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // stop the server
    server_clean();
}

#[tokio::test]
#[serial]
async fn test_grpc_server_with_log_responses_disabled() {
    // start the server
    server_setup();

    // create a client
    let mut client = client_setup().await;

    // create a connection to the sqlite database
    let conn = db_setup();

    // verify tables are empty
    for table_name in DbTable::ALL.iter().map(|t| t.to_str()) {
        assert_eq!(count_rows_in_table(&conn, table_name), 0);
    }

    // disable log_responses
    write_config_to_file(&Config {
        log_responses: false,
        ..Config::default()
    });
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    for _ in 1..=NUM_ITER {
        // handle_tcp_connection
        client
            .handle_tcp_connection(None, AppGuardTcpConnection::default())
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 0);
    for table in &[DbTable::TcpConnection] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // stop the server
    server_clean();
}

// #[tokio::test]
// #[serial]
// async fn test_grpc_server_responds_with_errors() {
//     // start the server
//     server_setup();
//
//     // create a client
//     let mut client = client_setup().await;
//
//     // delete the DB to force the server to respond with errors
//     assert!(Path::new(SQLITE_PATH.as_str()).exists());
//     remove_file(SQLITE_PATH.as_str()).unwrap_or(());
//     assert!(!Path::new(SQLITE_PATH.as_str()).exists());
//
//     // handle_tcp_connection
//     let ret_val = handle_tcp_connection(&mut client, AppGuardTcpConnection::default()).await;
//     let error = ret_val.unwrap_err();
//     assert_eq!(error.message(), "attempt to write a readonly database");
//     assert_eq!(error.code(), tonic::Code::Internal);
//
//     assert!(!Path::new(SQLITE_PATH.as_str()).exists());
//
//     // stop the server
//     server_teardown(server);
// }
