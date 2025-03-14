use serial_test::serial;

use appguard_server::config::Config;
use appguard_server::db::tables::DbTable;
use appguard_server::firewall::firewall::FirewallResult;
use appguard_server::proto::appguard::{AppGuardSmtpRequest, AppGuardSmtpResponse, FirewallPolicy};

use crate::config::write_config_to_file;
use crate::helpers::{
    client_setup, count_rows_in_table, db_setup, server_clean, server_setup, NUM_ITER,
};
use crate::smtp_request::{
    retrieve_stored_smtp_requests, sample_smtp_request, sample_smtp_request_2,
};
use crate::smtp_response::{
    retrieve_stored_smtp_responses, sample_smtp_response, sample_smtp_response_2,
};
use crate::tcp_connection::sample_tcp_connection;

mod config;
mod helpers;
mod ip_info;
mod smtp_headers;
mod smtp_request;
mod smtp_response;
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

    for i in 1..=NUM_ITER {
        // handle_smtp_request
        let ret_val = client
            .handle_smtp_request(None, FirewallPolicy::Allow, sample_smtp_request(i, true))
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);

        // handle_smtp_response
        let ret_val = client
            .handle_smtp_response(None, FirewallPolicy::Allow, sample_smtp_response(0, true))
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    for table in &[DbTable::SmtpRequest, DbTable::SmtpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_smtp_requests(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);
    for stored_request in stored_requests.iter() {
        assert_eq!(stored_request.ip, "::1");
        assert_eq!(
            stored_request.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec!["body".to_string()],
            }
        );
        assert_eq!(
            stored_request.app_guard_smtp_request,
            sample_smtp_request(0, false)
        );
        assert_eq!(stored_request.user_agent, Some("Supa cool UA".to_owned()));
    }

    // verify stored responses
    let stored_responses = retrieve_stored_smtp_responses(&conn);
    assert_eq!(stored_responses.len(), NUM_ITER as usize);
    for stored_response in stored_responses.iter() {
        assert_eq!(stored_response.ip, "::1");
        assert_eq!(
            stored_response.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec![],
            }
        );
        assert_eq!(stored_response.app_guard_smtp_response.code, Some(250));
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
        // handle_smtp_request
        if i % 2 == 0 {
            let smtp_request = sample_smtp_request(i, true);
            let ret_val = client
                .handle_smtp_request(None, FirewallPolicy::Allow, smtp_request)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
        } else {
            let smtp_request = sample_smtp_request_2(true);
            let ret_val = client
                .handle_smtp_request(None, FirewallPolicy::Allow, smtp_request)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
        };

        // handle_smtp_response
        if i % 2 == 0 {
            let smtp_response = sample_smtp_response(0, true);
            let ret_val = client
                .handle_smtp_response(None, FirewallPolicy::Allow, smtp_response)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
        } else {
            let smtp_response = sample_smtp_response_2(true);
            let ret_val = client
                .handle_smtp_response(None, FirewallPolicy::Allow, smtp_response)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Deny as i32);
        };
    }

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // verify the number of rows in tables
    for table in &[DbTable::SmtpRequest, DbTable::SmtpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER * 2);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_smtp_requests(&conn);
    assert_eq!(stored_requests.len(), 2 * NUM_ITER as usize);
    for (i, stored_request) in stored_requests.iter().enumerate() {
        let i = 1 + i as u32;
        if i % 2 == 0 {
            assert_eq!(stored_request.ip, "::1");
            assert_eq!(
                stored_request.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Allow,
                    reasons: vec!["body".to_string()],
                }
            );
            assert_eq!(
                stored_request.app_guard_smtp_request,
                sample_smtp_request(0, false)
            );
            assert_eq!(stored_request.user_agent, Some("Supa cool UA".to_owned()));
        } else {
            assert_eq!(stored_request.ip, "8.8.8.8");
            assert_eq!(
                stored_request.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Allow,
                    reasons: vec![],
                }
            );
            assert_eq!(
                stored_request.app_guard_smtp_request,
                sample_smtp_request_2(false)
            );
            assert_eq!(stored_request.user_agent, None);
        }
    }

    // verify stored responses
    let stored_responses = retrieve_stored_smtp_responses(&conn);
    assert_eq!(stored_responses.len(), 2 * NUM_ITER as usize);
    for (i, stored_response) in stored_responses.iter().enumerate() {
        let i = 1 + i as u32;
        if i % 2 == 0 {
            assert_eq!(stored_response.ip, "::1");
            assert_eq!(
                stored_response.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Allow,
                    reasons: vec![],
                }
            );
            assert_eq!(stored_response.app_guard_smtp_response.code, Some(250));
        } else {
            assert_eq!(stored_response.ip, "8.8.8.8");
            assert_eq!(
                stored_response.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Deny,
                    reasons: vec!["response_code".to_string()],
                }
            );
            assert_eq!(
                stored_response.app_guard_smtp_response,
                sample_smtp_response_2(false)
            );
        }
    }

    // set retention to 5 seconds
    write_config_to_file(&Config {
        ..Config::default()
    });

    // verify that the there is still some data
    for table in &[DbTable::SmtpRequest, DbTable::SmtpResponse] {
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
        // handle_smtp_request
        let ret_val = client
            .handle_smtp_request(None, FirewallPolicy::Allow, AppGuardSmtpRequest::default())
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);

        // handle_smtp_response
        let ret_val = client
            .handle_smtp_response(None, FirewallPolicy::Allow, AppGuardSmtpResponse::default())
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    for table in &[DbTable::SmtpRequest, DbTable::SmtpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_smtp_requests(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);
    for stored_request in stored_requests.iter() {
        assert_eq!(
            stored_request.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec![],
            }
        );
        assert_eq!(
            stored_request.app_guard_smtp_request,
            AppGuardSmtpRequest::default()
        );
        assert_eq!(stored_request.user_agent, None);
    }

    // verify stored responses
    let stored_responses = retrieve_stored_smtp_responses(&conn);
    assert_eq!(stored_responses.len(), NUM_ITER as usize);
    for stored_response in stored_responses.iter() {
        assert_eq!(
            stored_response.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec![],
            }
        );
        assert_eq!(
            stored_response.app_guard_smtp_response,
            AppGuardSmtpResponse::default()
        );
    }

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
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    write_config_to_file(&Config {
        log_requests: false,
        ..Config::default()
    });
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    for _ in 1..=NUM_ITER {
        // handle_smtp_request
        client
            .handle_smtp_request(None, FirewallPolicy::Allow, AppGuardSmtpRequest::default())
            .await
            .unwrap();

        // handle_smtp_response
        client
            .handle_smtp_response(None, FirewallPolicy::Allow, AppGuardSmtpResponse::default())
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::SmtpRequest.to_str()), 0);
    for table in &[DbTable::SmtpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_smtp_requests(&conn);
    assert_eq!(stored_requests.len(), 0);

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
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    write_config_to_file(&Config {
        log_responses: false,
        ..Config::default()
    });
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    for _ in 1..=NUM_ITER {
        // handle_smtp_request
        client
            .handle_smtp_request(None, FirewallPolicy::Allow, AppGuardSmtpRequest::default())
            .await
            .unwrap();

        // handle_smtp_response
        client
            .handle_smtp_response(None, FirewallPolicy::Allow, AppGuardSmtpResponse::default())
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(
        count_rows_in_table(&conn, DbTable::SmtpResponse.to_str()),
        0
    );
    for table in &[DbTable::SmtpRequest] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored responses
    let stored_responses = retrieve_stored_smtp_responses(&conn);
    assert_eq!(stored_responses.len(), 0);

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
//     // handle_smtp_request
//     let ret_val = handle_smtp_request(&mut client, AppGuardSmtpRequest::default()).await;
//     let error = ret_val.unwrap_err();
//     assert_eq!(error.message(), "attempt to write a readonly database");
//     assert_eq!(error.code(), tonic::Code::Internal);
//
//     // handle_smtp_response
//     let ret_val = handle_smtp_response(&mut client, AppGuardSmtpResponse::default()).await;
//     let error = ret_val.unwrap_err();
//     assert_eq!(error.message(), "attempt to write a readonly database");
//     assert_eq!(error.code(), tonic::Code::Internal);
//
//     assert!(!Path::new(SQLITE_PATH.as_str()).exists());
//
//     // stop the server
//     server_teardown();
// }

#[tokio::test]
#[serial]
async fn test_grpc_server_smtp_response_time() {
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

    for i in 1..=NUM_ITER {
        // handle_tcp_connection
        let ret_val = client
            .handle_tcp_connection(None, sample_tcp_connection("SMTP".to_string()))
            .await
            .unwrap();
        let tcp_id = ret_val.tcp_info.as_ref().unwrap().tcp_id;
        assert_eq!(tcp_id, i);

        // handle_smtp_request
        client
            .handle_smtp_request(
                None,
                FirewallPolicy::Allow,
                sample_smtp_request(tcp_id, true),
            )
            .await
            .unwrap();

        // handle_smtp_response
        client
            .handle_smtp_response(
                None,
                FirewallPolicy::Allow,
                sample_smtp_response(tcp_id, true),
            )
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 1);
    for table in &[
        DbTable::TcpConnection,
        DbTable::SmtpRequest,
        DbTable::SmtpResponse,
    ] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_smtp_requests(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);

    // verify stored responses
    let stored_responses = retrieve_stored_smtp_responses(&conn);
    assert_eq!(stored_responses.len(), NUM_ITER as usize);
    for stored_response in stored_responses.iter() {
        assert!(stored_response.time_usec.unwrap() > 0);
    }

    // stop the server
    server_clean();
}
