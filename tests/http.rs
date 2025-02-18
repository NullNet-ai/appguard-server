use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use serial_test::serial;

use appguard_server::config::Config;
use appguard_server::constants::{API_KEY, BLACKLIST_PATH};
use appguard_server::db::tables::DbTable;
use appguard_server::db::views::DbView;
use appguard_server::fetch_data::{client_builder_with_ua, MmdbReader};
use appguard_server::firewall::firewall::FirewallResult;
use appguard_server::helpers::get_env;
use appguard_server::proto::aiguard::AiGuardResponse;
use appguard_server::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, FirewallPolicy,
};

use crate::config::write_config_to_file;
use crate::helpers::{
    client_setup, count_rows_in_table, db_setup, server_clean, server_setup, NUM_ITER,
};
use crate::http_request::{
    retrieve_stored_http_requests, sample_http_request, sample_http_request_2,
};
use crate::http_request_ai::retrieve_stored_http_request_ai;
use crate::http_request_dataset::retrieve_stored_http_request_dataset;
use crate::http_response::{
    retrieve_stored_http_responses, sample_http_response, sample_http_response_2,
};
use crate::tcp_connection::{sample_tcp_connection, sample_tcp_connection_2};

mod config;
mod helpers;
mod http_headers;
mod http_request;
mod http_request_ai;
mod http_request_dataset;
mod http_response;
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

    for i in 1..=NUM_ITER {
        // handle_http_request
        let ret_val = client
            .handle_http_request(None, FirewallPolicy::Allow, sample_http_request(i, true))
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);

        // handle_http_response
        let ret_val = client
            .handle_http_response(None, FirewallPolicy::Allow, sample_http_response(0, true))
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    for table in &[DbTable::HttpRequest, DbTable::HttpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_http_requests(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);
    for stored_request in stored_requests.iter() {
        assert_eq!(
            stored_request.app_guard_http_request,
            sample_http_request(0, false)
        );
        assert_eq!(stored_request.ip, "::1");
        assert_eq!(
            stored_request.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec![]
            }
        );
        let user_agent = "Mozilla/5.0".to_string();
        assert_eq!(stored_request.user_agent, Some(user_agent));
        let cookies = "[\"bis\", \"quits\"".to_string();
        assert_eq!(stored_request.cookies, Some(cookies));
    }

    // verify stored responses
    let stored_responses = retrieve_stored_http_responses(&conn);
    assert_eq!(stored_responses.len(), NUM_ITER as usize);
    for stored_response in stored_responses.iter() {
        assert_eq!(stored_response.ip, "::1");
        assert_eq!(
            stored_response.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec![]
            }
        );
        assert_eq!(stored_response.code, 200);
        assert_eq!(
            stored_response.headers,
            sample_http_response(0, false).headers
        );
        assert!(stored_response.time_usec.is_none());
        let size = 123;
        assert_eq!(stored_response.size, Some(size));
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
        // handle_http_request
        if i % 2 == 0 {
            let http_request = sample_http_request(i, true);
            let ret_val = client
                .handle_http_request(None, FirewallPolicy::Allow, http_request)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
        } else {
            let http_request = sample_http_request_2(0, true);
            let ret_val = client
                .handle_http_request(None, FirewallPolicy::Allow, http_request)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Deny as i32);
        };

        // handle_http_response
        if i % 2 == 0 {
            let http_response = sample_http_response(0, true);
            let ret_val = client
                .handle_http_response(None, FirewallPolicy::Allow, http_response)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
        } else {
            let http_response = sample_http_response_2(true);
            let ret_val = client
                .handle_http_response(None, FirewallPolicy::Allow, http_response)
                .await
                .unwrap();
            assert_eq!(ret_val.policy, FirewallPolicy::Deny as i32);
        };
    }

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // verify the number of rows in tables
    for table in &[DbTable::HttpRequest, DbTable::HttpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER * 2);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_http_requests(&conn);
    assert_eq!(stored_requests.len(), 2 * NUM_ITER as usize);
    for (i, stored_request) in stored_requests.iter().enumerate() {
        let i = 1 + i as u32;
        let user_agent;
        let cookies;
        if i % 2 == 0 {
            assert_eq!(stored_request.ip, "::1");
            assert_eq!(
                stored_request.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Allow,
                    reasons: vec![]
                }
            );
            assert_eq!(
                stored_request.app_guard_http_request,
                sample_http_request(0, false)
            );
            user_agent = "Mozilla/5.0".to_string();
            cookies = "[\"bis\", \"quits\"".to_string();
        } else {
            assert_eq!(stored_request.ip, "8.8.8.8");
            assert_eq!(
                stored_request.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Deny,
                    reasons: vec!["protocol".to_string(), "country".to_string()]
                }
            );
            assert_eq!(
                stored_request.app_guard_http_request,
                sample_http_request_2(0, false)
            );
            user_agent = "appguard-1.0.0".to_string();
            cookies = "2.5".to_string();
        }
        assert_eq!(stored_request.user_agent, Some(user_agent));
        assert_eq!(stored_request.cookies, Some(cookies));
    }

    // verify stored responses
    let stored_responses = retrieve_stored_http_responses(&conn);
    assert_eq!(stored_responses.len(), 2 * NUM_ITER as usize);
    for (i, stored_response) in stored_responses.iter().enumerate() {
        let i = 1 + i as u32;
        let size: u64;
        if i % 2 == 0 {
            assert_eq!(stored_response.ip, "::1");
            assert_eq!(
                stored_response.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Allow,
                    reasons: vec![]
                }
            );
            assert_eq!(stored_response.code, 200);
            assert_eq!(
                stored_response.headers,
                sample_http_response(0, false).headers
            );
            assert!(stored_response.time_usec.is_none());
            size = 123;
        } else {
            assert_eq!(stored_response.ip, "8.8.8.8");
            assert_eq!(
                stored_response.fw_res,
                FirewallResult {
                    policy: FirewallPolicy::Deny,
                    reasons: vec!["protocol".to_string(), "country".to_string()]
                }
            );
            assert_eq!(stored_response.code, 404);
            assert_eq!(
                stored_response.headers,
                sample_http_response_2(false).headers
            );
            assert!(stored_response.time_usec.is_none());
            size = 256;
        }
        assert_eq!(stored_response.size, Some(size));
    }

    // set retention to 5 seconds
    write_config_to_file(&Config {
        retention_sec: 5,
        ..Config::default()
    });

    // verify that the there is still some data
    for table in &[DbTable::HttpRequest, DbTable::HttpResponse] {
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
        // handle_http_request
        let ret_val = client
            .handle_http_request(None, FirewallPolicy::Allow, AppGuardHttpRequest::default())
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);

        // handle_http_response
        let ret_val = client
            .handle_http_response(None, FirewallPolicy::Allow, AppGuardHttpResponse::default())
            .await
            .unwrap();
        assert_eq!(ret_val.policy, FirewallPolicy::Allow as i32);
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    for table in &[DbTable::HttpRequest, DbTable::HttpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_http_requests(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);
    for stored_request in stored_requests.iter() {
        assert_eq!(
            stored_request.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec![]
            }
        );
        assert_eq!(
            stored_request.app_guard_http_request,
            AppGuardHttpRequest::default()
        );
        assert_eq!(stored_request.user_agent, None);
        assert_eq!(stored_request.cookies, None);
    }

    // verify stored responses
    let stored_responses = retrieve_stored_http_responses(&conn);
    assert_eq!(stored_responses.len(), NUM_ITER as usize);
    for stored_response in stored_responses.iter() {
        assert_eq!(
            stored_response.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Allow,
                reasons: vec![]
            }
        );
        assert_eq!(stored_response.code, 0);
        assert_eq!(stored_response.headers, HashMap::new());
        assert!(stored_response.time_usec.is_none());
        assert!(stored_response.size.is_none());
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
        // handle_http_request
        client
            .handle_http_request(None, FirewallPolicy::Allow, AppGuardHttpRequest::default())
            .await
            .unwrap();

        // handle_http_response
        client
            .handle_http_response(None, FirewallPolicy::Allow, AppGuardHttpResponse::default())
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::HttpRequest.to_str()), 0);
    for table in &[DbTable::HttpResponse] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_http_requests(&conn);
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
        // handle_http_request
        client
            .handle_http_request(None, FirewallPolicy::Allow, AppGuardHttpRequest::default())
            .await
            .unwrap();

        // handle_http_response
        client
            .handle_http_response(None, FirewallPolicy::Allow, AppGuardHttpResponse::default())
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(
        count_rows_in_table(&conn, DbTable::HttpResponse.to_str()),
        0
    );
    for table in &[DbTable::HttpRequest] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored responses
    let stored_responses = retrieve_stored_http_responses(&conn);
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
//     // handle_http_request
//     let ret_val = handle_http_request(&mut client, AppGuardHttpRequest::default()).await;
//     let error = ret_val.unwrap_err();
//     assert_eq!(error.message(), "attempt to write a readonly database");
//     assert_eq!(error.code(), tonic::Code::Internal);
//
//     // handle_http_response
//     let ret_val = handle_http_response(&mut client, AppGuardHttpResponse::default()).await;
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
async fn test_grpc_server_http_response_time() {
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
        let ret_val = client
            .handle_tcp_connection(None, sample_tcp_connection("HTTP".to_string()))
            .await
            .unwrap();
        let tcp_id = ret_val.tcp_info.as_ref().unwrap().tcp_id;

        // handle_http_request
        client
            .handle_http_request(
                None,
                FirewallPolicy::Allow,
                sample_http_request(tcp_id, true),
            )
            .await
            .unwrap();

        // handle_http_response
        client
            .handle_http_response(
                None,
                FirewallPolicy::Allow,
                sample_http_response(tcp_id, true),
            )
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 1);
    for table in &[
        DbTable::TcpConnection,
        DbTable::HttpRequest,
        DbTable::HttpResponse,
    ] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }

    // verify stored requests
    let stored_requests = retrieve_stored_http_requests(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);

    // verify stored responses
    let stored_responses = retrieve_stored_http_responses(&conn);
    assert_eq!(stored_responses.len(), NUM_ITER as usize);
    for stored_response in stored_responses.iter() {
        assert!(stored_response.time_usec.unwrap() > 0);
    }

    // stop the server
    server_clean();
}

#[tokio::test]
#[serial]
async fn test_grpc_server_http_request_ai_dataset() {
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
        let ret_val = client
            .handle_tcp_connection(None, sample_tcp_connection_2("HTTP".to_string()))
            .await
            .unwrap();
        let tcp_id = ret_val.tcp_info.as_ref().unwrap().tcp_id;

        // handle_http_request
        client
            .handle_http_request(
                None,
                FirewallPolicy::Allow,
                sample_http_request_2(tcp_id, true),
            )
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // verify the number of rows in tables
    assert_eq!(count_rows_in_table(&conn, DbTable::IpInfo.to_str()), 1);
    for table in &[
        DbTable::TcpConnection,
        DbTable::HttpRequest,
        DbTable::HttpRequestAi,
    ] {
        assert_eq!(count_rows_in_table(&conn, table.to_str()), NUM_ITER);
    }
    assert_eq!(
        count_rows_in_table(&conn, DbView::HttpRequestDataset.to_str()),
        NUM_ITER
    );

    // verify stored AI HTTP requests
    let stored_requests = retrieve_stored_http_request_ai(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);
    for stored_request in stored_requests.iter() {
        assert_eq!(
            stored_request.ai_res,
            AiGuardResponse {
                confidence: 0.5,
                columns: vec!["original_url".to_owned(), "user_agent".to_owned()],
            }
        );
    }

    // verify stored dataset HTTP requests
    let api_key = get_env(API_KEY, "key", "IP info API key");
    let reader = Arc::new(RwLock::new(MmdbReader::default()));
    let blacklist_conn = Arc::new(Mutex::new(
        rusqlite::Connection::open(BLACKLIST_PATH).expect("Test"),
    ));
    let stored_requests = retrieve_stored_http_request_dataset(&conn);
    assert_eq!(stored_requests.len(), NUM_ITER as usize);
    for stored_request in stored_requests.iter() {
        assert_eq!(
            stored_request.fw_res,
            FirewallResult {
                policy: FirewallPolicy::Deny,
                reasons: vec!["protocol".to_string(), "country".to_string()]
            }
        );
        assert_eq!(
            stored_request.ai_res,
            AiGuardResponse {
                confidence: 0.5,
                columns: vec!["original_url".to_owned(), "user_agent".to_owned()],
            }
        );
        let sample_tcp = sample_tcp_connection_2("HTTP".to_string());
        assert_eq!(stored_request.source, sample_tcp.source_ip);
        assert_eq!(stored_request.sport, sample_tcp.source_port);
        let ip_info = AppGuardIpInfo::lookup(
            &sample_tcp.source_ip.unwrap(),
            &client_builder_with_ua().build().unwrap(),
            &api_key,
            &reader,
            &blacklist_conn,
        )
        .await
        .unwrap();
        assert_eq!(stored_request.country, ip_info.country);
        assert_eq!(stored_request.asn, ip_info.asn);
        assert_eq!(stored_request.org, ip_info.org);
        assert_eq!(stored_request.blacklist, ip_info.blacklist);
        let sample_http = sample_http_request_2(0, false);
        assert_eq!(stored_request.original_url, sample_http.original_url);
        let user_agent = "appguard-1.0.0".to_string();
        assert_eq!(stored_request.user_agent, Some(user_agent));
        assert_eq!(stored_request.headers, sample_http.headers);
        assert_eq!(stored_request.method, sample_http.method);
        assert_eq!(stored_request.query, sample_http.query);
        let cookies = "2.5".to_string();
        assert_eq!(stored_request.cookies, Some(cookies));
    }

    // stop the server
    server_clean();
}
