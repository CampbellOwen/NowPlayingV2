use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Query, State},
    response::Redirect,
    routing::get,
    Router,
};
use local_ip_address::local_ip;
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

#[derive(Debug, Clone)]
struct LoginState {
    code_verifier: Option<Vec<u8>>,
    server_config: ServerState,
    api_data: ApiData,
}

#[derive(Debug, Clone)]
struct ServerState {
    ip: String,
    port: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ApiData {
    client_id: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u32,
    refresh_token: String,
}

#[tokio::main]
async fn main() {
    let config_file = std::fs::read_to_string("config.json")
        .expect("Need to have a config.json file containing your app's client_id");
    let config: ApiData = serde_json::from_str(&config_file).unwrap();

    let login_state = Arc::new(Mutex::new(LoginState {
        code_verifier: None,
        server_config: ServerState {
            ip: local_ip().unwrap().to_string(),
            port: "8765".to_string(),
        },
        api_data: config,
    }));

    let app = Router::new()
        .route("/authcode", get(auth_code).with_state(login_state.clone()))
        .route("/login", get(login).with_state(login_state));

    //axum::Server::local_addr(&self)gg

    axum::Server::bind(&"0.0.0.0:8765".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn auth_code(
    Query(params): Query<HashMap<String, String>>,
    State(app_state): State<Arc<Mutex<LoginState>>>,
) -> &'static str {
    let code_verifier;
    let client_id;
    {
        let mut app_state = app_state.lock().await;
        code_verifier = app_state.code_verifier.as_ref().unwrap().clone();
        client_id = app_state.api_data.client_id.clone();

        app_state.code_verifier = None;
    }

    let client = reqwest::Client::new();
    let url = Url::parse_with_params(
        "https://accounts.spotify.com/api/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &params["code"]),
            (
                "redirect_uri",
                "https://campbellowen.github.io/redirect_to_local",
            ),
            ("client_id", &client_id),
            (
                "code_verifier",
                std::str::from_utf8(&code_verifier).unwrap(),
            ),
            ("response_type", "code"),
        ],
    )
    .unwrap()
    .to_string();
    let response = client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Content-Length", "0")
        .send()
        .await
        .unwrap();

    let response_data = response.json::<TokenResponse>().await.unwrap();

    println!("Access  Token: {:?}", &response_data.access_token);
    println!("Refresh Token: {:?}", &response_data.refresh_token);

    "Auth code"
}

async fn login(State(app_state): State<Arc<Mutex<LoginState>>>) -> Redirect {
    let code_verifier = pkce::code_verifier(100);
    let code_challenge = pkce::code_challenge(&code_verifier);

    let ip;
    let client_id;
    {
        let mut app_state = app_state.lock().await;
        app_state.code_verifier = Some(code_verifier);

        ip = base64::encode(format!(
            "{}:{}",
            &app_state.server_config.ip, &app_state.server_config.port
        ));
        client_id = app_state.api_data.client_id.clone();
    }

    let url = Url::parse_with_params(
        "https://accounts.spotify.com/authorize",
        &[
            ("code_challenge_method", "S256"),
            ("code_challenge", &code_challenge),
            ("client_id", &client_id),
            ("response_type", "code"),
            (
                "redirect_uri",
                "https://campbellowen.github.io/redirect_to_local",
            ),
            (
                "scope",
                "user-read-playback-state user-read-currently-playing",
            ),
            ("state", &ip),
        ],
    )
    .unwrap();

    println!("Redirecting to Spotify log-in page");
    Redirect::to(url.as_ref())
}
