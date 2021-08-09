use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::header::HeaderValue;
use reqwest::{Url, Client, header::AUTHORIZATION};
use serde::{Serialize, Deserialize};
use serde_json::json;
use err_derive::Error;
use tokio::sync::{RwLock, RwLockReadGuard};
use tracing::{warn, debug, info};

/// The duration after which clients are pruned if not seen.
/// Pruning only occurs when a client list is successfully retrieved; in case of
/// error, old results will remain available until the next successful scan.
const CLIENT_TTL_SECONDS: i64 = 15 * 60;

#[derive(Debug, Error)]
pub enum QnapError {
  #[error(display = "a session is already active")]
  LoginCollision,

  #[error(display = "HTTP error: {:?}", _0)]
  HTTPError(#[error(source)] reqwest::Error),

  #[error(display = "URL error: {:?}", _0)]
  URLError(#[error(source)] url::ParseError),

  #[error(display = "API error: {} (code: {}, message: {})", message, error_code, error_message)]
  ResponseError {
    message: String,
    error_code: isize,
    error_message: String
  },

  #[error(display = "header error: {:?}", _0)]
  HeaderError(#[error(source)] reqwest::header::InvalidHeaderValue),

  #[error(display = "no token; login required")]
  NoToken
}

impl QnapError {
  fn from_response<T>(response: &QnapResponse<T>, message: impl Into<String>) -> QnapError {
    QnapError::ResponseError {
      message: message.into(),
      error_code: response.error_code,
      error_message: response.error_message.clone(),
    }
  }
}

type Result<T> = std::result::Result<T, QnapError>;

#[derive(Debug, Deserialize)]
struct LoginResponse {
  access_token: String,
  had_session: bool,
  is_qid: bool,
}

#[derive(Debug, Deserialize)]
struct QnapJwtHeader {
  #[serde(with = "chrono::serde::ts_seconds")]
  exp: DateTime<Utc>,

  #[serde(with = "chrono::serde::ts_seconds")]
  orig_iat: DateTime<Utc>,
}

#[derive(Debug)]
struct QnapToken {
  token: String,
  header: QnapJwtHeader
}

#[derive(Debug, Deserialize)]
struct QnapResponse<T> {
  error_code: isize,
  error_message: String,
  result: Option<T>,
  total: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct ClientMetadata {
  upload: String,
  download: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct ClientDevice {
  pub connect_iface: String,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
  pub last_conn_time: DateTime<Utc>,
  pub mac_addr: String,
  pub status: isize,
  pub description: String,
  pub name: String,
  #[serde(rename = "IP")]
  pub ip: IpAddr,
  pub hostname: String,

  #[serde(rename = "meta_data")]
  pub metadata: Option<ClientMetadata>,
}

impl PartialEq for ClientDevice {
  fn eq(&self, other: &Self) -> bool {
    self.connect_iface == other.connect_iface &&
      self.mac_addr == other.mac_addr
  }
}

impl Ord for ClientDevice {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    (&self.connect_iface, &self.mac_addr).cmp(&(&other.connect_iface, &other.mac_addr))
  }
}

impl PartialOrd for ClientDevice {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl Hash for ClientDevice {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.connect_iface.hash(state);
    self.mac_addr.hash(state);
  }
}

pub struct QnapClient {
  base_url: Url,
  username: String,
  password: String,
  client: Client,
  token: Option<QnapToken>,
}

impl QnapClient {
  pub fn new(base_url: Url, username: &str, password: &str) -> QnapClient {
    QnapClient {
      base_url,
      username: username.to_string(),
      password: password.to_string(),
      client: Client::new(),
      token: None
    }
  }

  pub fn has_token_expired(&self) -> bool {
    // note: tokens seem to last 24h
    let token = match &self.token {
      Some(token) => token,
      None => return false
    };

    Utc::now() > token.header.exp
  }

  pub async fn login(&mut self, force: bool) -> Result<()> {
    let url = self.base_url.join("/miro/api/v1/login")?;

    let response: QnapResponse<LoginResponse> = self.client
      .post(url)
      .json(&json!({
        "username": &self.username,
        "password": base64::encode(&self.password),
        "remember_me": false,
        "force": force,
      }))
      .send().await?
      .json().await?;

    let result = match &response.result {
      Some(result) => result,
      None => return Err(QnapError::ResponseError {
        message: format!("login failed: {:?}", response),
        error_code: response.error_code,
        error_message: response.error_message,
      })
    };

    if !force && result.had_session {
      return Err(QnapError::LoginCollision);
    }

    if result.access_token.is_empty() {
      return Err(QnapError::from_response(&response, "received no token"));
    }

    let header_str = result.access_token
      .split('.')
      .skip(1)
      .next()
      .ok_or_else(|| QnapError::from_response(&response, "invalid jwt header"))?;

    let header_bytes = base64::decode(header_str)
      .map_err(|e| QnapError::from_response(&response, format!("invalid header: {:?}", e)))?;

    let header: QnapJwtHeader = serde_json::from_slice(&header_bytes)
      .map_err(|e| QnapError::from_response(&response, format!("invalid header: {:?}", e)))?;

    self.token = Some(QnapToken {
      token: result.access_token.clone(),
      header,
    });

    Ok(())
  }

  pub async fn list_clients(&self) -> Result<Vec<ClientDevice>> {
    let token = match &self.token {
      Some(token) => token,
      None => return Err(QnapError::NoToken)
    };

    // TODO: handle pagination?
    let url = self.base_url.join("/miro/api/v1/clients")?;
    let client = reqwest::Client::new();
    let response: QnapResponse<Vec<ClientDevice>> = client
      .get(url)
      .header(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", &token.token))?)
      .query(&[("page", "1"), ("limit", "999")])
      .send().await?
      .json().await?;

    if let Some(result) = response.result {
      Ok(result)
    } else {
      return Err(QnapError::from_response(&response, "received no results"));
    }
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScannerEntry {
  last_seen: DateTime<Utc>,
  device: ClientDevice,
}

type ScannerEntries = Arc<RwLock<HashMap<ClientDevice, DateTime<Utc>>>>;

#[derive(Debug, Clone)]
pub struct QnapScanner {
  entries: ScannerEntries
}

async fn attempt_relogin(client: &mut QnapClient) -> Result<()> {
  let force = if client.has_token_expired() {
    // attempt to login immediately; the token expired
    debug!("qnap session expired, will refresh token");
    false
  } else {
    // the session was probably ended due to a user login; wait several minutes
    // before trying again to avoid kicking the user
    warn!("qnap session ended unexpectedly; waiting 10 minutes before retrying");
    tokio::time::sleep(Duration::from_secs(60 * 10)).await;
    true
  };

  client.login(force).await
}

async fn scan_continuous(mut client: QnapClient, entries: ScannerEntries) {
  let mut interval = tokio::time::interval(Duration::from_secs(20));

  loop {
    interval.tick().await;

    let clients = match client.list_clients().await {
      Ok(clients) => clients,
      Err(QnapError::ResponseError { error_code: 10032, .. }) => {
        if let Err(e) = attempt_relogin(&mut client).await {
          warn!("relogin failed: {}", e);

          // not much we can do, wait a bit to avoid log spam
          tokio::time::sleep(Duration::from_secs(300)).await;
        }
        continue;
      },
      e => {
        warn!("error scanning for qnap clients: {:?}", e);
        continue;
      }
    };

    let update_time = Utc::now();
    let mut entries = entries.write().await;
    for client in &clients {
      if let None = entries.insert(client.clone(), update_time) {
        info!("new client: {:?}", client);
      }
    }

    // prune old entries
    let remove_before = update_time - chrono::Duration::seconds(CLIENT_TTL_SECONDS);
    entries.retain(|e, last_seen| {
      if *last_seen <= remove_before {
        info!("pruning entry: {:?}", e);
        false
      } else {
        true
      }
    });
  }
}

impl QnapScanner {
  pub fn from_client(client: QnapClient) -> QnapScanner {
    let entries = Arc::new(RwLock::new(HashMap::new()));

    let entries_scan = Arc::clone(&entries);
    tokio::spawn(async move {
      scan_continuous(client, entries_scan).await
    });

    QnapScanner {
      entries
    }
  }

  pub async fn read_entries<'a>(&'a self) -> RwLockReadGuard<'a, HashMap<ClientDevice, DateTime<Utc>>> {
    self.entries.read().await
  }
}
