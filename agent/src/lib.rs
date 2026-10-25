use std::{
    env,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(windows)]
use reqwest::blocking::Client;
#[cfg(windows)]
use std::{sync::Arc, thread, time::Duration};

pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
const DEFAULT_SPOOL_LIMIT: u64 = 256 * 1024 * 1024;
const UPLOAD_BATCH: usize = 32;
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn log(level: &str, message: &str) {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let line = format!(
        "{{\"time\":{},\"level\":{},\"message\":{}}}\n",
        serde_json::to_string(&timestamp).unwrap_or_else(|_| "\"unknown\"".into()),
        serde_json::to_string(level).unwrap_or_else(|_| "\"error\"".into()),
        serde_json::to_string(message).unwrap_or_else(|_| "\"log encoding failed\"".into())
    );
    if let Some(path) = LOG_PATH.get() {
        if let Ok(_lock) = LOG_LOCK.get_or_init(|| Mutex::new(())).lock() {
            let result = (|| -> std::io::Result<()> {
                if let Some(parent) = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    std::fs::create_dir_all(parent)?;
                }
                if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() >= LOG_ROTATE_BYTES)
                {
                    let rotated = path.with_extension("log.1");
                    let _ = std::fs::remove_file(&rotated);
                    std::fs::rename(path, rotated)?;
                }
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?
                    .write_all(line.as_bytes())
            })();
            if result.is_ok() {
                return;
            }
        }
    }
    eprintln!("SENTINEL {level}: {message}");
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub id: String,
    pub schema_version: String,
    pub time: String,
    pub host_id: String,
    pub hostname: String,
    pub source: String,
    pub category: String,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
    pub fields: std::collections::BTreeMap<String, String>,
}

impl Event {
    fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.id.len() > 128 {
            return Err("event ID must contain 1 to 128 bytes".into());
        }
        if self.schema_version != "1.0" {
            return Err("unsupported event schema version".into());
        }
        if self.host_id.is_empty()
            || self.host_id.len() > 128
            || self.hostname.is_empty()
            || self.hostname.len() > 255
            || self.source.is_empty()
            || self.event_type.is_empty()
        {
            return Err(
                "host_id and hostname must be bounded; source and type are required".into(),
            );
        }
        if self
            .command_line
            .as_ref()
            .is_some_and(|value| value.len() > 4096)
        {
            return Err("command_line exceeds the 4096-byte limit".into());
        }
        DateTime::parse_from_rfc3339(&self.time)
            .map_err(|_| "event time must be RFC 3339".to_owned())?;
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_EVENT_BYTES {
            return Err("event exceeds the 1 MiB API limit".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub endpoint: String,
    pub token: String,
    pub host_id: String,
    pub hostname: String,
    pub spool_path: PathBuf,
    pub log_path: PathBuf,
    pub spool_limit: u64,
    pub channels: Vec<Channel>,
    pub client_certificate: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    pub name: String,
    pub event_ids: Vec<u16>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let endpoint = required("SENTINEL_SERVER_URL")?;
        let token = required("SENTINEL_AGENT_TOKEN")?;
        let hostname = env::var("COMPUTERNAME")
            .or_else(|_| env::var("HOSTNAME"))
            .map_err(|_| "COMPUTERNAME or HOSTNAME must be set".to_owned())?;
        let host_id = env::var("SENTINEL_HOST_ID").unwrap_or_else(|_| hostname.clone());
        if host_id.trim().is_empty() || host_id.len() > 128 {
            return Err("SENTINEL_HOST_ID must contain 1 to 128 bytes".into());
        }
        if hostname.trim().is_empty() || hostname.len() > 255 {
            return Err("hostname must contain 1 to 255 bytes".into());
        }
        let spool_path = env::var_os("SENTINEL_SPOOL_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("sentinel-agent.db"));
        let log_path = env::var_os("SENTINEL_LOG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| spool_path.with_extension("log"));
        let spool_limit = match env::var("SENTINEL_SPOOL_LIMIT_MB") {
            Ok(value) => value
                .parse::<u64>()
                .map_err(|_| "SENTINEL_SPOOL_LIMIT_MB must be a positive integer".to_owned())?
                .checked_mul(1024 * 1024)
                .ok_or_else(|| "SENTINEL_SPOOL_LIMIT_MB is too large".to_owned())?,
            Err(_) => DEFAULT_SPOOL_LIMIT,
        };
        if spool_limit < 1024 * 1024 {
            return Err("spool limit must be at least 1 MiB".into());
        }
        let channels = parse_channels(&env::var("SENTINEL_EVENT_CHANNELS").unwrap_or_default())?;
        let client_certificate = env::var_os("SENTINEL_CLIENT_CERT").map(PathBuf::from);
        let client_key = env::var_os("SENTINEL_CLIENT_KEY").map(PathBuf::from);
        if client_certificate.is_some() != client_key.is_some() {
            return Err(
                "SENTINEL_CLIENT_CERT and SENTINEL_CLIENT_KEY must be configured together".into(),
            );
        }
        validate_endpoint(&endpoint, client_certificate.is_some())?;
        Ok(Self {
            endpoint,
            token,
            host_id,
            hostname,
            spool_path,
            log_path,
            spool_limit,
            channels,
            client_certificate,
            client_key,
        })
    }
}

fn required(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} must be set"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

fn parse_channels(value: &str) -> Result<Vec<Channel>, String> {
    if value.trim().is_empty() {
        return Ok(vec![
            Channel {
                name: "Security".into(),
                event_ids: vec![4625, 4688],
            },
            Channel {
                name: "Microsoft-Windows-Sysmon/Operational".into(),
                event_ids: vec![1, 3, 11, 12, 13, 14],
            },
        ]);
    }
    let mut channels = Vec::new();
    for item in value.split(';').filter(|part| !part.trim().is_empty()) {
        let (name, ids) = item
            .split_once(':')
            .ok_or_else(|| format!("invalid channel mapping: {item}"))?;
        let event_ids = ids
            .split(',')
            .map(|id| {
                id.parse::<u16>()
                    .map_err(|_| format!("invalid event ID {id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if name.trim().is_empty() || event_ids.is_empty() {
            return Err("channel names and event IDs cannot be empty".into());
        }
        channels.push(Channel {
            name: name.trim().to_owned(),
            event_ids,
        });
        if channels
            .last()
            .is_some_and(|channel| channel.name.len() > 128)
        {
            return Err("event channel names must be at most 128 bytes".into());
        }
        if channels.len() > 32 {
            return Err("at most 32 event channels can be configured".into());
        }
    }
    if channels.is_empty() {
        return Err("at least one event channel must be configured".into());
    }
    Ok(channels)
}

fn validate_endpoint(endpoint: &str, has_identity: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|_| "SENTINEL_SERVER_URL must be an absolute URL".to_owned())?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "SENTINEL_SERVER_URL cannot contain credentials, a query, or a fragment".into(),
        );
    }
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("SENTINEL_SERVER_URL must use HTTPS".into());
    }
    if parsed.scheme() == "http"
        && !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
    {
        return Err("plain HTTP is allowed only for loopback development".into());
    }
    if parsed.scheme() == "https" && !has_identity {
        return Err("HTTPS telemetry requires a client certificate and key".into());
    }
    Ok(())
}

#[derive(Debug)]
pub struct Spool {
    connection: Connection,
    max_bytes: u64,
}

impl Spool {
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self, String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create spool directory: {error}"))?;
        }
        let connection =
            Connection::open(path).map_err(|error| format!("open SQLite spool: {error}"))?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| format!("enable spool WAL: {error}"))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| format!("set durable spool writes: {error}"))?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS outbox (
                event_id TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS bookmarks (
                channel TEXT PRIMARY KEY,
                xml TEXT NOT NULL
            );",
            )
            .map_err(|error| format!("initialize spool: {error}"))?;
        Ok(Self {
            connection,
            max_bytes,
        })
    }

    pub fn enqueue(&mut self, event: &Event) -> Result<bool, String> {
        self.enqueue_with_bookmark(event, None)
    }

    pub fn enqueue_with_bookmark(
        &mut self,
        event: &Event,
        bookmark: Option<(&str, &str)>,
    ) -> Result<bool, String> {
        event.validate()?;
        let payload = serde_json::to_vec(event).map_err(|error| error.to_string())?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| format!("begin spool transaction: {error}"))?;
        let duplicate: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE event_id = ?1)",
                [&event.id],
                |row| row.get(0),
            )
            .map_err(|error| format!("check event deduplication: {error}"))?;
        if !duplicate {
            let used: u64 = transaction
                .query_row(
                    "SELECT COALESCE(SUM(length(payload)), 0) FROM outbox",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| format!("measure spool usage: {error}"))?;
            if used.saturating_add(payload.len() as u64) > self.max_bytes {
                return Err("durable telemetry spool is full".into());
            }
            transaction
                .execute(
                    "INSERT INTO outbox(event_id, payload) VALUES (?1, ?2)",
                    params![event.id, payload],
                )
                .map_err(|error| format!("store event in outbox: {error}"))?;
        }
        if let Some((channel, xml)) = bookmark {
            transaction.execute("INSERT INTO bookmarks(channel, xml) VALUES (?1, ?2) ON CONFLICT(channel) DO UPDATE SET xml=excluded.xml", params![channel, xml])
                .map_err(|error| format!("store event bookmark: {error}"))?;
        }
        transaction
            .commit()
            .map_err(|error| format!("commit spool transaction: {error}"))?;
        Ok(!duplicate)
    }

    pub fn batch(&self, limit: usize) -> Result<Vec<(String, Vec<u8>)>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT event_id, payload FROM outbox ORDER BY rowid LIMIT ?1")
            .map_err(|error| format!("prepare outbox read: {error}"))?;
        let rows = statement
            .query_map([limit.min(UPLOAD_BATCH) as i64], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| format!("read outbox: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("decode outbox row: {error}"))
    }

    pub fn acknowledge(&mut self, event_id: &str) -> Result<(), String> {
        self.connection
            .execute("DELETE FROM outbox WHERE event_id = ?1", [event_id])
            .map_err(|error| format!("remove acknowledged event: {error}"))?;
        Ok(())
    }

    pub fn bookmark(&self, channel: &str) -> Result<Option<String>, String> {
        self.connection
            .query_row(
                "SELECT xml FROM bookmarks WHERE channel = ?1",
                [channel],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("read channel bookmark: {error}"))
    }

    pub fn queued_bytes(&self) -> Result<u64, String> {
        self.connection
            .query_row(
                "SELECT COALESCE(SUM(length(payload)), 0) FROM outbox",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("measure queued telemetry: {error}"))
    }

    pub fn save_bookmark(&mut self, channel: &str, xml: &str) -> Result<(), String> {
        self.connection.execute("INSERT INTO bookmarks(channel, xml) VALUES (?1, ?2) ON CONFLICT(channel) DO UPDATE SET xml=excluded.xml", params![channel, xml])
            .map_err(|error| format!("store event bookmark: {error}"))?;
        Ok(())
    }
}

#[cfg(windows)]
pub struct Agent {
    config: Config,
    spool: Arc<Mutex<Spool>>,
    client: Client,
}

#[cfg(windows)]
impl Agent {
    pub fn new(config: Config) -> Result<Self, String> {
        let _ = LOG_PATH.set(config.log_path.clone());
        let spool = Spool::open(&config.spool_path, config.spool_limit)?;
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(15))
            .https_only(config.endpoint.starts_with("https://"));
        if let (Some(certificate), Some(key)) = (&config.client_certificate, &config.client_key) {
            let mut identity = std::fs::read(certificate)
                .map_err(|error| format!("read client certificate: {error}"))?;
            identity.extend_from_slice(b"\n");
            identity
                .extend(std::fs::read(key).map_err(|error| format!("read client key: {error}"))?);
            builder = builder.identity(
                reqwest::Identity::from_pem(&identity)
                    .map_err(|error| format!("parse client identity: {error}"))?,
            );
        }
        let client = builder
            .build()
            .map_err(|error| format!("build HTTPS client: {error}"))?;
        Ok(Self {
            config,
            spool: Arc::new(Mutex::new(spool)),
            client,
        })
    }

    pub fn run(&self, stop: Arc<std::sync::atomic::AtomicBool>) -> Result<(), String> {
        #[cfg(not(windows))]
        {
            let _ = stop;
            return Err("native Windows Event Log collection is available only on Windows".into());
        }
        #[cfg(windows)]
        {
            let uploader = Uploader {
                endpoint: format!("{}/api/ingest", self.config.endpoint.trim_end_matches('/')),
                heartbeat_endpoint: format!(
                    "{}/api/heartbeat",
                    self.config.endpoint.trim_end_matches('/')
                ),
                heartbeat: AgentHeartbeat {
                    host_id: self.config.host_id.clone(),
                    hostname: self.config.hostname.clone(),
                    os: "Windows".into(),
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                    telemetry_sources: self
                        .config
                        .channels
                        .iter()
                        .map(|channel| channel.name.clone())
                        .collect(),
                    collection_capabilities: vec![
                        "windows_event_log".into(),
                        "sqlite_spool".into(),
                        "https_telemetry".into(),
                    ],
                },
                token: self.config.token.clone(),
                client: self.client.clone(),
                spool: self.spool.clone(),
                stop: stop.clone(),
            };
            let uploader_stop = stop.clone();
            let uploader_thread = thread::spawn(move || {
                let result = uploader.run();
                if result.is_err() {
                    uploader_stop.store(true, std::sync::atomic::Ordering::Release);
                }
                result
            });
            let collector_result =
                windows::collect(self.config.clone(), self.spool.clone(), stop.clone());
            stop.store(true, std::sync::atomic::Ordering::Release);
            let uploader_result = uploader_thread
                .join()
                .map_err(|_| "uploader thread panicked".to_owned())?;
            collector_result?;
            uploader_result
        }
    }
}

#[cfg(windows)]
struct Uploader {
    endpoint: String,
    heartbeat_endpoint: String,
    heartbeat: AgentHeartbeat,
    token: String,
    client: Client,
    spool: Arc<Mutex<Spool>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(windows)]
impl Uploader {
    fn run(self) -> Result<(), String> {
        let mut retry = Duration::from_secs(1);
        let mut next_heartbeat = std::time::Instant::now();
        while !self.stop.load(std::sync::atomic::Ordering::Acquire) {
            if std::time::Instant::now() >= next_heartbeat {
                match self
                    .client
                    .post(&self.heartbeat_endpoint)
                    .bearer_auth(&self.token)
                    .json(&self.heartbeat)
                    .send()
                {
                    Ok(response) if response.status().is_success() => {
                        log("info", "endpoint heartbeat accepted");
                        next_heartbeat = std::time::Instant::now() + Duration::from_secs(30);
                    }
                    Ok(response)
                        if response.status().is_server_error()
                            || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                    {
                        log(
                            "warn",
                            &format!("heartbeat deferred: HTTP {}", response.status()),
                        );
                        next_heartbeat = std::time::Instant::now() + Duration::from_secs(5);
                    }
                    Ok(response) => {
                        return Err(format!(
                            "heartbeat endpoint rejected the agent with HTTP {}",
                            response.status()
                        ));
                    }
                    Err(error) => {
                        log("warn", &format!("heartbeat deferred: {error}"));
                        next_heartbeat = std::time::Instant::now() + Duration::from_secs(5);
                    }
                }
            }
            let batch = self
                .spool
                .lock()
                .map_err(|_| "spool lock poisoned".to_owned())?
                .batch(UPLOAD_BATCH)?;
            if batch.is_empty() {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            let mut sent_any = false;
            let mut deferred = false;
            for (event_id, payload) in batch {
                if self.stop.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                let response = self
                    .client
                    .post(&self.endpoint)
                    .bearer_auth(&self.token)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(payload)
                    .send();
                match response {
                    Ok(response)
                        if response.status().is_success()
                            || response.status() == reqwest::StatusCode::CONFLICT =>
                    {
                        self.spool
                            .lock()
                            .map_err(|_| "spool lock poisoned".to_owned())?
                            .acknowledge(&event_id)?;
                        sent_any = true;
                    }
                    Ok(response)
                        if response.status().is_server_error()
                            || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                    {
                        log(
                            "warn",
                            &format!("telemetry upload deferred: HTTP {}", response.status()),
                        );
                        deferred = true;
                        break;
                    }
                    Ok(response) => {
                        return Err(format!(
                            "telemetry endpoint rejected the event with HTTP {}",
                            response.status()
                        ));
                    }
                    Err(error) => {
                        log("warn", &format!("telemetry upload deferred: {error}"));
                        deferred = true;
                        break;
                    }
                }
            }
            if deferred || !sent_any {
                thread::sleep(retry);
                retry = (retry * 2).min(Duration::from_secs(30));
            } else {
                retry = Duration::from_secs(1);
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize)]
struct AgentHeartbeat {
    host_id: String,
    hostname: String,
    os: String,
    agent_version: String,
    telemetry_sources: Vec<String>,
    collection_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEvent {
    pub provider: String,
    pub event_id: u16,
    pub record_id: u64,
    pub channel: String,
    pub computer: String,
    pub time: String,
    pub system_process_id: Option<u32>,
    pub user_sid: Option<String>,
    pub data: std::collections::BTreeMap<String, String>,
}

pub fn parse_windows_event(xml: &str) -> Result<RenderedEvent, String> {
    use quick_xml::{Reader, events::Event as XmlEvent};
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut event = RenderedEvent {
        provider: String::new(),
        event_id: 0,
        record_id: 0,
        channel: String::new(),
        computer: String::new(),
        time: String::new(),
        system_process_id: None,
        user_sid: None,
        data: Default::default(),
    };
    let mut data_name: Option<String> = None;
    let mut data_value = String::new();
    let mut text_element: Option<String> = None;
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("parse Windows event XML: {error}"))?
        {
            XmlEvent::Start(element) => {
                let name = String::from_utf8_lossy(element.local_name().as_ref()).to_string();
                text_element = Some(name.clone());
                match name.as_str() {
                    "Provider" => {
                        event.provider = attribute(&reader, &element, b"Name").unwrap_or_default()
                    }
                    "TimeCreated" => {
                        event.time = attribute(&reader, &element, b"SystemTime").unwrap_or_default()
                    }
                    "Execution" => {
                        event.system_process_id = attribute(&reader, &element, b"ProcessID")
                            .and_then(|value| parse_id(&value))
                    }
                    "Security" => event.user_sid = attribute(&reader, &element, b"UserID"),
                    "Data" => {
                        data_name = attribute(&reader, &element, b"Name");
                        data_value.clear();
                    }
                    _ => {}
                }
            }
            XmlEvent::Empty(element) => {
                let name = String::from_utf8_lossy(element.local_name().as_ref()).to_string();
                match name.as_str() {
                    "Provider" => {
                        event.provider = attribute(&reader, &element, b"Name").unwrap_or_default()
                    }
                    "TimeCreated" => {
                        event.time = attribute(&reader, &element, b"SystemTime").unwrap_or_default()
                    }
                    "Execution" => {
                        event.system_process_id = attribute(&reader, &element, b"ProcessID")
                            .and_then(|value| parse_id(&value))
                    }
                    "Security" => event.user_sid = attribute(&reader, &element, b"UserID"),
                    _ => {}
                }
            }
            XmlEvent::Text(text) => {
                let value = text
                    .xml_content()
                    .map_err(|error| format!("decode event XML text: {error}"))?
                    .into_owned();
                if data_name.is_some() {
                    data_value.push_str(&value);
                } else {
                    match text_element.as_deref() {
                        Some("EventID") => {
                            event.event_id = value
                                .trim()
                                .parse()
                                .map_err(|_| "invalid Windows EventID".to_owned())?
                        }
                        Some("EventRecordID") => {
                            event.record_id = value
                                .trim()
                                .parse()
                                .map_err(|_| "invalid EventRecordID".to_owned())?
                        }
                        Some("Channel") => event.channel = value.trim().to_owned(),
                        Some("Computer") => event.computer = value.trim().to_owned(),
                        _ => {}
                    }
                }
            }
            XmlEvent::GeneralRef(reference) if data_name.is_some() => {
                if let Some(character) = reference
                    .resolve_char_ref()
                    .map_err(|error| format!("decode XML character reference: {error}"))?
                {
                    data_value.push(character);
                } else {
                    let entity = reference
                        .decode()
                        .map_err(|error| format!("decode XML entity name: {error}"))?;
                    let character = match entity.as_ref() {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "apos" => '\'',
                        "quot" => '"',
                        _ => return Err("unsupported named XML entity in Windows event".into()),
                    };
                    data_value.push(character);
                }
            }
            XmlEvent::End(element) => {
                if element.local_name().as_ref() == b"Data" {
                    if let Some(name) = data_name.take() {
                        event.data.insert(name, std::mem::take(&mut data_value));
                    }
                }
                text_element = None;
            }
            XmlEvent::Eof => break,
            _ => {}
        }
    }
    if event.provider.is_empty()
        || event.event_id == 0
        || event.record_id == 0
        || event.time.is_empty()
    {
        return Err("Windows event is missing provider, event ID, record ID, or timestamp".into());
    }
    Ok(event)
}

fn attribute(
    reader: &quick_xml::Reader<&[u8]>,
    element: &quick_xml::events::BytesStart<'_>,
    name: &[u8],
) -> Option<String> {
    element
        .attributes()
        .flatten()
        .find(|attribute| attribute.key.local_name().as_ref() == name)
        .and_then(|attribute| {
            attribute
                .decode_and_unescape_value(reader.decoder())
                .ok()
                .map(|value| value.into_owned())
        })
}

pub fn normalize_windows_event(
    raw: &RenderedEvent,
    host_id: &str,
    hostname: &str,
) -> Option<Event> {
    use std::collections::BTreeMap;
    let sysmon = raw.provider.to_ascii_lowercase().contains("sysmon");
    let mut data = raw.data.clone();
    let (category, event_type, technique) = match (sysmon, raw.event_id) {
        (true, 1) | (false, 4688) => ("process", "process_start", None),
        (true, 3) => ("network", "network_connection", None),
        (true, 11) => ("file", "file_created", None),
        (true, 12..=14) => ("registry", "registry_change", None),
        (false, 4625) => ("authentication", "authentication_failure", Some("T1110")),
        _ => return None,
    };
    if sysmon && (12..=14).contains(&raw.event_id) {
        let target = data
            .get("TargetObject")
            .cloned()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if target.contains("\\currentversion\\run")
            || target.contains("\\winlogon\\")
            || target.contains("\\services\\")
        {
            data.insert("event_kind".into(), "startup_change".into());
        }
    }
    let event_type = if data
        .get("event_kind")
        .is_some_and(|value| value == "startup_change")
    {
        "startup_change"
    } else {
        event_type
    };
    let technique = if event_type == "startup_change" {
        Some("T1547")
    } else {
        technique
    };
    let time = DateTime::parse_from_rfc3339(&raw.time)
        .ok()?
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Nanos, true);
    let image = data
        .remove("Image")
        .or_else(|| data.remove("NewProcessName"));
    let command_line = data
        .remove("CommandLine")
        .map(|value| truncate_utf8(&redact_sensitive_command_line(&value), 4096));
    let process_id = data
        .remove("ProcessId")
        .or_else(|| data.remove("NewProcessId"))
        .and_then(|value| parse_id(&value));
    let parent_process_id = data
        .remove("ParentProcessId")
        .or_else(|| data.remove("CreatorProcessId"))
        .and_then(|value| parse_id(&value));
    let user = data
        .remove("User")
        .or_else(|| data.remove("TargetUserName"))
        .or_else(|| data.remove("SubjectUserName"))
        .or_else(|| raw.user_sid.clone());
    let destination_ip = data.remove("DestinationIp");
    let destination_port = data.remove("DestinationPort");
    let destination = destination_ip.map(|ip| match destination_port.as_deref() {
        Some(port) if ip.contains(':') => format!("[{ip}]:{port}"),
        Some(port) => format!("{ip}:{port}"),
        None => ip,
    });
    let sha256 = data.remove("Hashes").and_then(|hashes| {
        hashes.split(';').find_map(|part| {
            let (algorithm, value) = part.split_once('=')?;
            algorithm
                .eq_ignore_ascii_case("SHA256")
                .then(|| value.to_owned())
        })
    });
    let mut fields = BTreeMap::new();
    fields.insert("channel".into(), raw.channel.clone());
    fields.insert("provider".into(), raw.provider.clone());
    fields.insert("windows_event_id".into(), raw.event_id.to_string());
    fields.insert("record_id".into(), raw.record_id.to_string());
    if let Some(port) = destination_port {
        fields.insert("destination_port".into(), port);
    }
    if let Some(protocol) = data.remove("Protocol") {
        fields.insert("protocol".into(), protocol);
    }
    if let Some(target) = data
        .remove("TargetFilename")
        .or_else(|| data.remove("TargetObject"))
    {
        fields.insert("target_path".into(), target);
    }
    if let Some(hash) = sha256 {
        fields.insert("sha256".into(), hash);
    }
    for (key, value) in data.into_iter().take(32) {
        let field_name = format!("source_{key}");
        let field_value = if sensitive_key(&field_name) {
            "[REDACTED]".to_owned()
        } else {
            value.chars().take(1024).collect()
        };
        fields.insert(field_name, field_value);
    }
    let identity = format!(
        "{host_id}\0{}\0{}\0{}\0{}",
        raw.channel, raw.provider, raw.record_id, raw.time
    );
    let digest = Sha256::digest(identity.as_bytes());
    let id = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Some(Event {
        id: format!("win:{id}"),
        schema_version: "1.0".into(),
        time,
        host_id: host_id.to_owned(),
        hostname: hostname.to_owned(),
        source: "windows-eventlog".into(),
        category: category.into(),
        event_type: event_type.into(),
        process_id,
        parent_process_id,
        image,
        command_line,
        user,
        destination,
        technique: technique.map(str::to_owned),
        fields,
    })
}

fn redact_sensitive_command_line(value: &str) -> String {
    let mut spans = Vec::new();
    let mut start = None;
    let mut quoted = false;
    let mut previous = '\0';
    for (index, character) in value.char_indices() {
        if start.is_none() && !character.is_whitespace() {
            start = Some(index);
        }
        if character == '"' && previous != '\\' {
            quoted = !quoted;
        }
        if character.is_whitespace() && !quoted {
            if let Some(token_start) = start.take() {
                spans.push((token_start, index));
            }
        }
        previous = character;
    }
    if let Some(token_start) = start {
        spans.push((token_start, value.len()));
    }

    let mut output = String::with_capacity(value.len());
    let mut position = 0;
    let mut redact_next = false;
    for (token_start, token_end) in spans {
        output.push_str(&value[position..token_start]);
        let token = &value[token_start..token_end];
        if redact_next {
            output.push_str("[REDACTED]");
            redact_next = false;
        } else {
            if let Some(delimiter) = token.find(['=', ':']) {
                if sensitive_key(&token[..delimiter]) {
                    output.push_str(&token[..=delimiter]);
                    let suffix = (token.starts_with('"') && token.ends_with('"'))
                        || (token.starts_with('\'') && token.ends_with('\''));
                    output.push_str("[REDACTED]");
                    if suffix {
                        output.push(token.chars().last().unwrap_or('"'));
                    }
                } else {
                    output.push_str(token);
                }
            } else {
                let argument = token
                    .trim_matches(['"', '\''])
                    .trim_start_matches(['-', '/', '\\']);
                output.push_str(token);
                redact_next = sensitive_key(argument);
            }
        }
        position = token_end;
    }
    output.push_str(&value[position..]);
    output
}

fn sensitive_key(value: &str) -> bool {
    let key = value
        .trim_matches(['"', '\''])
        .trim_start_matches(['-', '/', '\\'])
        .to_ascii_lowercase()
        .replace('_', "-");
    [
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "api-key",
        "apikey",
        "credential",
        "authorization",
    ]
    .iter()
    .any(|name| key == *name || key.ends_with(&format!("-{name}")))
        || key == "apikey"
}

fn parse_id(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str) -> Event {
        Event {
            id: id.into(),
            schema_version: "1.0".into(),
            time: "2026-10-25T10:00:00Z".into(),
            host_id: "host-1".into(),
            hostname: "HOST-1".into(),
            source: "test".into(),
            category: "process".into(),
            event_type: "process_start".into(),
            process_id: Some(1),
            parent_process_id: Some(2),
            image: Some("test.exe".into()),
            command_line: None,
            user: None,
            destination: None,
            technique: None,
            fields: Default::default(),
        }
    }

    #[test]
    fn spool_is_durable_deduplicated_bounded_and_bookmarked() {
        let directory =
            std::env::temp_dir().join(format!("sentinel-agent-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("spool.sqlite");
        {
            let mut spool = Spool::open(&path, 2048).unwrap();
            assert!(
                spool
                    .enqueue_with_bookmark(&event("e1"), Some(("Security", "<Bookmark/>")))
                    .unwrap()
            );
            assert!(!spool.enqueue(&event("e1")).unwrap());
            assert_eq!(spool.batch(32).unwrap().len(), 1);
            assert_eq!(
                spool.bookmark("Security").unwrap().as_deref(),
                Some("<Bookmark/>")
            );
            assert!(spool.enqueue(&event("e2")).unwrap());
            assert!(spool.queued_bytes().unwrap() > 0);
            spool.acknowledge("e1").unwrap();
        }
        let spool = Spool::open(&path, 2048).unwrap();
        assert_eq!(spool.batch(32).unwrap().len(), 1);
        assert_eq!(
            spool.bookmark("Security").unwrap().as_deref(),
            Some("<Bookmark/>")
        );
        drop(spool);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn event_xml_normalizes_only_supported_windows_events() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-25T10:00:00.1234567Z"/><EventRecordID>42</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>HOST-1</Computer><Execution ProcessID="123"/><Security UserID="S-1-5-18"/></System><EventData><Data Name="ProcessId">0x2A</Data><Data Name="ParentProcessId">12</Data><Data Name="Image">C:\Windows\test.exe</Data><Data Name="CommandLine">test.exe &amp; safe</Data><Data Name="Hashes">SHA256=abc123</Data><Data Name="ApiKey">fixture-secret</Data></EventData></Event>"#;
        let raw = parse_windows_event(xml).unwrap();
        assert_eq!(raw.record_id, 42);
        let normalized = normalize_windows_event(&raw, "host-id", "HOST-1").unwrap();
        assert_eq!(normalized.event_type, "process_start");
        assert_eq!(normalized.process_id, Some(42));
        assert_eq!(normalized.parent_process_id, Some(12));
        assert_eq!(normalized.command_line.as_deref(), Some("test.exe & safe"));
        assert_eq!(
            normalized.fields.get("sha256").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            normalized.fields.get("source_ApiKey").map(String::as_str),
            Some("[REDACTED]")
        );
        assert!(
            normalize_windows_event(
                &RenderedEvent {
                    event_id: 999,
                    ..raw
                },
                "host-id",
                "HOST-1"
            )
            .is_none()
        );
    }

    #[test]
    fn remote_agent_endpoints_require_https_and_certificate_identity() {
        assert!(validate_endpoint("http://example.com:8080", false).is_err());
        assert!(validate_endpoint("https://sentinel.example.com", false).is_err());
        assert!(validate_endpoint("https://sentinel.example.com", true).is_ok());
        assert!(validate_endpoint("https://user:secret@sentinel.example.com", true).is_err());
        assert!(validate_endpoint("https://sentinel.example.com/path?token=secret", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:8080", false).is_ok());
    }

    #[test]
    fn command_line_is_bounded_without_splitting_utf8() {
        let mut raw = RenderedEvent {
            provider: "Microsoft-Windows-Sysmon".into(),
            event_id: 1,
            record_id: 7,
            channel: "Sysmon".into(),
            computer: "HOST-1".into(),
            time: "2026-10-25T10:00:00Z".into(),
            system_process_id: None,
            user_sid: None,
            data: Default::default(),
        };
        raw.data
            .insert("CommandLine".into(), format!("{}é", "a".repeat(4095)));
        let normalized = normalize_windows_event(&raw, "host-id", "HOST-1").unwrap();
        assert_eq!(normalized.command_line.as_deref().unwrap().len(), 4095);
    }

    #[test]
    fn command_line_secrets_are_redacted_before_spooling() {
        let command = r#"tool.exe --profile "approved deployment" --password="very secret value" --access_token abc123 --api-key:xyz"#;
        let redacted = redact_sensitive_command_line(command);
        assert_eq!(
            redacted,
            r#"tool.exe --profile "approved deployment" --password=[REDACTED] --access_token [REDACTED] --api-key:[REDACTED]"#
        );
        for secret in ["very secret value", "abc123", "xyz"] {
            assert!(!redacted.contains(secret));
        }
    }

    #[test]
    fn agent_event_validation_matches_backend_identity_bounds() {
        let mut value = event("bounded");
        value.host_id = "h".repeat(129);
        assert!(value.validate().is_err());
        value.host_id = "host-1".into();
        value.command_line = Some("x".repeat(4097));
        assert!(value.validate().is_err());
        value.command_line = Some("valid.exe".into());
        assert!(value.validate().is_ok());
    }
}
