use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{ACCEPT, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::config::{ServerConfig, TransportType};

use super::{DownstreamClient, DownstreamError, ToolCallResult, ToolDescriptor};

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Debug, Error)]
pub enum BuildDownstreamError {
    #[error("invalid stdio config for server {server}: {message}")]
    InvalidStdio { server: String, message: String },
    #[error("invalid http config for server {server}: {message}")]
    InvalidHttp { server: String, message: String },
    #[error("failed to spawn stdio server {server}: {source}")]
    Spawn {
        server: String,
        source: std::io::Error,
    },
    #[error("failed to initialize downstream server {server}: {source}")]
    Initialize {
        server: String,
        source: DownstreamError,
    },
}

pub async fn build_downstream_client(
    server_name: &str,
    config: &ServerConfig,
) -> Result<Arc<dyn DownstreamClient>, BuildDownstreamError> {
    match config.transport {
        TransportType::Stdio => {
            let command =
                config
                    .command
                    .as_deref()
                    .ok_or_else(|| BuildDownstreamError::InvalidStdio {
                        server: server_name.to_owned(),
                        message: "missing command".to_owned(),
                    })?;

            let mut cmd = Command::new(command);
            cmd.args(&config.args)
                .envs(&config.env)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());

            let mut child = cmd.spawn().map_err(|source| BuildDownstreamError::Spawn {
                server: server_name.to_owned(),
                source,
            })?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| BuildDownstreamError::InvalidStdio {
                    server: server_name.to_owned(),
                    message: "failed to capture child stdin".to_owned(),
                })?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| BuildDownstreamError::InvalidStdio {
                    server: server_name.to_owned(),
                    message: "failed to capture child stdout".to_owned(),
                })?;

            let client = Arc::new(StdioDownstreamClient {
                io: Mutex::new(StdioIo {
                    stdin,
                    lines: BufReader::new(stdout).lines(),
                    next_id: 1,
                }),
                initialized: Mutex::new(false),
            });

            client.ensure_initialized().await.map_err(|source| {
                BuildDownstreamError::Initialize {
                    server: server_name.to_owned(),
                    source,
                }
            })?;

            Ok(client)
        }
        TransportType::StreamableHttp => {
            let url = config
                .url
                .clone()
                .ok_or_else(|| BuildDownstreamError::InvalidHttp {
                    server: server_name.to_owned(),
                    message: "missing url".to_owned(),
                })?;

            let mut headers = HeaderMap::new();
            for (key, value) in &config.headers {
                let name = HeaderName::from_bytes(key.as_bytes()).map_err(|_| {
                    BuildDownstreamError::InvalidHttp {
                        server: server_name.to_owned(),
                        message: format!("invalid header name: {key}"),
                    }
                })?;
                let val = HeaderValue::from_str(value).map_err(|_| {
                    BuildDownstreamError::InvalidHttp {
                        server: server_name.to_owned(),
                        message: format!("invalid header value for: {key}"),
                    }
                })?;
                headers.insert(name, val);
            }

            let timeout_ms = config.timeout_ms.unwrap_or(30_000);
            let client = Arc::new(HttpDownstreamClient {
                endpoint: url,
                client: reqwest::Client::builder()
                    .timeout(std::time::Duration::from_millis(timeout_ms))
                    .default_headers(headers)
                    .build()
                    .map_err(|err| BuildDownstreamError::InvalidHttp {
                        server: server_name.to_owned(),
                        message: format!("failed to build reqwest client: {err}"),
                    })?,
                initialized: Mutex::new(false),
                session_id: Mutex::new(None),
                next_request_id: Mutex::new(1),
                last_event_id: Mutex::new(None),
            });

            client.ensure_initialized().await.map_err(|source| {
                BuildDownstreamError::Initialize {
                    server: server_name.to_owned(),
                    source,
                }
            })?;

            Ok(client)
        }
    }
}

struct StdioIo {
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

struct StdioDownstreamClient {
    io: Mutex<StdioIo>,
    initialized: Mutex<bool>,
}

impl StdioDownstreamClient {
    async fn ensure_initialized(&self) -> Result<(), DownstreamError> {
        let mut initialized = self.initialized.lock().await;
        if *initialized {
            return Ok(());
        }

        let _ = self
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "moco",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
            )
            .await?;
        self.notify("notifications/initialized", None).await?;

        *initialized = true;
        Ok(())
    }

    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, DownstreamError> {
        let mut io = self.io.lock().await;
        let id = io.next_id;
        io.next_id = io.next_id.saturating_add(1);

        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params.unwrap_or_else(|| json!({}))
        });
        let line = serde_json::to_string(&payload)
            .map_err(|err| DownstreamError::Call(format!("serialize request failed: {err}")))?;

        io.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|err| DownstreamError::Unavailable(format!("write failed: {err}")))?;
        io.stdin
            .write_all(b"\n")
            .await
            .map_err(|err| DownstreamError::Unavailable(format!("write newline failed: {err}")))?;
        io.stdin
            .flush()
            .await
            .map_err(|err| DownstreamError::Unavailable(format!("flush failed: {err}")))?;

        loop {
            let Some(line) = io
                .lines
                .next_line()
                .await
                .map_err(|err| DownstreamError::Unavailable(format!("read failed: {err}")))?
            else {
                return Err(DownstreamError::Unavailable(
                    "stdio stream closed by downstream".to_owned(),
                ));
            };

            let parsed: Value = match serde_json::from_str(&line) {
                Ok(val) => val,
                Err(_) => {
                    continue;
                }
            };

            if parsed.get("id") != Some(&json!(id)) {
                continue;
            }

            if let Some(result) = parsed.get("result") {
                return Ok(result.clone());
            }
            if let Some(error) = parsed.get("error") {
                return Err(DownstreamError::Call(format!(
                    "downstream returned json-rpc error: {error}"
                )));
            }
        }
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), DownstreamError> {
        let mut io = self.io.lock().await;
        let mut payload = json!({
            "jsonrpc": "2.0",
            "method": method,
        });
        if let Some(params) = params {
            payload["params"] = params;
        }
        let line = serde_json::to_string(&payload)
            .map_err(|err| DownstreamError::Call(format!("serialize notify failed: {err}")))?;
        io.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|err| DownstreamError::Unavailable(format!("write failed: {err}")))?;
        io.stdin
            .write_all(b"\n")
            .await
            .map_err(|err| DownstreamError::Unavailable(format!("write newline failed: {err}")))?;
        io.stdin
            .flush()
            .await
            .map_err(|err| DownstreamError::Unavailable(format!("flush failed: {err}")))?;
        Ok(())
    }
}

#[async_trait]
impl DownstreamClient for StdioDownstreamClient {
    async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, DownstreamError> {
        self.ensure_initialized().await?;
        let result = self.request("tools/list", Some(json!({}))).await?;
        parse_tools_list_result(&result)
    }

    async fn call_tool(
        &self,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<ToolCallResult, DownstreamError> {
        self.ensure_initialized().await?;
        let result = self
            .request(
                "tools/call",
                Some(json!({
                    "name": tool_name,
                    "arguments": arguments
                })),
            )
            .await?;
        Ok(parse_tool_call_result(&result))
    }
}

struct HttpDownstreamClient {
    endpoint: String,
    client: reqwest::Client,
    initialized: Mutex<bool>,
    session_id: Mutex<Option<String>>,
    next_request_id: Mutex<u64>,
    last_event_id: Mutex<Option<String>>,
}

impl HttpDownstreamClient {
    async fn ensure_initialized(&self) -> Result<(), DownstreamError> {
        let mut initialized = self.initialized.lock().await;
        if *initialized {
            return Ok(());
        }

        let _ = self
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "moco",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
            )
            .await?;
        self.notify("notifications/initialized", None).await?;

        *initialized = true;
        Ok(())
    }

    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, DownstreamError> {
        let mut next_id = self.next_request_id.lock().await;
        let request_id = *next_id;
        *next_id = next_id.saturating_add(1);
        drop(next_id);

        let body = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params.unwrap_or_else(|| json!({}))
        });

        let response = self.post(body).await?;

        if !response.status().is_success() {
            return Err(DownstreamError::Call(format!(
                "unexpected status: {}",
                response.status()
            )));
        }

        if let Some(session) = response
            .headers()
            .get("MCP-Session-Id")
            .and_then(|h| h.to_str().ok())
        {
            *self.session_id.lock().await = Some(session.to_owned());
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if content_type.contains("text/event-stream") {
            let sse = parse_jsonrpc_from_sse(response, request_id).await?;
            if let Some(last_event_id) = sse.last_event_id {
                *self.last_event_id.lock().await = Some(last_event_id);
            }
            return Ok(sse.payload);
        }

        let payload = response
            .json::<Value>()
            .await
            .map_err(|err| DownstreamError::Call(format!("invalid json response: {err}")))?;

        if let Some(result) = payload.get("result") {
            Ok(result.clone())
        } else if let Some(error) = payload.get("error") {
            Err(DownstreamError::Call(format!(
                "downstream returned json-rpc error: {error}"
            )))
        } else {
            Err(DownstreamError::Call(
                "json-rpc response missing result/error".to_owned(),
            ))
        }
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), DownstreamError> {
        let mut body = json!({
            "jsonrpc": "2.0",
            "method": method,
        });
        if let Some(params) = params {
            body["params"] = params;
        }
        let response = self.post(body).await?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::ACCEPTED {
            Ok(())
        } else {
            Err(DownstreamError::Call(format!(
                "notify failed with status: {}",
                response.status()
            )))
        }
    }

    async fn post(&self, body: Value) -> Result<reqwest::Response, DownstreamError> {
        let mut req = self.client.post(&self.endpoint);
        req = req.header(ACCEPT, "application/json, text/event-stream");
        req = req.header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION);

        if let Some(session) = self.session_id.lock().await.clone() {
            req = req.header("MCP-Session-Id", session);
        }
        if let Some(last_event_id) = self.last_event_id.lock().await.clone() {
            req = req.header("Last-Event-ID", last_event_id);
        }

        req.json(&body)
            .send()
            .await
            .map_err(|err| DownstreamError::Unavailable(format!("http request failed: {err}")))
    }
}

struct SseResponse {
    payload: Value,
    last_event_id: Option<String>,
}

#[derive(Default)]
struct SseEventBuffer {
    data: Vec<String>,
    event_id: Option<String>,
}

async fn parse_jsonrpc_from_sse(
    mut response: reqwest::Response,
    expected_request_id: u64,
) -> Result<SseResponse, DownstreamError> {
    let mut buffer = String::new();
    let mut event = SseEventBuffer::default();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| DownstreamError::Unavailable(format!("failed to read sse chunk: {err}")))?
    {
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(line_end) = buffer.find('\n') {
            let mut line = buffer[..line_end].to_owned();
            if line.ends_with('\r') {
                line.pop();
            }
            buffer.drain(..=line_end);

            if let Some(outcome) = process_sse_line(&line, &mut event, expected_request_id)? {
                return outcome;
            }
        }
    }

    if !buffer.is_empty() {
        if let Some(outcome) = process_sse_line(&buffer, &mut event, expected_request_id)? {
            return outcome;
        }
    }

    if let Some(outcome) = finalize_sse_event(&mut event, expected_request_id)? {
        return outcome;
    }

    Err(DownstreamError::Call(
        "sse stream ended before matching json-rpc response".to_owned(),
    ))
}

fn process_sse_line(
    line: &str,
    event: &mut SseEventBuffer,
    expected_request_id: u64,
) -> Result<Option<Result<SseResponse, DownstreamError>>, DownstreamError> {
    if line.is_empty() {
        return finalize_sse_event(event, expected_request_id);
    }

    if line.starts_with(':') {
        return Ok(None);
    }

    if let Some(event_id) = line.strip_prefix("id:") {
        let event_id = event_id.strip_prefix(' ').unwrap_or(event_id);
        event.event_id = Some(event_id.to_owned());
        return Ok(None);
    }

    if let Some(data) = line.strip_prefix("data:") {
        let data = data.strip_prefix(' ').unwrap_or(data);
        event.data.push(data.to_owned());
    }

    Ok(None)
}

fn finalize_sse_event(
    event: &mut SseEventBuffer,
    expected_request_id: u64,
) -> Result<Option<Result<SseResponse, DownstreamError>>, DownstreamError> {
    if event.data.is_empty() {
        return Ok(None);
    }

    let payload = event.data.join("\n");
    event.data.clear();
    let event_id = event.event_id.take();

    let parsed: Value = match serde_json::from_str(&payload) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    if parsed.get("id") != Some(&json!(expected_request_id)) {
        return Ok(None);
    }

    if let Some(result) = parsed.get("result") {
        return Ok(Some(Ok(SseResponse {
            payload: result.clone(),
            last_event_id: event_id,
        })));
    }
    if let Some(error) = parsed.get("error") {
        return Ok(Some(Err(DownstreamError::Call(format!(
            "downstream returned json-rpc error: {error}"
        )))));
    }

    Err(DownstreamError::Call(
        "sse json-rpc payload missing result/error".to_owned(),
    ))
}

#[async_trait]
impl DownstreamClient for HttpDownstreamClient {
    async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, DownstreamError> {
        self.ensure_initialized().await?;
        let result = self.request("tools/list", Some(json!({}))).await?;
        parse_tools_list_result(&result)
    }

    async fn call_tool(
        &self,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<ToolCallResult, DownstreamError> {
        self.ensure_initialized().await?;
        let result = self
            .request(
                "tools/call",
                Some(json!({
                    "name": tool_name,
                    "arguments": arguments
                })),
            )
            .await?;
        Ok(parse_tool_call_result(&result))
    }
}

fn parse_tools_list_result(result: &Value) -> Result<Vec<ToolDescriptor>, DownstreamError> {
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| DownstreamError::Call("tools/list result missing tools array".to_owned()))?;

    let mut out = Vec::with_capacity(tools.len());
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| DownstreamError::Call("tool entry missing name".to_owned()))?
            .to_owned();

        let description = tool
            .get("description")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let input_schema = tool
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| json!({ "type": "object" }));

        out.push(ToolDescriptor {
            name,
            description,
            input_schema,
        });
    }
    Ok(out)
}

fn parse_tool_call_result(result: &Value) -> ToolCallResult {
    ToolCallResult {
        content: result
            .get("content")
            .cloned()
            .unwrap_or_else(|| json!([{"type":"text","text":""}])),
        is_error: result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn parse_tools_list_ok() {
        let payload = json!({
            "tools": [
                { "name": "a", "description": "d", "inputSchema": {"type":"object"} }
            ]
        });
        let tools = parse_tools_list_result(&payload).expect("parse failed");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "a");
    }

    #[test]
    fn parse_call_result_defaults() {
        let payload = json!({});
        let result = parse_tool_call_result(&payload);
        assert!(!result.is_error);
        assert!(result.content.is_array());
    }

    #[tokio::test]
    async fn build_http_client_rejects_missing_url() {
        let cfg = ServerConfig {
            transport: TransportType::StreamableHttp,
            command: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            url: None,
            headers: BTreeMap::new(),
            timeout_ms: Some(1000),
        };
        let err = match build_downstream_client("test", &cfg).await {
            Ok(_) => panic!("expected error"),
            Err(err) => err,
        };
        assert!(matches!(err, BuildDownstreamError::InvalidHttp { .. }));
    }

    #[test]
    fn finalize_sse_event_matches_expected_id() {
        let mut event = SseEventBuffer {
            data: vec!["{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}".to_owned()],
            event_id: Some("evt-7".to_owned()),
        };

        let outcome = finalize_sse_event(&mut event, 7)
            .expect("finalize should succeed")
            .expect("expected matching event")
            .expect("result should be ok");

        assert_eq!(outcome.payload, json!({"ok": true}));
        assert_eq!(outcome.last_event_id.as_deref(), Some("evt-7"));
    }
}
