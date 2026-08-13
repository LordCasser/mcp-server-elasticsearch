// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

mod base_tools;

use crate::servers::IncludeExclude;
use crate::utils::none_if_empty_string;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use elasticsearch::Elasticsearch;
use elasticsearch::auth::Credentials;
use elasticsearch::cert::CertificateValidation;
use elasticsearch::http::Url;
use elasticsearch::http::headers::{HeaderValue, USER_AGENT};
use elasticsearch::http::response::Response;
use elasticsearch::http::transport::{SingleNodeConnectionPool, TransportBuilder};
use http::request::Parts;
use http::header;
use indexmap::IndexMap;
use rmcp::RoleServer;
use rmcp::model::ToolAnnotations;
use rmcp::service::RequestContext;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_bool_from_anything;
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct ElasticsearchMcpConfig {
    /// Cluster URL
    pub url: String,

    /// API key
    #[serde(default, deserialize_with = "none_if_empty_string")]
    pub api_key: Option<String>,

    /// Username
    #[serde(default, deserialize_with = "none_if_empty_string")]
    pub username: Option<String>,

    /// Password
    #[serde(default, deserialize_with = "none_if_empty_string")]
    pub password: Option<String>,

    /// Should we skip SSL certificate verification?
    #[serde(default, deserialize_with = "deserialize_bool_from_anything")]
    pub ssl_skip_verify: bool,

    /// Search templates to expose as tools or resources
    #[serde(default)]
    pub tools: Tools,

    /// Prompts
    #[serde(default)]
    pub prompts: Vec<String>,
    // TODO: search as resources?
}

// A wrapper around an ES client that provides a client instance configured
/// for a given request context (i.e. auth credentials).
///
/// The 7.x client cannot clone a transport with different credentials, so this
/// provider keeps the configuration snapshot and rebuilds a client on demand.
#[derive(Clone)]
pub struct EsClientProvider {
    url: Url,
    base_credentials: Option<Credentials>,
    ssl_skip_verify: bool,
    user_agent: String,
}

impl EsClientProvider {
    pub fn new(
        url: Url,
        base_credentials: Option<Credentials>,
        ssl_skip_verify: bool,
        user_agent: String,
    ) -> Self {
        EsClientProvider {
            url,
            base_credentials,
            ssl_skip_verify,
            user_agent,
        }
    }

    /// Build a client from the provider snapshot, optionally overriding the
    /// base credentials with request-specific ones.
    fn build_client(&self, credentials: Option<Credentials>) -> Result<Elasticsearch, rmcp::Error> {
        let pool = SingleNodeConnectionPool::new(self.url.clone());
        let mut transport = TransportBuilder::new(pool);
        if let Some(creds) = credentials {
            transport = transport.auth(creds);
        }
        if self.ssl_skip_verify {
            transport = transport.cert_validation(CertificateValidation::None);
        }
        transport = transport.header(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent).map_err(internal_error)?,
        );
        let transport = transport.build().map_err(internal_error)?;
        Ok(Elasticsearch::new(transport))
    }

    /// If the incoming request is a http request and has an `Authorization` header, use it
    /// to authenticate to the remote ES instance.
    pub fn get(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<Cow<'_, Elasticsearch>, rmcp::Error> {
        let Some(mut auth) = context
            .extensions
            .get::<Parts>()
            .and_then(|p| p.headers.get(header::AUTHORIZATION))
            .and_then(|h| h.to_str().ok())
        else {
            // No auth
            return self.build_client(self.base_credentials.clone()).map(Cow::Owned);
        };

        // MCP inspector insists on sending a bearer token and prepends "Bearer" to the value provided
        if auth.starts_with("Bearer ApiKey ") || auth.starts_with("Bearer Basic ") {
            auth = auth.trim_start_matches("Bearer ");
        }

        let credentials = credentials_from_authorization_header(auth)?;
        self.build_client(Some(credentials)).map(Cow::Owned)
    }
}

/// Parse an `Authorization` header value into client credentials.
///
/// Supported schemes: `ApiKey <base64(id:key)>`, `Basic <base64(username:password)>`
/// and `Bearer <token>`. The 7.x client re-encodes the decoded credentials into a
/// header that is byte-equivalent to the original value (for valid input).
fn credentials_from_authorization_header(auth: &str) -> Result<Credentials, rmcp::Error> {
    let Some((scheme, value)) = auth.split_once(' ') else {
        return Err(rmcp::Error::internal_error(
            "Invalid Authorization header: expected '<scheme> <credentials>'",
            None,
        ));
    };

    match scheme {
        "ApiKey" => {
            let (id, key) = decode_pair(value, "API key").map_err(anyhow_to_internal)?;
            Ok(Credentials::ApiKey(id, key))
        }
        "Basic" => {
            let (username, password) = decode_pair(value, "Basic credentials").map_err(anyhow_to_internal)?;
            Ok(Credentials::Basic(username, password))
        }
        "Bearer" => Ok(Credentials::Bearer(value.to_string())),
        _ => Err(rmcp::Error::internal_error(
            format!("Unsupported authorization scheme '{scheme}'"),
            None,
        )),
    }
}

/// Map an anyhow error to an internal error of the MCP server.
fn anyhow_to_internal(e: anyhow::Error) -> rmcp::Error {
    rmcp::Error::internal_error(e.to_string(), None)
}

/// Decode `base64(first:second)` into its two parts.
fn decode_pair(encoded: &str, description: &str) -> anyhow::Result<(String, String)> {
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|e| anyhow::Error::msg(format!("Invalid base64 for {description}: {e}")))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|e| anyhow::Error::msg(format!("{description} is not valid UTF-8: {e}")))?;
    let Some((first, second)) = decoded.split_once(':') else {
        return Err(anyhow::Error::msg(format!(
            "{description} must be the base64 encoding of 'first:second'"
        )));
    };
    Ok((first.to_string(), second.to_string()))
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tools {
    #[serde(flatten)]
    pub incl_excl: Option<IncludeExclude>,
    pub custom: HashMap<String, CustomTool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CustomTool {
    SearchTemplate(SearchTemplateTool),
}

impl CustomTool {
    pub fn base(&self) -> &ToolBase {
        match self {
            CustomTool::SearchTemplate(search_template) => &search_template.base,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolBase {
    pub description: String,
    pub parameters: IndexMap<String, schemars::schema::SchemaObject>,
    pub annotations: Option<ToolAnnotations>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchTemplateTool {
    #[serde(flatten)]
    base: ToolBase,
    #[serde(flatten)]
    template: SearchTemplate,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchTemplate {
    TemplateId(String),
    Template(serde_json::Value), // or constrain to an object?
}

#[derive(Clone)]
pub struct ElasticsearchMcp {}

impl ElasticsearchMcp {
    pub fn new_with_config(config: ElasticsearchMcpConfig, container_mode: bool) -> anyhow::Result<base_tools::EsBaseTools> {
        // The configured API key is the base64 encoding of `id:key`
        let creds = if let Some(api_key) = config.api_key.clone() {
            let (id, key) = decode_pair(&api_key, "API key")?;
            Some(Credentials::ApiKey(id, key))
        } else if let Some(username) = config.username.clone() {
            let pwd = config.password.clone().ok_or(anyhow::Error::msg("missing password"))?;
            Some(Credentials::Basic(username, pwd))
        } else {
            None
        };

        let url = config.url.as_str();
        if url.is_empty() {
            return Err(anyhow::Error::msg("Elasticsearch URL is empty"));
        }

        let mut url = Url::parse(url)?;
        if container_mode {
            rewrite_localhost(&mut url)?;
        }

        Ok(base_tools::EsBaseTools::new(EsClientProvider::new(
            url,
            creds,
            config.ssl_skip_verify,
            format!("elastic-mcp/{}", env!("CARGO_PKG_VERSION")),
        )))
    }
}

//------------------------------------------------------------------------------------------------
// Utilities

/// Rewrite urls targeting `localhost` to a hostname that maps to the container host, if possible.
///
/// The host name for the container host depends on the OCI runtime used. This is useful to accept
/// Elasticsearch URLs like `http://localhost:9200`.
fn rewrite_localhost(url: &mut Url) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    let aliases = &[
        "host.docker.internal", // Docker
        "host.containers.internal", // Podman, maybe others
    ];

    if let Some(host) = url.host_str() && host == "localhost" {
        for alias in aliases {
            if let Ok(mut alias_add) = (*alias, 80).to_socket_addrs() && alias_add.next().is_some() {
                url.set_host(Some(alias))?;
                tracing::info!("Container mode: using '{alias}' instead of 'localhost'");
                return Ok(());
            }
        }
    }
    tracing::warn!("Container mode: cound not find a replacement for 'localhost'");
    Ok(())
}

/// Map any error to an internal error of the MCP server
pub fn internal_error(e: impl std::error::Error) -> rmcp::Error {
    rmcp::Error::internal_error(e.to_string(), None)
}

/// Return an error as an error response to the client, which may be able to take
/// action to correct it. This should be refined to handle common error types such
/// as index not found, which could be caused by the client hallucinating an index name.
///
/// TODO (in rmcp): if rmcp::Error had a variant that accepts a CallToolResult, this would
/// allow to use the '?' operator while sending a result to the client.
pub fn handle_error(result: Result<Response, elasticsearch::Error>) -> Result<Response, rmcp::Error> {
    match result {
        Ok(resp) => resp.error_for_status_code(),
        Err(e) => {
            tracing::error!("Error: {:?}", &e);
            Err(e)
        }
    }
    .map_err(internal_error)
}

pub async fn read_json<T: DeserializeOwned>(
    response: Result<Response, elasticsearch::Error>,
) -> Result<T, rmcp::Error> {
    // let text = read_text(response).await?;
    // tracing::debug!("Received json {text}");
    // serde_json::from_str(&text).map_err(internal_error)

    let response = handle_error(response)?;
    response.json().await.map_err(internal_error)
}

#[allow(dead_code)]
pub async fn read_text(result: Result<Response, elasticsearch::Error>) -> Result<String, rmcp::Error> {
    let response = handle_error(result)?;
    response.text().await.map_err(internal_error)
}
