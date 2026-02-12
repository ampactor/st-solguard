use crate::error::{Error, Result};
use reqwest::{Client, StatusCode, header};
use serde::de::DeserializeOwned;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    max_retries: u32,
    base_delay_ms: u64,
}

impl HttpClient {
    pub fn new(user_agent: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(180))
            .user_agent(user_agent)
            .build()
            .map_err(|e| Error::http(e.to_string()))?;

        Ok(Self {
            client,
            max_retries: 3,
            base_delay_ms: 1000,
        })
    }

    pub async fn get_text(&self, url: &str) -> Result<String> {
        self.request_with_retry(|| self.client.get(url)).await
    }

    #[allow(dead_code)]
    pub async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let body = self.get_text(url).await?;
        serde_json::from_str(&body).map_err(|e| Error::parse(format!("JSON parse: {e}")))
    }

    pub async fn get_json_authed<T: DeserializeOwned>(&self, url: &str, token: &str) -> Result<T> {
        let body = self
            .request_with_retry(|| {
                self.client
                    .get(url)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::ACCEPT, "application/vnd.github+json")
            })
            .await?;
        serde_json::from_str(&body).map_err(|e| Error::parse(format!("JSON parse: {e}")))
    }

    pub async fn post_json_raw(
        &self,
        url: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Result<String> {
        self.request_with_retry(|| {
            let mut req = self
                .client
                .post(url)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            req
        })
        .await
    }

    async fn request_with_retry<F>(&self, build: F) -> Result<String>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let mut last_error = Error::http("no attempts made");
        let mut delay = self.base_delay_ms;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                debug!(attempt, delay_ms = delay, "retrying request");
                sleep(Duration::from_millis(delay)).await;
                delay = (delay * 2).min(30_000);
            }

            match build().send().await {
                Ok(resp) => return self.handle_response(resp).await,
                Err(e) => {
                    last_error = Error::http(e.to_string());
                    if e.is_timeout() || e.is_connect() {
                        warn!(attempt, "transient failure, will retry");
                        continue;
                    }
                    return Err(last_error);
                }
            }
        }

        Err(last_error)
    }

    async fn handle_response(&self, resp: reqwest::Response) -> Result<String> {
        let status = resp.status();
        let url = resp.url().to_string();

        match status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED => {
                resp.text().await.map_err(|e| Error::http(e.to_string()))
            }
            StatusCode::TOO_MANY_REQUESTS => {
                let retry_after = resp
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok());
                Err(Error::RateLimit {
                    platform: extract_domain(&url),
                    retry_after_secs: retry_after,
                })
            }
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(Error::api_with_status(
                    extract_domain(&url),
                    body,
                    status.as_u16(),
                ))
            }
        }
    }
}

fn extract_domain(url: &str) -> String {
    url.split("//")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or("unknown")
        .to_string()
}
