//! A small ACME (RFC 8555) client for DNS-01 issuance with external account binding, as ZeroSSL requires.
//! One `issue` call is one attempt: a fresh order, its challenges, finalization with the tunnel's CSR, and the
//! certificate chain. Retries of whole attempts are the job runner's (see `retry.rs`); an attempt only repeats
//! requests that are safe to repeat: getting a nonce, a rejected nonce, and POST-as-GET reads.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::header::{CONTENT_TYPE, HeaderMap, LOCATION, RETRY_AFTER};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::crypto::{base64url, decode_base64url};
use crate::dns::{DnsProvider, TxtRecord, wait_for_propagation};
use crate::retry::{Class, classify};

#[derive(Clone)]
pub struct AcmeConfig {
    pub directory: String,
    pub email: String,
    pub eab_kid: Option<String>,
    pub eab_hmac_key: Option<String>,
    /// The account key, a P-256 private JWK.
    pub account_key_jwk: Option<String>,
    pub dns_propagation_timeout: Duration,
    pub authorization_poll: Duration,
    pub order_poll: Duration,
}

pub struct Acme {
    config: AcmeConfig,
    http: reqwest::Client,
    dns: Option<DnsProvider>,
    /// The account URL (the JWS `kid`), once registered.
    account: Mutex<Option<String>>,
    /// Ends attempts in progress (shutdown): each cleans up its authorizations and records first.
    stop: tokio_util::sync::CancellationToken,
}

/// The attempt ended because the server is shutting down, after cleaning up; it is not a failure.
#[derive(Debug, thiserror::Error)]
#[error("certificate issuance stopped: the server is shutting down")]
pub struct Stopped;

/// One attempt's result: the leaf and the rest of the chain as PEM, and the leaf's expiry.
#[derive(Debug, Clone)]
pub struct Issued {
    pub certificate: String,
    pub chain: String,
    pub expiry: String,
}

/// The first challenge, which the API shows while issuance waits for DNS.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub token: String,
    pub key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Deserialize)]
struct Order {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: Option<String>,
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct Authorization {
    status: String,
    identifier: Identifier,
    #[serde(default)]
    challenges: Vec<AcmeChallenge>,
}

#[derive(Deserialize)]
struct Identifier {
    value: String,
}

#[derive(Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    status: String,
    /// Why validation failed (RFC 8555 section 8), a problem document.
    #[serde(default)]
    error: Option<Value>,
}

impl Authorization {
    fn dns_challenge(&self) -> Option<&AcmeChallenge> {
        self.challenges
            .iter()
            .find(|challenge| challenge.kind == "dns-01")
    }

    /// The CA's reasons for failed validation, from the challenges' error documents.
    fn error_detail(&self) -> String {
        self.challenges
            .iter()
            .filter_map(|challenge| challenge.error.as_ref())
            .map(|error| {
                let kind = error["type"].as_str().unwrap_or_default();
                let detail = error["detail"].as_str().unwrap_or_default();
                match (kind.is_empty(), detail.is_empty()) {
                    (false, false) => format!("{kind}: {detail}"),
                    (true, true) => error.to_string(),
                    _ => format!("{kind}{detail}"),
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// A pending authorization this attempt answers.
struct Pending {
    url: String,
    identifier: String,
    challenge_url: String,
    token: String,
    /// The TXT record value.
    value: String,
}

struct Key {
    pair: EcdsaKeyPair,
    jwk: Value,
    thumbprint: String,
}

struct Response {
    headers: HeaderMap,
    body: bytes::Bytes,
}

/// An ACME error response (RFC 8555 section 6.7), displayed as the Worker's `describeError` did.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Problem {
    pub status: u16,
    /// The problem type URN, empty when the body was not a problem document.
    pub kind: String,
    pub retry_after: Option<Duration>,
    pub message: String,
}

/// A failure that is expected to clear up by itself, such as a missing nonce or an authorization the CA has
/// not finished validating.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Transient {
    pub message: String,
    pub retry_after: Option<Duration>,
}

impl Transient {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retry_after: None,
        }
    }
}

/// Requests in one attempt that are safe to repeat are tried this many times.
const REQUEST_TRIES: u32 = 3;
/// The pause before repeating such a request, doubled each time.
const REQUEST_RETRY_PAUSE: Duration = Duration::from_millis(500);
/// Reads of the answered authorizations, `authorization_poll` apart, before giving up on them.
const AUTHORIZATION_POLLS: u32 = 60;
/// Orders per attempt: one more after abandoning an order whose authorizations an earlier attempt left unusable.
const ORDERS: u32 = 2;

impl Acme {
    pub fn new(config: AcmeConfig, http: reqwest::Client, dns: Option<DnsProvider>) -> Self {
        Self {
            config,
            http,
            dns,
            account: Mutex::new(None),
            stop: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Ends every attempt in progress and any started later with [`Stopped`], each after deactivating its
    /// answered authorizations and deleting its challenge records, so a shutdown leaves nothing in the zone.
    pub fn stop(&self) {
        self.stop.cancel();
    }

    pub fn dns(&self) -> Option<&DnsProvider> {
        self.dns.as_ref()
    }

    pub async fn issue(
        &self,
        identifiers: &[String],
        csr_pem: &str,
        on_challenge: impl AsyncFnOnce(Challenge) -> Result<()>,
    ) -> Result<Issued> {
        // EAB is optional: ZeroSSL requires it, Let's Encrypt does not.
        let kid = self.config.eab_kid.as_deref();
        let hmac = self.config.eab_hmac_key.as_deref();
        if (kid.is_some()) != (hmac.is_some()) {
            bail!("ACME_EAB_KID and ACME_EAB_HMAC_KEY must be set together");
        }
        let Some(dns) = &self.dns else {
            bail!("CLOUDFLARE_ZONE_ID and CLOUDFLARE_API_TOKEN are required");
        };
        if self.stop.is_cancelled() {
            return Err(Stopped.into());
        }
        let key = account_key(self.config.account_key_jwk.as_deref())?;
        let origin = url::Url::parse(&self.config.directory)
            .context("ACME_URL is not a URL")?
            .origin();
        let directory: Directory = self
            .http
            .get(&self.config.directory)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("fetching the ACME directory")?
            .error_for_status()?
            .json()
            .await
            .context("reading the ACME directory")?;
        let mut session = Session {
            http: &self.http,
            origin,
            key: &key,
            new_nonce: &directory.new_nonce,
            nonce: None,
            kid: self.account.lock().await.clone(),
        };
        if session.kid.is_none() {
            let mut payload = json!({
                "contact": [format!("mailto:{}", self.config.email)],
                "termsOfServiceAgreed": true,
            });
            if let Some(binding) = kid.and_then(|kid| {
                hmac.map(|hmac| external_account_binding(&key, kid, hmac, &directory.new_account))
            }) {
                payload["externalAccountBinding"] = binding?;
            }
            let response = session.post(&directory.new_account, Some(&payload)).await?;
            let location = header(&response.headers, LOCATION)
                .ok_or_else(|| anyhow!("ACME account has no location URL"))?;
            *self.account.lock().await = Some(location.clone());
            session.kid = Some(location);
        }

        let (order_url, pending) = place_order(
            &mut session,
            &directory.new_order,
            identifiers,
            &key.thumbprint,
        )
        .await?;
        if let Some(first) = pending.first() {
            on_challenge(Challenge {
                token: first.token.clone(),
                key: first.value.clone(),
            })
            .await?;
        }

        // A hostname and its wildcard share one record name, and may share a token (so one value).
        let mut wanted: Vec<(String, String)> = Vec::new();
        for authorization in &pending {
            let name = format!(
                "_acme-challenge.{}",
                authorization.identifier.trim_start_matches("*.")
            );
            if !wanted
                .iter()
                .any(|(n, v)| *n == name && *v == authorization.value)
            {
                wanted.push((name, authorization.value.clone()));
            }
        }
        let mut records: Vec<TxtRecord> = Vec::new();
        // Authorizations whose challenge was (or may have been) answered and that have not reached a final
        // state. The CA may still be checking their records, so those stay published until each one is valid,
        // invalid or deactivated.
        let mut unsettled: Vec<&Pending> = Vec::new();
        let attempt = async {
            for (name, value) in &wanted {
                records.push(
                    dns.create_txt(name, value)
                        .await
                        .context("creating the DNS challenge record")?,
                );
            }
            wait_for_propagation(&self.http, &records, self.config.dns_propagation_timeout).await;
            for authorization in &pending {
                unsettled.push(authorization);
                session
                    .post(&authorization.challenge_url, Some(&json!({})))
                    .await?;
            }
            let mut polls = 0;
            loop {
                let mut index = 0;
                while index < unsettled.len() {
                    let current = unsettled[index];
                    let authorization: Authorization =
                        parse(&session.get(&current.url).await?.body, "authorization")?;
                    match &authorization.status[..] {
                        "valid" => {
                            unsettled.remove(index);
                        }
                        "pending" => index += 1,
                        status => {
                            unsettled.remove(index);
                            let detail = authorization.error_detail();
                            warn!(
                                identifier = %current.identifier,
                                authorization = %current.url,
                                status,
                                error = %detail,
                                "ACME authorization failed"
                            );
                            // Other pending authorizations are deactivated below; the next attempt starts over.
                            if detail.is_empty() {
                                bail!(
                                    "ACME authorization for {} ended in {status}",
                                    current.identifier
                                );
                            }
                            bail!(
                                "ACME authorization for {} ended in {status}: {detail}",
                                current.identifier
                            );
                        }
                    }
                }
                if unsettled.is_empty() {
                    break;
                }
                polls += 1;
                if polls > AUTHORIZATION_POLLS {
                    for current in &unsettled {
                        warn!(
                            identifier = %current.identifier,
                            authorization = %current.url,
                            "ACME authorization still pending; deactivating it so the next attempt gets a new one"
                        );
                    }
                    return Err(Transient::new("ACME authorization ended in pending").into());
                }
                tokio::time::sleep(self.config.authorization_poll).await;
            }

            let mut order: Order = parse(&session.get(&order_url).await?.body, "order")?;
            for _ in 0..30 {
                if order.status != "pending" {
                    break;
                }
                tokio::time::sleep(self.config.order_poll).await;
                order = parse(&session.get(&order_url).await?.body, "order")?;
            }
            let csr = pem_der(csr_pem).ok_or_else(|| anyhow!("CSR is not PEM"))?;
            // An order an earlier attempt already finalized is not finalized again.
            if order.status == "ready" {
                let finalize = order
                    .finalize
                    .as_deref()
                    .ok_or_else(|| anyhow!("ACME order has no finalize URL"))?;
                session
                    .post(finalize, Some(&json!({ "csr": base64url(&csr) })))
                    .await?;
                order = parse(&session.get(&order_url).await?.body, "order")?;
            }
            for _ in 0..30 {
                if order.status != "processing" {
                    break;
                }
                tokio::time::sleep(self.config.order_poll).await;
                order = parse(&session.get(&order_url).await?.body, "order")?;
            }
            let certificate_url = match (&order.status[..], &order.certificate) {
                ("valid", Some(url)) => url.clone(),
                (status @ ("pending" | "processing"), _) => {
                    return Err(Transient::new(format!("ACME order ended in {status}")).into());
                }
                (status, _) => bail!("ACME order ended in {status}"),
            };
            let response = session.get(&certificate_url).await?;
            let pem = std::str::from_utf8(&response.body)?;
            let issued = chain_from_pem(pem)?;
            if !certifies_key(pem, &csr) {
                bail!("ACME returned a certificate for another key");
            }
            Ok(issued)
        };
        // A shutdown ends the attempt here, so the cleanup below still runs.
        let result = tokio::select! {
            result = attempt => result,
            () = self.stop.cancelled() => Err(Stopped.into()),
        };
        // An authorization left pending is handed to the next order as it is, its challenge possibly stuck in
        // `processing` for good (ZeroSSL), so it is deactivated (RFC 8555 section 7.5.2) and the next attempt
        // gets a new one. Its records are deleted only once the CA can no longer be checking them.
        let mut settled = true;
        for authorization in &unsettled {
            if let Err(error) = deactivate(&mut session, &authorization.url).await {
                warn!(
                    error = %format!("{error:#}"),
                    identifier = %authorization.identifier,
                    authorization = %authorization.url,
                    "deactivating an ACME authorization failed; keeping its challenge records"
                );
                settled = false;
            }
        }
        // Otherwise the records stay until the sweep removes them (`jobs::run_dns_sweeper`), long after the CA
        // could still check them.
        if settled {
            for record in &records {
                dns.delete_txt(record).await;
            }
        }
        if result.is_ok() {
            info!(identifiers = ?identifiers, "certificate issued");
        }
        result
    }
}

/// Places an order and reads its authorizations: the order's URL and the pending ones to answer. The CA hands
/// back authorizations from earlier orders for the same identifiers: valid ones are skipped, and an order with
/// one that cannot succeed (a challenge an earlier attempt answered whose validation never finished, or a failed
/// authorization) is abandoned for a fresh one, after deactivating the stuck ones so they are not reused.
async fn place_order(
    session: &mut Session<'_>,
    new_order: &str,
    identifiers: &[String],
    thumbprint: &str,
) -> Result<(String, Vec<Pending>)> {
    let identifiers: Vec<Value> = identifiers
        .iter()
        .map(|value| json!({ "type": "dns", "value": value }))
        .collect();
    for _ in 0..ORDERS {
        let response = session
            .post(new_order, Some(&json!({ "identifiers": identifiers })))
            .await?;
        let order_url = header(&response.headers, LOCATION)
            .ok_or_else(|| anyhow!("ACME order has no location URL"))?;
        let order: Order = parse(&response.body, "order")?;
        let mut pending = Vec::new();
        let mut stale = Vec::new();
        let mut usable = true;
        for url in &order.authorizations {
            let authorization: Authorization =
                parse(&session.get(url).await?.body, "authorization")?;
            let identifier = authorization.identifier.value.clone();
            match &authorization.status[..] {
                "valid" => continue,
                "pending" => {}
                status => {
                    // invalid, deactivated, expired or revoked: the order cannot become ready.
                    warn!(
                        %identifier,
                        authorization = %url,
                        status,
                        error = %authorization.error_detail(),
                        "ACME order has a failed authorization; placing a new order"
                    );
                    usable = false;
                    continue;
                }
            }
            let challenge = authorization
                .dns_challenge()
                .ok_or_else(|| anyhow!("ACME server did not offer dns-01"))?;
            // Each attempt settles the challenges it answers or deactivates their authorizations, so one being
            // validated now was left by an attempt that was cut off, or by an older version of this server; such
            // validation may never finish, and the CA keeps handing the authorization out until it is deactivated.
            if !(challenge.status.is_empty() || challenge.status == "pending") {
                warn!(
                    %identifier,
                    authorization = %url,
                    challenge = %challenge.status,
                    error = %authorization.error_detail(),
                    "ACME authorization was left with a challenge in progress; deactivating it"
                );
                stale.push(url.clone());
                usable = false;
                continue;
            }
            let key_authorization = format!("{}.{thumbprint}", challenge.token);
            let value = base64url(
                ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes()).as_ref(),
            );
            pending.push(Pending {
                url: url.clone(),
                identifier,
                challenge_url: challenge.url.clone(),
                token: challenge.token.clone(),
                value,
            });
        }
        if usable {
            return Ok((order_url, pending));
        }
        // Its unanswered authorizations are fine for the next order.
        for url in &stale {
            deactivate(session, url).await?;
        }
    }
    Err(Transient::new("ACME server kept handing out authorizations that cannot succeed").into())
}

/// Deactivates an authorization (RFC 8555 section 7.5.2) so the CA stops validating it and hands out a new one.
/// One that reached a final state meanwhile needs nothing.
async fn deactivate(session: &mut Session<'_>, url: &str) -> Result<()> {
    match session
        .post(url, Some(&json!({ "status": "deactivated" })))
        .await
    {
        Ok(_) => {
            info!(authorization = %url, "deactivated an ACME authorization");
            Ok(())
        }
        Err(error) => {
            let authorization: Authorization =
                parse(&session.get(url).await?.body, "authorization")?;
            if authorization.status == "pending" {
                Err(error.context("deactivating an ACME authorization"))
            } else {
                Ok(())
            }
        }
    }
}

struct Session<'a> {
    http: &'a reqwest::Client,
    /// The directory's scheme, host and port: the only place requests go, whatever URLs the CA's answers name.
    origin: url::Origin,
    key: &'a Key,
    new_nonce: &'a str,
    nonce: Option<String>,
    kid: Option<String>,
}

impl Session<'_> {
    /// The nonce from the last response, or a new one. ZeroSSL's proxy sometimes answers without one (with an
    /// error status), so this tries again shortly, with GET (RFC 8555 section 7.2) after the first HEAD.
    async fn fresh_nonce(&mut self) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        self.check_url(self.new_nonce)?;
        let mut pause = REQUEST_RETRY_PAUSE;
        let mut last = String::new();
        for attempt in 1..=REQUEST_TRIES {
            let request = if attempt == 1 {
                self.http.head(self.new_nonce)
            } else {
                self.http.get(self.new_nonce)
            };
            match request.timeout(Duration::from_secs(30)).send().await {
                Ok(response) => {
                    if let Some(nonce) = header(response.headers(), "replay-nonce") {
                        return Ok(nonce);
                    }
                    last = format!(" (HTTP {})", response.status().as_u16());
                }
                Err(error) => last = format!(": {error}"),
            }
            if attempt < REQUEST_TRIES {
                tokio::time::sleep(pause).await;
                pause *= 2;
            }
        }
        Err(Transient::new(format!("ACME server returned no nonce{last}")).into())
    }

    /// A POST-as-GET read, repeated a few times on a transient failure (a 502 from the CA's proxy, a reset
    /// connection), since reading twice is harmless.
    async fn get(&mut self, url: &str) -> Result<Response> {
        let mut pause = REQUEST_RETRY_PAUSE;
        let mut attempt = 1;
        loop {
            match self.post(url, None).await {
                Err(error)
                    if attempt < REQUEST_TRIES
                        && matches!(classify(&error), Class::Transient { .. }) =>
                {
                    tokio::time::sleep(pause).await;
                    pause *= 2;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    /// A signed POST; `None` is POST-as-GET. Retries a rejected nonce with the one the rejection carries, which
    /// servers may do at any time.
    async fn post(&mut self, url: &str, payload: Option<&Value>) -> Result<Response> {
        let mut attempt = 0;
        self.check_url(url)?;
        loop {
            attempt += 1;
            let nonce = self.fresh_nonce().await?;
            let body = self.sign(url, &nonce, payload)?;
            let response = self
                .http
                .post(url)
                .header(CONTENT_TYPE, "application/jose+json")
                .timeout(Duration::from_secs(60))
                .body(body)
                .send()
                .await
                .with_context(|| format!("ACME request to {url} failed"))?;
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            self.nonce = header(&headers, "replay-nonce");
            let body = response
                .bytes()
                .await
                .with_context(|| format!("ACME request to {url} failed"))?;
            if status < 400 {
                return Ok(Response { headers, body });
            }
            let problem: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let kind = problem["type"].as_str().unwrap_or_default();
            if kind.ends_with(":badNonce") && attempt <= 3 {
                continue;
            }
            let detail = problem["detail"].as_str().unwrap_or_default();
            let text = String::from_utf8_lossy(&body);
            // As the Worker's describeError: the message, the HTTP status, and the start of the response body.
            let message = format!(
                "{} | HTTP {status} | {}",
                if detail.is_empty() {
                    format!("ACME request to {url} failed")
                } else {
                    format!("{kind}: {detail}")
                },
                text.chars().take(300).collect::<String>()
            );
            return Err(Problem {
                status,
                kind: kind.to_owned(),
                retry_after: header(&headers, RETRY_AFTER)
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .map(Duration::from_secs),
                message,
            }
            .into());
        }
    }
    /// Refuses a URL the CA named unless it is on the directory's own origin (an HTTPS directory: HTTPS only).
    fn check_url(&self, url: &str) -> Result<()> {
        match url::Url::parse(url) {
            Ok(parsed) if parsed.origin() == self.origin => Ok(()),
            _ => Err(anyhow!(
                "the ACME server named a URL outside its directory's origin: {}",
                url.chars().take(200).collect::<String>()
            )),
        }
    }

    fn sign(&self, url: &str, nonce: &str, payload: Option<&Value>) -> Result<String> {
        let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
        match &self.kid {
            Some(kid) => protected["kid"] = kid.clone().into(),
            None => protected["jwk"] = self.key.jwk.clone(),
        }
        let protected = base64url(serde_json::to_string(&protected)?.as_bytes());
        let payload = match payload {
            Some(payload) => base64url(serde_json::to_string(payload)?.as_bytes()),
            None => String::new(),
        };
        let signature = self
            .key
            .pair
            .sign(
                &SystemRandom::new(),
                format!("{protected}.{payload}").as_bytes(),
            )
            .map_err(|_| anyhow!("signing an ACME request failed"))?;
        Ok(serde_json::to_string(&json!({
            "protected": protected,
            "payload": payload,
            "signature": base64url(signature.as_ref()),
        }))?)
    }
}

/// Reads a JSON response. A 2xx response that is not the JSON it should be came from a struggling proxy in
/// front of the CA, so it is transient.
fn parse<T: DeserializeOwned>(body: &[u8], what: &str) -> Result<T> {
    serde_json::from_slice(body).map_err(|error| {
        Transient::new(format!(
            "ACME {what} response could not be read ({error}): {}",
            String::from_utf8_lossy(body)
                .chars()
                .take(100)
                .collect::<String>()
        ))
        .into()
    })
}

/// Whether the leaf of `pem` certifies the public key of the CSR `csr_der`.
fn certifies_key(pem: &str, csr_der: &[u8]) -> bool {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::prelude::FromDer;
    let Some(Ok(leaf)) = CertificateDer::pem_slice_iter(pem.as_bytes()).next() else {
        return false;
    };
    let (Ok((_, certificate)), Ok((_, request))) = (
        x509_parser::parse_x509_certificate(leaf.as_ref()),
        X509CertificationRequest::from_der(csr_der),
    ) else {
        return false;
    };
    certificate.public_key().raw == request.certification_request_info.subject_pki.raw
}

fn header(headers: &HeaderMap, name: impl reqwest::header::AsHeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Reads the account key from its P-256 private JWK.
fn account_key(jwk: Option<&str>) -> Result<Key> {
    let invalid = || anyhow!("ACME_ACCOUNT_KEY_JWK is not a P-256 private JWK");
    let jwk: Value = serde_json::from_str(jwk.ok_or_else(invalid)?).map_err(|_| invalid())?;
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(invalid());
    }
    let field = |name: &str| {
        jwk[name]
            .as_str()
            .and_then(decode_base64url)
            .filter(|bytes| bytes.len() == 32)
            .ok_or_else(invalid)
    };
    let (x, y, d) = (field("x")?, field("y")?, field("d")?);
    let mut public = vec![4u8];
    public.extend(&x);
    public.extend(&y);
    let pair = EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &d,
        &public,
        &SystemRandom::new(),
    )
    .map_err(|_| invalid())?;
    Ok(key_from_pair(pair))
}

fn key_from_pair(pair: EcdsaKeyPair) -> Key {
    let public = pair.public_key().as_ref();
    let x = base64url(&public[1..33]);
    let y = base64url(&public[33..65]);
    // RFC 7638: the required members in lexicographic order, without whitespace.
    let thumbprint_input = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let thumbprint = base64url(
        ring::digest::digest(&ring::digest::SHA256, thumbprint_input.as_bytes()).as_ref(),
    );
    Key {
        pair,
        jwk: json!({ "crv": "P-256", "kty": "EC", "x": x, "y": y }),
        thumbprint,
    }
}

/// The EAB JWS: the account's public JWK, MACed with the HMAC key the CA issued for `kid`.
fn external_account_binding(key: &Key, kid: &str, hmac_key: &str, url: &str) -> Result<Value> {
    let secret =
        decode_base64url(hmac_key).ok_or_else(|| anyhow!("ACME_EAB_HMAC_KEY is not base64url"))?;
    let protected = base64url(
        serde_json::to_string(&json!({ "alg": "HS256", "kid": kid, "url": url }))?.as_bytes(),
    );
    let payload = base64url(serde_json::to_string(&key.jwk)?.as_bytes());
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret),
        format!("{protected}.{payload}").as_bytes(),
    );
    Ok(json!({ "protected": protected, "payload": payload, "signature": base64url(tag.as_ref()) }))
}

/// The DER of the first PEM block.
pub fn pem_der(pem: &str) -> Option<Vec<u8>> {
    use rustls_pki_types::pem::PemObject;
    if let Ok(csr) = rustls_pki_types::CertificateSigningRequestDer::from_pem_slice(pem.as_bytes())
    {
        return Some(csr.as_ref().to_vec());
    }
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .split_whitespace()
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// Splits a PEM chain into the leaf and the rest, formatted as the Worker formatted them: 64-column base64,
/// no trailing newline, certificates joined by one newline.
pub fn chain_from_pem(pem: &str) -> Result<Issued> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow!("ACME response did not contain a certificate: {error}"))?;
    let Some(leaf) = certificates.first() else {
        bail!("ACME response did not contain a certificate");
    };
    let expiry = expiry(leaf.as_ref())?;
    let pems: Vec<String> = certificates
        .iter()
        .map(|der| to_pem(der.as_ref()))
        .collect();
    Ok(Issued {
        certificate: pems[0].clone(),
        chain: pems[1..].join("\n"),
        expiry,
    })
}

pub fn to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        lines.join("\n")
    )
}

/// A certificate's notAfter as an ISO timestamp.
pub fn expiry(der: &[u8]) -> Result<String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow!("invalid certificate: {error}"))?;
    let seconds = certificate.validity().not_after.timestamp();
    Ok(crate::clock::iso((seconds.max(0) as u64) * 1000))
}

/// Generates a P-256 account key as a private JWK, for `opentunnel-server account-key`.
pub fn generate_account_jwk() -> Result<String> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| anyhow!("generating a key failed"))?;
    // The private scalar sits at a fixed offset in ring's PKCS#8 encoding of a P-256 key.
    let bytes = pkcs8.as_ref();
    let d = &bytes[36..68];
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, bytes, &rng)
        .map_err(|_| anyhow!("reading the generated key failed"))?;
    let public = pair.public_key().as_ref();
    Ok(serde_json::to_string(&json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64url(&public[1..33]),
        "y": base64url(&public[33..65]),
        "d": base64url(d),
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_go_only_to_the_directorys_origin() {
        crate::install_crypto_provider();
        let http = reqwest::Client::new();
        let key = account_key(Some(&generate_account_jwk().unwrap())).unwrap();
        let session = Session {
            http: &http,
            origin: url::Url::parse("https://acme.zerossl.com/v2/DV90")
                .unwrap()
                .origin(),
            key: &key,
            new_nonce: "https://acme.zerossl.com/v2/DV90/newNonce",
            nonce: None,
            kid: None,
        };
        for url in [
            "https://acme.zerossl.com/v2/DV90/order/1",
            "https://acme.zerossl.com:443/v2/DV90/authz/2",
        ] {
            assert!(session.check_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://acme.zerossl.com/v2/DV90/order/1",
            "https://169.254.169.254/latest/meta-data",
            "http://[fdaa::1]:9000/internal/tunnel/x/routes",
            "https://acme.zerossl.com.evil.example/",
            "https://acme.zerossl.com:8443/",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(session.check_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn reads_generated_account_keys() {
        let jwk = generate_account_jwk().unwrap();
        let key = account_key(Some(&jwk)).unwrap();
        assert_eq!(key.thumbprint.len(), 43);
        assert!(account_key(Some(r#"{"kty":"RSA"}"#)).is_err());
        assert_eq!(
            account_key(None).err().unwrap().to_string(),
            "ACME_ACCOUNT_KEY_JWK is not a P-256 private JWK"
        );
    }

    #[test]
    fn formats_chains_like_the_worker() {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["a.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = format!("{}\n{}", certificate.pem(), certificate.pem());
        let issued = chain_from_pem(&pem).unwrap();
        assert!(
            issued
                .certificate
                .starts_with("-----BEGIN CERTIFICATE-----\n")
        );
        assert!(issued.certificate.ends_with("\n-----END CERTIFICATE-----"));
        assert_eq!(issued.chain, issued.certificate);
        assert!(issued.expiry.ends_with(".000Z"));
    }
}
