use async_trait::async_trait;
use email_address::EmailAddress;
use phonenumber::{Mode, parse};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiKind {
    Email,
    Phone,
    Address,
    Credential,
    Other,
}

impl PiiKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Address => "address",
            Self::Credential => "credential",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub value: String,
}

#[async_trait]
pub trait PiiProvider: Send + Sync {
    async fn detect(&self, text: &str) -> Vec<PiiMatch>;
    fn provider_name(&self) -> &'static str;
}

#[derive(Debug, Default)]
pub struct LocalPiiProvider;

#[async_trait]
impl PiiProvider for LocalPiiProvider {
    async fn detect(&self, text: &str) -> Vec<PiiMatch> {
        let mut out = Vec::new();

        for token in split_words(text) {
            if token.contains('@') && EmailAddress::is_valid(token) {
                out.push(PiiMatch {
                    kind: PiiKind::Email,
                    value: token.to_owned(),
                });
            }
        }

        for token in extract_phone_candidates(text) {
            if let Ok(number) = parse(None, token) {
                if number.is_valid() {
                    out.push(PiiMatch {
                        kind: PiiKind::Phone,
                        value: number.format().mode(Mode::E164).to_string(),
                    });
                }
            }
        }

        let jp_postal = Regex::new(r"\b\d{3}-\d{4}\b").expect("valid regex");
        let us_street = Regex::new(
            r"\b\d{1,6}\s+[A-Za-z0-9.\-\s]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b",
        )
        .expect("valid regex");
        if jp_postal.is_match(text) || us_street.is_match(text) {
            out.push(PiiMatch {
                kind: PiiKind::Address,
                value: clip(text),
            });
        }

        let lower = text.to_lowercase();
        let has_context = [
            "token",
            "secret",
            "api_key",
            "apikey",
            "authorization",
            "bearer",
            "password",
        ]
        .iter()
        .any(|k| lower.contains(k));

        for token in split_words(text) {
            if token.len() < 20 {
                continue;
            }
            if !token.chars().any(|c| c.is_ascii_digit())
                || !token.chars().any(|c| c.is_ascii_alphabetic())
            {
                continue;
            }
            let entropy = shannon_entropy(token);
            if entropy < 3.8 {
                continue;
            }
            if !has_context && !looks_like_credential_shape(token) {
                continue;
            }
            out.push(PiiMatch {
                kind: PiiKind::Credential,
                value: clip(token),
            });
        }

        out
    }

    fn provider_name(&self) -> &'static str {
        "local"
    }
}

fn split_words(input: &str) -> impl Iterator<Item = &str> {
    input
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';')
        .filter(|part| !part.is_empty())
}

fn extract_phone_candidates(input: &str) -> impl Iterator<Item = &str> {
    input
        .split(|c: char| !(c.is_ascii_digit() || matches!(c, '+' | '-' | '(' | ')' | ' ')))
        .filter(|part| {
            let digits = part.chars().filter(|ch| ch.is_ascii_digit()).count();
            digits >= 10
        })
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = std::collections::HashMap::<char, usize>::new();
    for ch in input.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    let len = input.chars().count() as f64;

    counts
        .into_values()
        .map(|count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_credential_shape(token: &str) -> bool {
    token.starts_with("sk-")
        || token.starts_with("ghp_")
        || token.starts_with("AKIA")
        || token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '+' | '='))
}

fn clip(text: &str) -> String {
    const MAX: usize = 120;
    let mut chars = text.chars();
    let clipped: String = chars.by_ref().take(MAX).collect();
    if chars.next().is_some() {
        format!("{clipped}...")
    } else {
        clipped
    }
}
