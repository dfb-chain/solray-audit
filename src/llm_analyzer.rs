use crate::Vulnerability;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Deserialize)]
struct Message {
    content: String,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AnthropicContent {
    text: String,
}

pub struct LLMAnalyzer {
    client: Client,
    openai_api_key: Option<String>,
    anthropic_api_key: Option<String>,
}

impl LLMAnalyzer {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok(),
        }
    }

    pub async fn analyze_with_openai(
        &self,
        code: &str,
        context: &str,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let api_key = self
            .openai_api_key
            .as_ref()
            .ok_or("OPENAI_API_KEY not set")?;

        let prompt = self.build_solana_security_prompt(code, context);

        let request = OpenAIRequest {
            model: "gpt-4".to_string(),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: "You are a Solana security expert. Analyze Rust code for vulnerabilities and return JSON with findings.".to_string(),
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: prompt,
                }
            ],
            temperature: 0.1,
            max_tokens: 2000,
        };

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let openai_response: OpenAIResponse = response.json().await?;

        if let Some(choice) = openai_response.choices.first() {
            self.parse_llm_response(&choice.message.content)
        } else {
            Ok(Vec::new())
        }
    }

    #[allow(dead_code)]
    pub async fn analyze_with_anthropic(
        &self,
        code: &str,
        context: &str,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let api_key = self
            .anthropic_api_key
            .as_ref()
            .ok_or("ANTHROPIC_API_KEY not set")?;

        let prompt = self.build_solana_security_prompt(code, context);

        let request = AnthropicRequest {
            model: "claude-3-sonnet-20240229".to_string(),
            max_tokens: 2000,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: format!(
                    "{}\n\n{}",
                    "You are a Solana security expert. Analyze the following Rust code for vulnerabilities and return JSON with findings.",
                    prompt
                ),
            }],
        };

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("Content-Type", "application/json")
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send()
            .await?;

        let anthropic_response: AnthropicResponse = response.json().await?;

        if let Some(content) = anthropic_response.content.first() {
            self.parse_llm_response(&content.text)
        } else {
            Ok(Vec::new())
        }
    }

    fn build_solana_security_prompt(&self, code: &str, context: &str) -> String {
        format!(
            r#"Analyze this Solana program code for security vulnerabilities using Sec3's comprehensive vulnerability taxonomy. Focus on these critical categories:

## Core Security Issues (Sec3 X-Ray Compatible):
1. **Account Validation**: Missing signer checks, ownership validation, rent exemption
2. **Cross-Program Invocation (CPI)**: Arbitrary CPI, unverified program IDs, account reloading
3. **Arithmetic Vulnerabilities**: Overflow/underflow, precision loss, casting truncation
4. **Account Data Confusion**: Type cosplay, discriminator issues, deserialization before validation
5. **PDA Security**: Bump seed validation, insecure PDA sharing, canonical address derivation
6. **Token Operations**: Freeze authority, mint/burn authorities, ATA validation
7. **Authority Management**: Unchecked transfers, upgrade vectors, multisig requirements
8. **DoS Attacks**: Compute budget exhaustion, account size growth, unbounded loops
9. **Economic Attacks**: Front-running, sandwich attacks, price manipulation, flash loans
10. **State Management**: Reentrancy patterns, initialization checks, close account safety

## Advanced Patterns:
- Unsafe Rust usage and memory safety
- Oracle manipulation and staleness checks
- Sysvar validation and trust assumptions
- Account duplication/aliasing across CPI
- Time/slot drift in calculations
- Dependency vulnerabilities and supply chain issues

Return findings in this JSON format:
[
  {{
    "rule_id": "S-XXXX",
    "vuln_type": "vulnerability_type",
    "severity": "critical|high|medium|low",
    "message": "detailed description",
    "mitigation": "specific remediation steps",
    "line_number": 123,
    "code_snippet": "problematic code",
    "file_path": "optional_file_path"
  }}
]

Code to analyze:
```rust
{}
```

Context: {}
"#,
            code, context
        )
    }

    fn parse_llm_response(
        &self,
        response: &str,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        // Try to extract JSON from the response
        let json_start = response.find('[').unwrap_or(0);
        let json_end = response.rfind(']').map(|i| i + 1).unwrap_or(response.len());
        let json_str = &response[json_start..json_end];

        let vulnerabilities: Vec<Vulnerability> = serde_json::from_str(json_str)?;
        Ok(vulnerabilities)
    }

    pub fn has_api_keys(&self) -> bool {
        self.openai_api_key.is_some() || self.anthropic_api_key.is_some()
    }
}
