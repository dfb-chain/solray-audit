use crate::{Rule, Vulnerability};
use ethers_solc::{artifacts::Source, remappings::Remapping, CompilerInput, Solc};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

pub struct SolidityAstAnalyzer {
    rules: Arc<HashMap<String, Rule>>,
    file_path: Option<String>,
    project_root: Option<PathBuf>,
    include_paths: Vec<PathBuf>,
    remappings: Vec<String>,
    solc_version: Option<String>,
}

impl SolidityAstAnalyzer {
    pub fn new(
        rules: Arc<HashMap<String, Rule>>,
        file_path: Option<String>,
        project_root: Option<PathBuf>,
        include_paths: Vec<PathBuf>,
        remappings: Vec<String>,
        solc_version: Option<String>,
    ) -> Self {
        Self {
            rules,
            file_path,
            project_root,
            include_paths,
            remappings,
            solc_version,
        }
    }

    pub fn analyze(
        &mut self,
        source_code: &str,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let mut vulns = Vec::new();
        let Some(file_path) = &self.file_path else {
            eprintln!("⚠️ AST analysis skipped: provide real file paths for Solidity targets.");
            return Ok(vulns);
        };

        if file_path.to_ascii_lowercase().ends_with(".json") {
            eprintln!(
                "⚠️ AST analysis skipped for ABI/JSON artifact: {}",
                file_path
            );
            return Ok(vulns);
        }

        let path = PathBuf::from(file_path);
        if !path.exists() {
            eprintln!(
                "⚠️ AST analysis skipped: Solidity file not found on disk: {}",
                file_path
            );
            return Ok(vulns);
        }

        let mut solc = if let Some(version) = &self.solc_version {
            match Solc::find_or_install_svm_version(version) {
                Ok(solc_bin) => solc_bin,
                Err(err) => {
                    eprintln!(
                        "⚠️ Failed to prepare solc version {} via svm: {}. Falling back to default solc.",
                        version, err
                    );
                    Solc::default()
                }
            }
        } else {
            Solc::default()
        };
        if let Some(root) = &self.project_root {
            solc = solc.with_base_path(root);
        }
        for include in &self.include_paths {
            solc = solc.arg(format!("--include-path={}", include.to_string_lossy()));
        }
        let mut sources = BTreeMap::new();
        sources.insert(path.clone(), Source::new(source_code.to_string()));
        let inputs = CompilerInput::with_sources(sources);
        let Some(mut input) = inputs.into_iter().find(|i| i.language.eq_ignore_ascii_case("Solidity")) else {
            eprintln!("⚠️ Unable to build Solidity compiler input for {}", file_path);
            return Ok(vulns);
        };

        if let Some(root) = &self.project_root {
            input = input.with_base_path(root);
        }

        if !self.remappings.is_empty() {
            let mut parsed = Vec::new();
            for remap in &self.remappings {
                match Remapping::from_str(remap) {
                    Ok(value) => parsed.push(value),
                    Err(err) => eprintln!("⚠️ Failed to parse remapping '{}': {}", remap, err),
                }
            }
            if !parsed.is_empty() {
                input.settings.remappings = parsed;
            }
        }

        let output = match solc.compile_exact(&input) {
            Ok(out) => out,
            Err(e) => {
                eprintln!("Failed to compile Solidity source with solc: {}", e);
                return Ok(vulns);
            }
        };

        if output.has_error() {
            for err in &output.errors {
                eprintln!("solc: {}", err);
            }
            return Ok(vulns);
        }

        let target_key = canonical_string(path.as_path());

        for (name, unit) in output.sources.iter() {
            let normalized = canonical_string(Path::new(name.as_str()));
            if !target_key.is_empty() && normalized != target_key {
                continue;
            }

            if let Some(ast) = &unit.ast {
                match serde_json::to_value(ast) {
                    Ok(value) => {
                        self.inspect_ast(&value, source_code, &mut vulns);
                    }
                    Err(e) => eprintln!("Failed to convert Solidity AST to JSON: {}", e),
                }
            }
        }

        Ok(vulns)
    }

    fn inspect_ast(&self, ast: &Value, source_code: &str, vulns: &mut Vec<Vulnerability>) {
        if let Some(nodes) = ast.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                if node_type(node) == Some("ContractDefinition") {
                    self.inspect_contract(node, source_code, vulns);
                }
            }
        }
    }

    fn inspect_contract(
        &self,
        contract: &Value,
        source_code: &str,
        vulns: &mut Vec<Vulnerability>,
    ) {
        if let Some(nodes) = contract.get("nodes").and_then(|n| n.as_array()) {
            for node in nodes {
                match node_type(node) {
                    Some("FunctionDefinition") => {
                        self.check_unrestricted_setter(node, source_code, vulns);
                    }
                    _ => {}
                }
            }
        }
    }

    fn check_unrestricted_setter(
        &self,
        function: &Value,
        source_code: &str,
        vulns: &mut Vec<Vulnerability>,
    ) {
        let name = function
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let visibility = function
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let state_mutability = function
            .get("stateMutability")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if name.is_empty()
            || !matches!(visibility, "public" | "external")
            || matches!(state_mutability, "view" | "pure")
            || !is_sensitive_function(name)
        {
            return;
        }

        let modifiers_vec = function
            .get("modifiers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if has_protective_modifier(&modifiers_vec) {
            return;
        }

        if let Some((offset, length)) = parse_span(function) {
            let line_number = offset_to_line(source_code, offset);
            let code_snippet = snippet_from_span(source_code, offset, length);
            self.push_vulnerability("EVM-1001", line_number, code_snippet, vulns);
        }
    }

    fn push_vulnerability(
        &self,
        rule_id: &str,
        line_number: usize,
        code_snippet: String,
        vulns: &mut Vec<Vulnerability>,
    ) {
        let (message, severity, mitigation) = if let Some(rule) = self.rules.get(rule_id) {
            (
                rule.description.clone(),
                rule.severity.clone(),
                rule.mitigation.clone(),
            )
        } else {
            (
                "Potentially unprotected privileged function".to_string(),
                "medium".to_string(),
                None,
            )
        };

        vulns.push(Vulnerability {
            rule_id: rule_id.to_string(),
            vuln_type: rule_id.to_string(),
            severity,
            message,
            mitigation,
            line_number,
            code_snippet,
            file_path: self.file_path.clone(),
        });
    }
}

fn node_type(value: &Value) -> Option<&str> {
    value.get("nodeType").and_then(|n| n.as_str())
}

fn canonical_string(path: &Path) -> String {
    path.canonicalize()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

fn parse_span(value: &Value) -> Option<(usize, usize)> {
    let src = value.get("src")?.as_str()?;
    let mut parts = src.split(':');
    let start = parts.next()?.parse().ok()?;
    let len = parts.next()?.parse().ok()?;
    Some((start, len))
}

fn offset_to_line(source: &str, offset: usize) -> usize {
    if offset == 0 {
        return 1;
    }
    let mut line = 1;
    let mut consumed = 0usize;
    for ch in source.chars() {
        if consumed >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
        }
        consumed += ch.len_utf8();
    }
    line
}

fn snippet_from_span(source: &str, offset: usize, length: usize) -> String {
    if source.is_empty() {
        return String::new();
    }
    let bytes = source.as_bytes();
    if offset >= bytes.len() {
        return String::new();
    }
    let end = (offset + length).min(bytes.len());
    if end <= offset {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[offset..end])
        .trim()
        .to_string()
}

fn is_sensitive_function(name: &str) -> bool {
    const CONTROLLED_PREFIXES: [&str; 10] = [
        "set",
        "update",
        "configure",
        "grant",
        "revoke",
        "add",
        "remove",
        "pause",
        "resume",
        "upgrade",
    ];
    let lower = name.to_ascii_lowercase();
    CONTROLLED_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn has_protective_modifier(modifiers: &[Value]) -> bool {
    const SAFE_NAMES: [&str; 8] = [
        "onlyOwner",
        "onlyRole",
        "auth",
        "governance",
        "whenNotPaused",
        "initializer",
        "reinitializer",
        "restricted",
    ];

    modifiers.iter().any(|modifier| {
        modifier
            .get("modifierName")
            .and_then(|n| n.get("name"))
            .and_then(|n| n.as_str())
            .map(|name| {
                SAFE_NAMES
                    .iter()
                    .any(|safe| name.eq_ignore_ascii_case(safe))
            })
            .unwrap_or(false)
    })
}
