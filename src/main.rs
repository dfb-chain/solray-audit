use clap::{Args as ClapArgs, Parser, Subcommand};
use dotenv::dotenv;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use toml::from_str;

mod ast_analyzer;
mod evm_analyzer;
mod llm_analyzer;
mod solana_tester;

use ast_analyzer::AstAnalyzer;
use llm_analyzer::LLMAnalyzer;
use solana_tester::SolanaProgramTester;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Vulnerability {
    rule_id: String,
    vuln_type: String,
    severity: String,
    message: String,
    mitigation: Option<String>,
    line_number: usize,
    code_snippet: String,
    file_path: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Rule {
    id: String,
    description: String,
    severity: String,
    patterns: Vec<String>,
    enabled: bool,
    mitigation: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct AnalysisMode {
    regex: bool,
    ast: bool,
    llm: bool,
}

#[derive(Deserialize, Debug)]
struct Config {
    rules: Vec<Rule>,
    analysis_mode: Option<AnalysisMode>,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "DFB Solana + EVM Security Audit POC",
    long_about = None
)]
struct Args {
    #[command(flatten)]
    solana: SolanaArgs,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze Solidity/EVM targets (beta)
    Evm(EvmArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct SolanaArgs {
    /// Path to Rust file to analyze (default: stdin)
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Read from stdin instead of file
    #[arg(short, long)]
    stdin: bool,

    /// Path to rules.toml (default: ./rules.toml)
    #[arg(short, long, default_value = "rules.toml")]
    rules: PathBuf,

    /// Test with real Solana programs
    #[arg(long)]
    test_programs: bool,

    /// Use LLM analysis (requires API keys)
    #[arg(long)]
    use_llm: bool,

    /// Use AST analysis
    #[arg(long)]
    use_ast: bool,
}

#[derive(ClapArgs, Debug)]
struct EvmArgs {
    /// Root of the Solidity project (defaults to current dir)
    #[arg(long)]
    repo: Option<PathBuf>,

    /// Comma-separated Solidity targets relative to repo (or absolute paths)
    #[arg(long, value_delimiter = ',')]
    targets: Vec<String>,

    /// Include every .sol/.json file under these directories (recursive)
    #[arg(long = "target-dir", value_delimiter = ',')]
    target_dirs: Vec<PathBuf>,

    /// Path to rules.toml (default: ./rules_evm.toml)
    #[arg(long, default_value = "rules_evm.toml")]
    rules: PathBuf,

    /// Use LLM analysis (requires API keys)
    #[arg(long)]
    use_llm: bool,

    /// Use AST analysis (experimental)
    #[arg(long)]
    use_ast: bool,

    /// Read Solidity source from stdin (useful for quick scans)
    #[arg(long)]
    stdin: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();

    let args = Args::parse();

    if let Some(command) = args.command {
        match command {
            Commands::Evm(evm_args) => {
                return run_evm(evm_args).await;
            }
        }
    }

    run_solana(args.solana).await
}

async fn run_solana(args: SolanaArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Handle test programs mode
    if args.test_programs {
        return test_solana_programs().await;
    }

    // Load rules config
    let mut config_str = String::new();
    let mut rules_file = File::open(&args.rules)?;
    rules_file.read_to_string(&mut config_str)?;
    let config: Config = from_str(&config_str)?;

    // Determine analysis modes
    let analysis_mode = config.analysis_mode.unwrap_or(AnalysisMode {
        regex: true,
        ast: args.use_ast,
        llm: args.use_llm,
    });

    // Load code
    let code = if let Some(file_path) = &args.file {
        fs::read_to_string(file_path)?
    } else if args.stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        input
    } else {
        return Err("Provide --file or --stdin".into());
    };

    let file_path = args.file.as_ref().map(|p| p.to_string_lossy().to_string());
    let mut all_vulnerabilities = Vec::new();
    let regex_rules = build_active_patterns(&config.rules);

    // Regex analysis
    if analysis_mode.regex && !regex_rules.is_empty() {
        let regex_vulns = analyze_code(&code, &regex_rules, file_path.clone());
        let regex_count = regex_vulns.len();
        all_vulnerabilities.extend(regex_vulns);
        println!("🔍 Regex analysis: {} vulnerabilities found", regex_count);
    }

    // AST analysis
    if analysis_mode.ast {
        let mut ast_analyzer = AstAnalyzer::new(file_path.clone());
        let ast_vulns = ast_analyzer.analyze(&code);
        let ast_count = ast_vulns.len();
        all_vulnerabilities.extend(ast_vulns);
        println!("🌳 AST analysis: {} vulnerabilities found", ast_count);
    }

    // LLM analysis
    if analysis_mode.llm {
        let llm_analyzer = LLMAnalyzer::new();
        if llm_analyzer.has_api_keys() {
            match llm_analyzer
                .analyze_with_openai(&code, "Solana program security analysis")
                .await
            {
                Ok(llm_vulns) => {
                    let llm_count = llm_vulns.len();
                    all_vulnerabilities.extend(llm_vulns);
                    println!("🤖 LLM analysis: {} vulnerabilities found", llm_count);
                }
                Err(e) => eprintln!("LLM analysis failed: {}", e),
            }
        } else {
            eprintln!(
                "⚠️ LLM analysis requested but no API keys found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variables."
            );
        }
    }

    // Output results
    let json_output = serde_json::to_string_pretty(&all_vulnerabilities)?;
    println!("{}", json_output);

    if !all_vulnerabilities.is_empty() {
        println!(
            "\n🚨 Total: {} vulnerabilities found. Review and fix!",
            all_vulnerabilities.len()
        );
    } else {
        println!("\n✅ No vulnerabilities detected.");
    }

    Ok(())
}

async fn run_evm(args: EvmArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut config_str = String::new();
    let mut rules_file = File::open(&args.rules)?;
    rules_file.read_to_string(&mut config_str)?;
    let config: Config = from_str(&config_str)?;

    let analysis_mode = config.analysis_mode.unwrap_or(AnalysisMode {
        regex: true,
        ast: args.use_ast,
        llm: args.use_llm,
    });

    let base_dir = if let Some(repo) = args.repo {
        repo
    } else {
        std::env::current_dir()?
    };
    let base_dir = fs::canonicalize(&base_dir).unwrap_or(base_dir);
    let import_settings = detect_evm_import_settings(&base_dir);

    let sources = load_evm_sources(&base_dir, &args.targets, &args.target_dirs, args.stdin)?;
    if sources.is_empty() {
        return Err("Provide --targets or --stdin for evm command".into());
    }

    let regex_rules = build_active_patterns(&config.rules);
    let rules_map: Arc<HashMap<String, Rule>> = Arc::new(
        config
            .rules
            .iter()
            .cloned()
            .map(|r| (r.id.clone(), r))
            .collect(),
    );

    let mut all_vulnerabilities = Vec::new();

    for source in &sources {
        if analysis_mode.regex && !regex_rules.is_empty() {
            let regex_vulns = analyze_code(&source.code, &regex_rules, source.file_path.clone());
            println!(
                "🔍 Regex analysis ({}): {} vulnerabilities found",
                source.display_name(),
                regex_vulns.len()
            );
            all_vulnerabilities.extend(regex_vulns);
        }

        let is_json = source.is_json();

        if analysis_mode.ast && !is_json {
            let mut solidity_analyzer = evm_analyzer::SolidityAstAnalyzer::new(
                Arc::clone(&rules_map),
                source.file_path.clone(),
                Some(base_dir.clone()),
                import_settings.include_paths.clone(),
                import_settings.remappings.clone(),
                import_settings.solc_version.clone(),
            );
            let ast_vulns = solidity_analyzer.analyze(&source.code)?;
            println!(
                "🌿 Solidity AST analysis ({}): {} vulnerabilities found",
                source.display_name(),
                ast_vulns.len()
            );
            all_vulnerabilities.extend(ast_vulns);
        } else if analysis_mode.ast && is_json {
            if let Some(path) = &source.file_path {
                eprintln!(
                    "⚠️ Skipping AST analysis for ABI/JSON artifact ({}). Provide Solidity source for AST checks.",
                    path
                );
            }
        }

        if analysis_mode.llm {
            let llm_analyzer = LLMAnalyzer::new();
            if llm_analyzer.has_api_keys() {
                match llm_analyzer
                    .analyze_with_openai(&source.code, "Solidity smart contract security analysis")
                    .await
                {
                    Ok(llm_vulns) => {
                        println!(
                            "🤖 LLM analysis ({}): {} vulnerabilities found",
                            source.display_name(),
                            llm_vulns.len()
                        );
                        all_vulnerabilities.extend(llm_vulns);
                    }
                    Err(e) => eprintln!("LLM analysis failed for {}: {}", source.display_name(), e),
                }
            } else {
                eprintln!(
                    "⚠️ LLM analysis requested but no API keys found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variables."
                );
            }
        }
    }

    let json_output = serde_json::to_string_pretty(&all_vulnerabilities)?;
    println!("{}", json_output);

    if !all_vulnerabilities.is_empty() {
        println!(
            "\n🚨 Total: {} vulnerabilities found across Solidity targets. Review and fix!",
            all_vulnerabilities.len()
        );
    } else {
        println!("\n✅ No vulnerabilities detected in Solidity targets.");
    }

    Ok(())
}

struct SourceBlob {
    code: String,
    file_path: Option<String>,
}

impl SourceBlob {
    fn display_name(&self) -> String {
        self.file_path
            .clone()
            .unwrap_or_else(|| "stdin".to_string())
    }

    fn is_json(&self) -> bool {
        self.file_path
            .as_deref()
            .map(|path| path.to_ascii_lowercase().ends_with(".json"))
            .unwrap_or(false)
    }
}

fn load_evm_sources(
    base_dir: &Path,
    targets: &[String],
    target_dirs: &[PathBuf],
    stdin: bool,
) -> Result<Vec<SourceBlob>, Box<dyn std::error::Error>> {
    let mut sources = Vec::new();
    let mut seen = HashSet::new();

    for dir in target_dirs {
        let full_dir = if dir.is_absolute() {
            dir.clone()
        } else {
            base_dir.join(dir)
        };
        collect_sources_from_dir(&full_dir, &mut sources, &mut seen)?;
    }

    for target in targets {
        let target_path = Path::new(target);
        let full_path = if target_path.is_absolute() {
            target_path.to_path_buf()
        } else {
            base_dir.join(target_path)
        };

        if !full_path.exists() {
            return Err(format!("Target path not found: {}", full_path.display()).into());
        }

        if full_path.is_dir() {
            collect_sources_from_dir(&full_path, &mut sources, &mut seen)?;
        } else {
            add_source_file(&full_path, &mut sources, &mut seen)?;
        }
    }

    if stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        if !input.trim().is_empty() {
            sources.push(SourceBlob {
                code: input,
                file_path: None,
            });
        }
    }

    Ok(sources)
}

#[derive(Clone, Debug, Default)]
struct EvmImportSettings {
    include_paths: Vec<PathBuf>,
    remappings: Vec<String>,
    solc_version: Option<String>,
}

fn detect_evm_import_settings(base_dir: &Path) -> EvmImportSettings {
    let mut include_paths = Vec::new();
    let mut remappings = Vec::new();

    for candidate in [
        "lib",
        "node_modules",
        "dependencies",
        "vendor",
        "third_party",
    ] {
        add_include_path(base_dir.join(candidate), &mut include_paths);
    }

    let mut solc_version = None;

    if let Some(profile) = read_foundry_profile(base_dir) {
        if let Some(libs) = profile.get("libs").and_then(|v| v.as_array()) {
            for lib in libs {
                if let Some(lib_str) = lib.as_str() {
                    add_include_path(base_dir.join(lib_str), &mut include_paths);
                }
            }
        }
        if let Some(remap_values) = profile.get("remappings").and_then(|v| v.as_array()) {
            for remap in remap_values {
                if let Some(remap_str) = remap.as_str() {
                    let trimmed = remap_str.trim();
                    if !trimmed.is_empty() {
                        remappings.push(trimmed.to_string());
                    }
                }
            }
        }
        if let Some(version) = profile.get("solc_version").and_then(|v| v.as_str()) {
            let trimmed = version.trim();
            if !trimmed.is_empty() {
                solc_version = Some(trimmed.to_string());
            }
        }
    }

    load_remappings_file(&base_dir.join("remappings.txt"), &mut remappings);

    EvmImportSettings {
        include_paths: dedup_paths(include_paths),
        remappings: dedup_strings(remappings),
        solc_version,
    }
}

fn add_include_path(path: PathBuf, acc: &mut Vec<PathBuf>) {
    if path.exists() && path.is_dir() {
        match path.canonicalize() {
            Ok(canon) => acc.push(canon),
            Err(_) => acc.push(path),
        }
    }
}

fn read_foundry_profile(base_dir: &Path) -> Option<toml::Value> {
    let path = base_dir.join("foundry.toml");
    let contents = fs::read_to_string(path).ok()?;
    let parsed: toml::Value = contents.parse().ok()?;
    parsed.get("profile")?.get("default").cloned()
}

fn load_remappings_file(path: &Path, remappings: &mut Vec<String>) {
    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        remappings.push(trimmed.to_string());
    }
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for path in paths {
        let key = path.to_string_lossy().to_string();
        if seen.insert(key) {
            deduped.push(path);
        }
    }
    deduped
}

fn dedup_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            deduped.push(value);
        }
    }
    deduped
}

fn collect_sources_from_dir(
    dir: &Path,
    sources: &mut Vec<SourceBlob>,
    seen: &mut HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !dir.exists() {
        return Err(format!("Directory not found: {}", dir.display()).into());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_sources_from_dir(&path, sources, seen)?;
        } else {
            add_source_file(&path, sources, seen)?;
        }
    }
    Ok(())
}

fn add_source_file(
    path: &Path,
    sources: &mut Vec<SourceBlob>,
    seen: &mut HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !is_supported_evm_file(path) {
        return Ok(());
    }

    let canonical = canonical_string(path);
    if !seen.insert(canonical.clone()) {
        return Ok(());
    }

    let code = fs::read_to_string(path)?;
    sources.push(SourceBlob {
        code,
        file_path: Some(canonical),
    });
    Ok(())
}

fn is_supported_evm_file(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("sol") || ext.eq_ignore_ascii_case("json") => true,
        _ => false,
    }
}

fn canonical_string(path: &Path) -> String {
    path.canonicalize()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

async fn test_solana_programs() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing with real Solana programs...");

    let mut tester = SolanaProgramTester::new()?;
    let vulnerabilities = tester.test_popular_programs().await?;

    println!("\n📊 Test Results:");
    println!("Programs tested: {}", tester.get_program_paths().len());
    println!("Total vulnerabilities found: {}", vulnerabilities.len());

    // Group vulnerabilities by severity
    let mut severity_counts = std::collections::HashMap::new();
    for vuln in &vulnerabilities {
        *severity_counts.entry(&vuln.severity).or_insert(0) += 1;
    }

    println!("\nSeverity breakdown:");
    for (severity, count) in severity_counts {
        println!("  {}: {}", severity, count);
    }

    // Output detailed results
    let json_output = serde_json::to_string_pretty(&vulnerabilities)?;
    println!("\nDetailed results:");
    println!("{}", json_output);

    Ok(())
}

fn analyze_code(
    code: &str,
    active_patterns: &[(&Rule, Regex)],
    file_path: Option<String>,
) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let lines: Vec<&str> = code.lines().collect();

    for (rule, re) in active_patterns {
        vulns.extend(find_matches(&lines, re, rule, &file_path));
    }

    vulns
}

fn build_active_patterns<'a>(rules: &'a [Rule]) -> Vec<(&'a Rule, Regex)> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| {
            let pattern = r.patterns.first()?;
            let re = Regex::new(pattern).ok()?;
            Some((r, re))
        })
        .collect()
}

fn find_matches(
    lines: &[&str],
    re: &Regex,
    rule: &Rule,
    file_path: &Option<String>,
) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if re.is_match(line) {
            vulns.push(Vulnerability {
                rule_id: rule.id.clone(),
                vuln_type: rule.id.clone(), // Reuse ID for type; customize if needed
                severity: rule.severity.clone(),
                message: rule.description.clone(),
                mitigation: rule.mitigation.clone(),
                line_number: i + 1,
                code_snippet: line.trim().to_string(),
                file_path: file_path.clone(),
            });
        }
    }
    vulns
}
