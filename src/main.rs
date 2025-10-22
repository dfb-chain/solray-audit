use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::PathBuf;
use toml::from_str;
use dotenv::dotenv;

mod ast_analyzer;
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

#[derive(Deserialize, Serialize, Debug)]
struct Rule {
    id: String,
    description: String,
    severity: String,
    patterns: Vec<String>,
    enabled: bool,
    mitigation: Option<String>,
}

#[derive(Deserialize, Debug)]
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
#[command(author, version, about = "DFB Solana Security Audit POC", long_about = None)]
struct Args {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Load environment variables
    dotenv().ok();

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

    // Regex analysis
    if analysis_mode.regex {
        let active_patterns: Vec<(&Rule, Regex)> = config.rules.iter()
            .filter(|r| r.enabled)
            .filter_map(|r| {
                if !r.patterns.is_empty() {
                    let re = Regex::new(&r.patterns[0]).ok()?;
                    Some((r, re))
                } else {
                    None
                }
            })
            .collect();

        if !active_patterns.is_empty() {
            let lines: Vec<&str> = code.lines().collect();
            let regex_vulns = analyze_code(&lines, &active_patterns, file_path.clone());
            all_vulnerabilities.extend(regex_vulns);
            println!("🔍 Regex analysis: {} vulnerabilities found", all_vulnerabilities.len());
        }
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
            match llm_analyzer.analyze_with_openai(&code, "Solana program security analysis").await {
                Ok(llm_vulns) => {
                    let llm_count = llm_vulns.len();
                    all_vulnerabilities.extend(llm_vulns);
                    println!("🤖 LLM analysis: {} vulnerabilities found", llm_count);
                }
                Err(e) => eprintln!("LLM analysis failed: {}", e),
            }
        } else {
            eprintln!("⚠️ LLM analysis requested but no API keys found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variables.");
        }
    }

    // Output results
    let json_output = serde_json::to_string_pretty(&all_vulnerabilities)?;
    println!("{}", json_output);

    if !all_vulnerabilities.is_empty() {
        println!("\n🚨 Total: {} vulnerabilities found. Review and fix!", all_vulnerabilities.len());
    } else {
        println!("\n✅ No vulnerabilities detected.");
    }

    Ok(())
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
    lines: &[&str],
    active_patterns: &[(&Rule, Regex)],
    file_path: Option<String>,
) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    for (rule, re) in active_patterns {
        vulns.extend(find_matches(lines, re, rule, &file_path));
    }

    vulns
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
                vuln_type: rule.id.clone(),  // Reuse ID for type; customize if needed
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