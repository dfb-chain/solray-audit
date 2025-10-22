# Solray Audit - Advanced Solana Security Scanner

A comprehensive security audit tool for Solana programs with **Sec3 X-Ray compatible** vulnerability detection, featuring multiple analysis modes including regex patterns, AST parsing, and LLM-powered analysis.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Sec3 Compatible](https://img.shields.io/badge/Sec3-X--Ray%20Compatible-blue.svg)](https://www.sec3.dev/)

> **Note**: This tool provides balanced vulnerability detection - flagging real security concerns while minimizing false positives. It's designed to complement professional security audits, not replace them.

## Features

### 🔍 Multi-Mode Analysis
- **Regex Analysis**: Fast pattern-based vulnerability detection with 50+ Sec3 patterns
- **AST Analysis**: Deep code structure analysis using Rust's syn crate with balanced detection
- **LLM Analysis**: AI-powered vulnerability detection using OpenAI GPT-4 or Anthropic Claude

### 🧪 Real Program Testing
- Test against popular Solana programs
- Mock vulnerable programs with Sec3 vulnerability patterns
- Comprehensive vulnerability reporting with severity breakdown

### 🛡️ Comprehensive Security Rules (Sec3 X-Ray Compatible)
**Core Security Issues:**
- Account validation (signer checks, ownership, rent exemption)
- Cross-program invocation (CPI) security
- Arithmetic vulnerabilities (overflow/underflow, precision loss)
- Account data confusion and type cosplay
- PDA security and bump seed validation
- Token operations and authority management
- DoS attacks (compute budget, account size growth)
- Economic attacks (front-running, sandwich attacks, flash loans)
- State management and reentrancy patterns

**Advanced Patterns:**
- Unsafe Rust usage and memory safety
- Oracle manipulation and staleness checks
- Sysvar validation and trust assumptions
- Account duplication/aliasing across CPI
- Time/slot drift in calculations
- Dependency vulnerabilities and supply chain issues

## Installation

### From Source
```bash
git clone https://github.com/dfb-chain/solray-audit.git
cd solray-audit
cargo build --release
cargo install --path .
```

### Quick Install
```bash
cargo install --git https://github.com/dfb-chain/solray-audit.git
```

## Usage

### Basic Analysis
```bash
# Analyze a single file (balanced detection)
solray-audit --file programs/my-program/src/lib.rs

# Analyze from stdin
cat programs/my-program/src/lib.rs | solray-audit --stdin

# Use AST analysis for deeper detection
solray-audit --file programs/my-program/src/lib.rs --use-ast

# Use LLM analysis (requires API key)
solray-audit --file programs/my-program/src/lib.rs --use-llm
```

### Testing with Real Programs
```bash
# Test against popular Solana programs with Sec3 patterns
solray-audit --test-programs

# Test with specific analysis modes
solray-audit --test-programs --use-ast --use-llm
```

### Environment Setup for LLM Analysis

Create a `.env` file with your API keys:

```bash
# For OpenAI GPT-4
OPENAI_API_KEY=your_openai_api_key_here

# For Anthropic Claude
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

Get API keys from:
- OpenAI: https://platform.openai.com/api-keys
- Anthropic: https://console.anthropic.com/

## Configuration

Edit `rules.toml` to customize analysis modes and rules. The tool includes **50+ Sec3 X-Ray compatible vulnerability patterns**:

```toml
[analysis_mode]
regex = true    # Enable regex pattern matching (50+ Sec3 patterns)
ast = true      # Enable AST analysis
llm = false     # Enable LLM analysis (requires API keys)

# Example Sec3 vulnerability patterns
[[rules]]
id = "S-2002"
description = "Account Data Confusion: Wrong account type deserialization without discriminator check"
severity = "critical"
patterns = ["Account<'info, \\w+>.*?(?<!discriminator|discriminator::check)"]
enabled = true
mitigation = "Add discriminator checks before deserialization"

[[rules]]
id = "S-2036"
description = "DoS via Compute Budget: Unbounded loops causing griefing"
severity = "high"
patterns = ["(loop|while|for).*?(?<!limit|bound)"]
enabled = true
mitigation = "Add loop bounds and compute budget checks"
```

## Analysis Modes

### Regex Analysis
- Fast pattern matching with **50+ Sec3 X-Ray patterns**
- Configurable rules in `rules.toml`
- Covers comprehensive vulnerability taxonomy
- Includes critical, high, medium, and low severity issues

### AST Analysis (Balanced Detection)
- Deep code structure analysis using Rust's syn crate
- **Balanced approach**: Flags real security concerns while minimizing false positives
- Detects critical patterns: CPI calls, arithmetic operations, deserialization, loops
- Provides actionable security guidance for each finding

### LLM Analysis
- AI-powered vulnerability detection with Sec3 knowledge
- Context-aware analysis using comprehensive prompts
- Can detect novel vulnerability patterns
- Requires API keys and internet connection

## Balanced Detection Philosophy

Solray Audit uses a **balanced detection approach** that:

✅ **Flags Real Issues**: Detects actual security vulnerabilities like:
- Cross-program invocations (CPI) without proper validation
- Unchecked arithmetic operations
- Direct deserialization without validation
- Unbounded loops and recursion

❌ **Minimizes False Positives**: Avoids flagging:
- Normal Anchor framework usage
- Properly validated operations
- Standard Rust patterns

🎯 **Provides Actionable Guidance**: Each finding includes:
- Clear description of the security concern
- Specific mitigation recommendations
- Severity classification (critical/high/medium/low)

## Output Format

Results are returned in JSON format:

```json
[
  {
    "ruleId": "S-1001",
    "vulnType": "Missing Signer Check",
    "severity": "high",
    "message": "Missing Signer Check: Fails to verify if an account signed the transaction",
    "mitigation": "Check AccountInfo::is_signer",
    "lineNumber": 42,
    "codeSnippet": "invoke(&instruction, &accounts)",
    "filePath": "src/lib.rs"
  }
]
```

## Examples

### Testing Vulnerable Code
```rust
use anchor_lang::prelude::*;

#[program]
pub mod vulnerable {
    use super::*;

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        // VULNERABILITY: Missing signer check
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;
        
        // VULNERABILITY: Unchecked arithmetic
        from.balance -= amount;
        to.balance += amount;
        
        Ok(())
    }
}
```

Running analysis:
```bash
cargo run -- --file vulnerable.rs --use-ast --use-llm
```

## Sec3 X-Ray Compatibility

This tool implements **Sec3's comprehensive vulnerability taxonomy** with 55+ vulnerability patterns:

- **Core Security Issues**: Account validation, CPI security, arithmetic vulnerabilities, account data confusion, PDA security, token operations, authority management, DoS attacks, economic attacks, state management
- **Advanced Patterns**: Unsafe Rust usage, oracle manipulation, sysvar validation, account duplication, time/slot drift, dependency vulnerabilities
- **Compatible with Sec3 X-Ray**: Uses the same vulnerability classification and detection patterns

## Contributing

We welcome contributions to improve Solray Audit! Here's how you can help:

### 🐛 Bug Reports
- Report false positives or missed vulnerabilities
- Include code samples and expected behavior
- Use GitHub Issues with proper labels

### 🔧 Feature Requests
- Suggest new vulnerability patterns
- Propose improvements to detection accuracy
- Request new analysis modes or integrations

### 💻 Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add new vulnerability patterns or analysis modes
4. Test your changes thoroughly
5. Submit a pull request

### 📋 Development Guidelines
- Follow Rust best practices and clippy suggestions
- Add tests for new vulnerability patterns
- Update documentation for new features
- Ensure balanced detection (avoid false positives)

## Project Status

**Current Version**: v0.1.0  
**Status**: Active Development  
**Maintainer**: DFB Chain Team  

### Roadmap
- [ ] Improved line number detection
- [ ] Enhanced code snippet extraction
- [ ] More sophisticated AST analysis
- [ ] Integration with popular Solana IDEs
- [ ] CI/CD pipeline integration

## License

MIT License - see [LICENSE](LICENSE) file for details

## Acknowledgments

- **Sec3**: For the comprehensive vulnerability taxonomy and X-Ray toolchain
- **Helius**: For Solana security best practices
- **Cantina**: For security research and patterns
- **SlowMist**: For Solana security guidelines
- **Anchor Team**: For the amazing Solana framework
