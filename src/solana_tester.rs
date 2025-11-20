use crate::{AstAnalyzer, LLMAnalyzer, Vulnerability};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

pub struct SolanaProgramTester {
    temp_dir: TempDir,
    programs: HashMap<String, String>, // name -> path
}

impl SolanaProgramTester {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        Ok(Self {
            temp_dir,
            programs: HashMap::new(),
        })
    }

    pub async fn test_popular_programs(
        &mut self,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let mut all_vulnerabilities = Vec::new();

        // Test popular Solana programs
        let programs_to_test = vec![
            (
                "anchor-examples",
                "https://github.com/coral-xyz/anchor/tree/master/examples",
            ),
            (
                "solana-program-library",
                "https://github.com/solana-labs/solana-program-library",
            ),
            (
                "metaplex-program-library",
                "https://github.com/metaplex-foundation/metaplex-program-library",
            ),
            ("raydium-amm", "https://github.com/raydium-io/raydium-amm"),
            ("orca-whirlpools", "https://github.com/orca-so/whirlpools"),
        ];

        for (name, url) in programs_to_test {
            println!("Testing {}...", name);
            match self.clone_and_analyze_program(name, url).await {
                Ok(vulns) => {
                    println!("Found {} vulnerabilities in {}", vulns.len(), name);
                    all_vulnerabilities.extend(vulns);
                }
                Err(e) => {
                    eprintln!("Failed to test {}: {}", name, e);
                }
            }
        }

        Ok(all_vulnerabilities)
    }

    async fn clone_and_analyze_program(
        &mut self,
        name: &str,
        _url: &str,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let program_path = self.temp_dir.path().join(name);

        // Clone the repository
        if program_path.exists() {
            fs::remove_dir_all(&program_path)?;
        }

        // For demo purposes, we'll create a mock program structure
        // In a real implementation, you'd clone the actual repositories
        self.create_mock_solana_program(&program_path, name)?;

        self.programs
            .insert(name.to_string(), program_path.to_string_lossy().to_string());

        // Analyze the program
        self.analyze_program_directory(&program_path).await
    }

    fn create_mock_solana_program(
        &self,
        path: &Path,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(path)?;

        // Create a mock program with common vulnerabilities
        let mock_code = match name {
            "anchor-examples" => self.create_mock_anchor_program(),
            "raydium-amm" => self.create_mock_amm_program(),
            "orca-whirlpools" => self.create_mock_pool_program(),
            _ => self.create_generic_mock_program(),
        };

        fs::write(path.join("lib.rs"), mock_code)?;
        Ok(())
    }

    fn create_mock_anchor_program(&self) -> String {
        r#"use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod example {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let account = &mut ctx.accounts.account;
        account.data = 0;
        Ok(())
    }

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        // VULNERABILITY: Missing signer check
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;
        
        // VULNERABILITY: Unchecked arithmetic
        from.balance -= amount;
        to.balance += amount;
        
        Ok(())
    }

    pub fn invoke_external(ctx: Context<InvokeExternal>) -> Result<()> {
        // VULNERABILITY: Arbitrary CPI without program validation
        let cpi_program = ctx.accounts.external_program.to_account_info();
        let cpi_accounts = vec![];
        
        anchor_lang::solana_program::program::invoke(
            &anchor_lang::solana_program::instruction::Instruction {
                program_id: cpi_program.key(),
                accounts: vec![],
                data: vec![],
            },
            &[cpi_program],
        )?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 8)]
    pub account: Account<'info, DataAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, DataAccount>,
    #[account(mut)]
    pub to: Account<'info, DataAccount>,
}

#[derive(Accounts)]
pub struct InvokeExternal<'info> {
    pub external_program: AccountInfo<'info>,
}

#[account]
pub struct DataAccount {
    pub data: u64,
    pub balance: u64,
}
"#
        .to_string()
    }

    fn create_mock_amm_program(&self) -> String {
        r#"use anchor_lang::prelude::*;

declare_id!("AMM1111111111111111111111111111111111111");

#[program]
pub mod amm {
    use super::*;

    pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // VULNERABILITY: Precision loss - division before multiplication
        let amount_out = amount_in / pool.reserve_in * pool.reserve_out;
        
        // VULNERABILITY: Missing frontrunning protection
        pool.reserve_in += amount_in;
        pool.reserve_out -= amount_out;
        
        Ok(())
    }

    pub fn add_liquidity(ctx: Context<AddLiquidity>, amount_a: u64, amount_b: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // VULNERABILITY: Unchecked arithmetic
        pool.reserve_a += amount_a;
        pool.reserve_b += amount_b;
        
        Ok(())
    }

    pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
        // VULNERABILITY: Flash loan without protection
        let pool = &mut ctx.accounts.pool;
        pool.reserve_a -= amount;
        
        // VULNERABILITY: Unbounded loop (DoS via compute budget)
        loop {
            // This could run forever
        }
    }

    pub fn freeze_pool(ctx: Context<FreezePool>) -> Result<()> {
        // VULNERABILITY: Missing freeze authority check
        let pool = &mut ctx.accounts.pool;
        pool.frozen = true;
        Ok(())
    }

    pub fn deserialize_account(ctx: Context<DeserializeAccount>) -> Result<()> {
        // VULNERABILITY: Deserializing before validation
        let account_data = ctx.accounts.account.data.borrow();
        let _parsed: Pool = borsh::BorshDeserialize::try_from_slice(&account_data)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct AddLiquidity<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct FlashLoan<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct FreezePool<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    pub authority: AccountInfo<'info>, // Missing freeze authority check
}

#[derive(Accounts)]
pub struct DeserializeAccount<'info> {
    pub account: AccountInfo<'info>,
}

#[account]
pub struct Pool {
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub reserve_in: u64,
    pub reserve_out: u64,
    pub frozen: bool,
}
"#
        .to_string()
    }

    fn create_mock_pool_program(&self) -> String {
        r#"use anchor_lang::prelude::*;

declare_id!("POOL1111111111111111111111111111111111111");

#[program]
pub mod whirlpool {
    use super::*;

    pub fn initialize_pool(ctx: Context<InitializePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // VULNERABILITY: PDA creation without proper validation
        let (pda, bump) = Pubkey::find_program_address(&[b"pool"], &ctx.program_id);
        pool.pda = pda;
        pool.bump = bump;
        
        Ok(())
    }

    pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // VULNERABILITY: Account confusion - no discriminator check
        let user_account = &ctx.accounts.user;
        
        // VULNERABILITY: Missing account reload after CPI
        anchor_lang::solana_program::program::invoke(
            &anchor_lang::solana_program::instruction::Instruction {
                program_id: ctx.accounts.token_program.key(),
                accounts: vec![],
                data: vec![],
            },
            &[ctx.accounts.token_program.to_account_info()],
        )?;
        
        // Using stale data here
        pool.total_supply += amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(init, payer = user, space = 8 + 32 + 1)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    pub user: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
}

#[account]
pub struct Pool {
    pub pda: Pubkey,
    pub bump: u8,
    pub total_supply: u64,
}
"#
        .to_string()
    }

    fn create_generic_mock_program(&self) -> String {
        r#"use anchor_lang::prelude::*;

declare_id!("GENERIC111111111111111111111111111111111");

#[program]
pub mod generic {
    use super::*;

    pub fn generic_function(ctx: Context<Generic>) -> Result<()> {
        // Generic vulnerable code
        let account = &mut ctx.accounts.account;
        account.data = 42;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Generic<'info> {
    #[account(mut)]
    pub account: Account<'info, GenericAccount>,
}

#[account]
pub struct GenericAccount {
    pub data: u64,
}
"#
        .to_string()
    }

    async fn analyze_program_directory(
        &self,
        path: &Path,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let mut all_vulnerabilities = Vec::new();

        // Find all Rust files
        let rust_files = self.find_rust_files(path)?;

        for file_path in rust_files {
            let code = fs::read_to_string(&file_path)?;
            let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();

            // AST Analysis
            let mut ast_analyzer = AstAnalyzer::new(Some(file_name.clone()));
            let ast_vulns = ast_analyzer.analyze(&code);
            all_vulnerabilities.extend(ast_vulns);

            // LLM Analysis (if API keys are available)
            let llm_analyzer = LLMAnalyzer::new();
            if llm_analyzer.has_api_keys() {
                match llm_analyzer
                    .analyze_with_openai(&code, "Solana program analysis")
                    .await
                {
                    Ok(llm_vulns) => all_vulnerabilities.extend(llm_vulns),
                    Err(e) => eprintln!("LLM analysis failed for {}: {}", file_name, e),
                }
            }
        }

        Ok(all_vulnerabilities)
    }

    fn find_rust_files(
        &self,
        path: &Path,
    ) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
        let mut rust_files = Vec::new();

        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    rust_files.extend(self.find_rust_files(&path)?);
                } else if path.extension().map_or(false, |ext| ext == "rs") {
                    rust_files.push(path);
                }
            }
        }

        Ok(rust_files)
    }

    pub fn get_program_paths(&self) -> &HashMap<String, String> {
        &self.programs
    }
}
