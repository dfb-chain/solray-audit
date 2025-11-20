use crate::Vulnerability;
use syn::{
    BinOp, Expr, ExprBinary, ExprCall, ExprForLoop, ExprLoop, ExprMethodCall, ExprWhile, ItemFn,
    ItemStruct, spanned::Spanned, visit::Visit,
};

pub struct AstAnalyzer {
    vulnerabilities: Vec<Vulnerability>,
    file_path: Option<String>,
    source_lines: Vec<String>,
}

impl AstAnalyzer {
    pub fn new(file_path: Option<String>) -> Self {
        Self {
            vulnerabilities: Vec::new(),
            file_path,
            source_lines: Vec::new(),
        }
    }

    pub fn analyze(&mut self, code: &str) -> Vec<Vulnerability> {
        // Store source lines for line number mapping
        self.source_lines = code.lines().map(|s| s.to_string()).collect();

        // Parse the Rust code into an AST
        let syntax_tree = match syn::parse_file(code) {
            Ok(ast) => ast,
            Err(e) => {
                eprintln!("Failed to parse Rust code: {}", e);
                return Vec::new();
            }
        };

        // Visit the AST to find vulnerabilities
        self.visit_file(&syntax_tree);

        // Remove duplicates and return
        self.deduplicate_vulnerabilities()
    }

    fn get_line_number(&self, _span: proc_macro2::Span) -> usize {
        // For now, return a placeholder line number
        // In a real implementation, you'd need to map span positions to line numbers
        1
    }

    fn get_code_snippet(&self, _span: proc_macro2::Span) -> String {
        // For now, return a placeholder
        // In a real implementation, you'd extract the actual code snippet
        "code snippet".to_string()
    }

    fn add_vulnerability(
        &mut self,
        rule_id: &str,
        description: &str,
        severity: &str,
        mitigation: Option<&str>,
        span: proc_macro2::Span,
        _context: &str,
    ) {
        let line_number = self.get_line_number(span);
        let code_snippet = self.get_code_snippet(span);

        // Only add if we have a valid line number and code snippet
        if line_number > 0 && !code_snippet.is_empty() && code_snippet != "unknown" {
            self.vulnerabilities.push(Vulnerability {
                rule_id: rule_id.to_string(),
                vuln_type: rule_id.to_string(),
                severity: severity.to_string(),
                message: description.to_string(),
                mitigation: mitigation.map(|s| s.to_string()),
                line_number,
                code_snippet,
                file_path: self.file_path.clone(),
            });
        }
    }

    fn deduplicate_vulnerabilities(&mut self) -> Vec<Vulnerability> {
        // Remove duplicates based on rule_id, line_number, and code_snippet
        let mut seen = std::collections::HashSet::new();
        let mut unique_vulns = Vec::new();

        for vuln in self.vulnerabilities.drain(..) {
            let key = (
                vuln.rule_id.clone(),
                vuln.line_number,
                vuln.code_snippet.clone(),
            );
            if seen.insert(key) {
                unique_vulns.push(vuln);
            }
        }

        unique_vulns
    }
}

impl<'ast> Visit<'ast> for AstAnalyzer {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        // Check for dangerous function calls
        if let Expr::Path(path) = &*call.func {
            if let Some(ident) = path.path.get_ident() {
                match ident.to_string().as_str() {
                    "invoke" | "invoke_signed" => {
                        self.check_cpi_vulnerabilities(call);
                    }
                    "transfer" | "transfer_checked" => {
                        self.check_transfer_vulnerabilities(call);
                    }
                    "try_from_slice" | "from_bytes" => {
                        self.check_deserialization_vulnerabilities(call);
                    }
                    "create_program_address" => {
                        self.check_pda_vulnerabilities(call);
                    }
                    _ => {}
                }
            }
        }

        // Continue visiting
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, method_call: &'ast ExprMethodCall) {
        // Check for dangerous method calls
        match method_call.method.to_string().as_str() {
            "invoke" | "invoke_signed" => {
                self.check_cpi_vulnerabilities_method(method_call);
            }
            "transfer" | "transfer_checked" => {
                self.check_transfer_vulnerabilities_method(method_call);
            }
            _ => {}
        }

        syn::visit::visit_expr_method_call(self, method_call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        // Check for arithmetic operations without overflow protection
        match binary.op {
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) | BinOp::Div(_) => {
                self.check_arithmetic_vulnerabilities(binary);
            }
            _ => {}
        }

        syn::visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_loop(&mut self, loop_expr: &'ast ExprLoop) {
        // Check for unbounded loops (DoS via compute budget)
        self.check_unbounded_loop_vulnerabilities(loop_expr);
        syn::visit::visit_expr_loop(self, loop_expr);
    }

    fn visit_expr_while(&mut self, while_expr: &'ast ExprWhile) {
        // Check for unbounded while loops
        self.check_unbounded_while_vulnerabilities(while_expr);
        syn::visit::visit_expr_while(self, while_expr);
    }

    fn visit_expr_for_loop(&mut self, for_loop: &'ast ExprForLoop) {
        // Check for unbounded for loops
        self.check_unbounded_for_vulnerabilities(for_loop);
        syn::visit::visit_expr_for_loop(self, for_loop);
    }

    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Check for recursive functions (reentrancy-adjacent) - but be more selective
        self.check_recursive_function_vulnerabilities(func);
        syn::visit::visit_item_fn(self, func);
    }

    fn visit_item_struct(&mut self, struct_item: &'ast ItemStruct) {
        // Check for missing discriminators in structs - but be more selective
        self.check_struct_discriminator_vulnerabilities(struct_item);
        syn::visit::visit_item_struct(self, struct_item);
    }
}

impl AstAnalyzer {
    fn check_cpi_vulnerabilities(&mut self, call: &ExprCall) {
        // Flag CPI calls - they need careful review
        self.add_vulnerability(
            "S-1001",
            "Cross-Program Invocation: CPI call detected - verify program whitelist and signer validation",
            "high",
            Some("Ensure program is whitelisted and proper signer validation"),
            call.span(),
            "invoke/invoke_signed call"
        );
    }

    fn check_cpi_vulnerabilities_method(&mut self, method_call: &ExprMethodCall) {
        // Flag CPI method calls
        self.add_vulnerability(
            "S-1001",
            "Cross-Program Invocation: CPI method call detected - verify program whitelist and signer validation",
            "high",
            Some("Ensure program is whitelisted and proper signer validation"),
            method_call.span(),
            "invoke/invoke_signed method call"
        );
    }

    fn check_transfer_vulnerabilities(&mut self, call: &ExprCall) {
        // Flag transfer calls - they need careful review
        self.add_vulnerability(
            "S-1002",
            "Transfer Operation: Transfer call detected - verify ownership and signer validation",
            "high",
            Some("Verify account ownership and signer validation before transfer"),
            call.span(),
            "transfer call",
        );
    }

    fn check_transfer_vulnerabilities_method(&mut self, method_call: &ExprMethodCall) {
        // Flag transfer method calls
        self.add_vulnerability(
            "S-1002",
            "Transfer Operation: Transfer method call detected - verify ownership and signer validation",
            "high",
            Some("Verify account ownership and signer validation before transfer"),
            method_call.span(),
            "transfer method call"
        );
    }

    fn check_arithmetic_vulnerabilities(&mut self, binary: &ExprBinary) {
        // Flag arithmetic operations - they need careful review for overflow
        self.add_vulnerability(
            "S-1003",
            "Arithmetic Operation: Unchecked arithmetic detected - verify overflow protection",
            "critical",
            Some("Use checked_* methods or enable overflow-checks in Cargo.toml"),
            binary.span(),
            "arithmetic operation",
        );
    }

    fn check_deserialization_vulnerabilities(&mut self, call: &ExprCall) {
        // Flag deserialization calls
        self.add_vulnerability(
            "S-2012",
            "Deserialization: Direct deserialization detected - verify input validation",
            "critical",
            Some("Validate input data before deserialization"),
            call.span(),
            "try_from_slice/from_bytes call",
        );
    }

    fn check_pda_vulnerabilities(&mut self, call: &ExprCall) {
        // Flag PDA creation calls
        self.add_vulnerability(
            "S-2015",
            "PDA Creation: create_program_address detected - verify canonical bump usage",
            "medium",
            Some("Use find_program_address for canonical bumps"),
            call.span(),
            "create_program_address call",
        );
    }

    fn check_unbounded_loop_vulnerabilities(&mut self, loop_expr: &ExprLoop) {
        // Flag infinite loops
        self.add_vulnerability(
            "S-2036",
            "Infinite Loop: Unbounded loop detected - verify termination conditions",
            "high",
            Some("Add loop bounds and compute budget checks"),
            loop_expr.span(),
            "unbounded loop",
        );
    }

    fn check_unbounded_while_vulnerabilities(&mut self, while_expr: &ExprWhile) {
        // Flag potentially unbounded while loops
        self.add_vulnerability(
            "S-2036",
            "While Loop: While loop detected - verify termination conditions",
            "medium",
            Some("Ensure while loop has proper termination conditions"),
            while_expr.span(),
            "while loop",
        );
    }

    fn check_unbounded_for_vulnerabilities(&mut self, for_loop: &ExprForLoop) {
        // Flag for loops (generally safer but still worth reviewing)
        self.add_vulnerability(
            "S-2036",
            "For Loop: For loop detected - verify iteration bounds",
            "low",
            Some("Ensure for loop has reasonable iteration bounds"),
            for_loop.span(),
            "for loop",
        );
    }

    fn check_recursive_function_vulnerabilities(&mut self, func: &ItemFn) {
        // Flag function definitions (potential recursion)
        self.add_vulnerability(
            "S-2035",
            "Function Definition: Function detected - verify no recursion issues",
            "low",
            Some("Ensure function doesn't have recursion depth issues"),
            func.span(),
            "function definition",
        );
    }

    fn check_struct_discriminator_vulnerabilities(&mut self, struct_item: &ItemStruct) {
        // Flag struct definitions (potential account confusion)
        self.add_vulnerability(
            "S-2002",
            "Struct Definition: Struct detected - verify discriminator usage",
            "medium",
            Some("Ensure structs have proper discriminators if used as accounts"),
            struct_item.span(),
            "struct definition",
        );
    }
}
