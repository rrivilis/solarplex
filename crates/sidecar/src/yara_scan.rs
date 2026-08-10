use std::sync::OnceLock;

static RULES: OnceLock<yara_x::Rules> = OnceLock::new();

const STARTER_RULES: &str = r####"
rule prompt_injection {
    meta:
        description = "Common LLM prompt injection markers"
        verdict     = "suspicious"
    strings:
        $a1 = "ignore previous instructions" ascii nocase
        $a2 = "ignore all previous" ascii nocase
        $a3 = "disregard previous" ascii nocase
        $a4 = "forget your instructions" ascii nocase
        $a5 = "new instructions:" ascii nocase
        $a6 = "system prompt:" ascii nocase
        $a7 = "###instruction" ascii nocase
        $a8 = "<|system|>" ascii nocase
        $a9 = "<|im_start|>" ascii nocase
    condition:
        any of them
}

rule encoded_payload {
    meta:
        description = "Base64-encoded PowerShell or shell payload"
        verdict     = "suspicious"
    strings:
        $ps_enc  = /[Pp]o[Ww][Ee][Rr][Ss][Hh][Ee][Ll]{2}.*-[Ee][Nn][Cc]/
        $b64_dec = /echo\s+[A-Za-z0-9+\/]{40,}.*\|\s*base64/
    condition:
        any of them
}

rule shell_injection {
    meta:
        description = "Shell command injection / reverse-shell patterns"
        verdict     = "suspicious"
    strings:
        $curl_sh  = /curl\s[^|]+\|\s*sh/
        $wget_sh  = /wget\s[^|]+\|\s*sh/
        $nc_rev   = /nc\s[^-]*-e\s*\/bin\/sh/
        $bash_tcp = /bash\s+-i\s*>&\s*\/dev\/tcp/
    condition:
        any of them
}

rule data_exfil {
    meta:
        description = "Data exfiltration indicators"
        verdict     = "suspicious"
    strings:
        $ex1 = "exfiltrate" ascii nocase
        $ex2 = /curl\s+-d\s+.*https?:\/\//
    condition:
        any of them
}
"####;

fn compiled_rules() -> &'static yara_x::Rules {
    RULES.get_or_init(|| {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(STARTER_RULES.as_bytes())
            .expect("built-in YARA rules failed to compile");
        compiler.build()
    })
}

/// Scan `data` against the built-in YARA rules.
/// Returns the names of all matching rules.
pub fn scan_content(data: &[u8]) -> Vec<String> {
    let rules = compiled_rules();
    let mut scanner = yara_x::Scanner::new(rules);
    match scanner.scan(data) {
        Ok(results) => results
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect(),
        Err(e) => {
            tracing::warn!("YARA scan error: {e}");
            vec![]
        }
    }
}
