use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntentError {
    #[error("xre parse error in grammar {grammar}: {detail}")]
    GrammarParse { grammar: &'static str, detail: String },
    #[error("unsupported xre construct in grammar {grammar}: {detail} — this compiler deliberately \
             only handles Symbol/Concatenate/Union/Optional/Group (see lib.rs doc comment for why)")]
    UnsupportedConstruct { grammar: &'static str, detail: String },
    #[error("fst construction error: {0}")]
    Fst(String),
}
