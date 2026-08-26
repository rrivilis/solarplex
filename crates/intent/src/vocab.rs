//! Word ↔ arc-label table, shared between grammar compilation and runtime
//! tokenization so both sides agree on what integer a given word means.
//! Label 0 is reserved for epsilon (OpenFst/rustfst convention).

use std::collections::HashMap;

pub type Label = u32;
pub const EPSILON: Label = 0;

#[derive(Default)]
pub struct Vocab {
    word_to_label: HashMap<String, Label>,
    next: Label,
}

impl Vocab {
    pub fn new() -> Self {
        Vocab {
            word_to_label: HashMap::new(),
            next: 1,
        }
    }

    /// Get-or-create a label for `word` (case-insensitive).
    pub fn intern(&mut self, word: &str) -> Label {
        let key = word.to_lowercase();
        if let Some(&l) = self.word_to_label.get(&key) {
            return l;
        }
        let l = self.next;
        self.next += 1;
        self.word_to_label.insert(key, l);
        l
    }

    /// Look up a word's label without creating one — used at match time so
    /// an input word never in any grammar simply fails to match anything,
    /// rather than silently growing the vocab.
    pub fn lookup(&self, word: &str) -> Option<Label> {
        self.word_to_label.get(&word.to_lowercase()).copied()
    }
}
