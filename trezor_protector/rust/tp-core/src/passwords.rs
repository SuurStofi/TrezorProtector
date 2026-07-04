//! Password and passphrase generation, plus strength estimation.
//!
//! All randomness comes from the OS CSPRNG. Character selection uses
//! rejection-free uniform sampling (`gen_range`), so there is no modulo bias.

use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?";

#[derive(Clone, Copy)]
pub struct GenerateOptions {
    pub length: usize,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Skip visually ambiguous characters (0/O, 1/l/I, …).
    pub avoid_ambiguous: bool,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self { length: 20, upper: true, digits: true, symbols: true, avoid_ambiguous: false }
    }
}

const AMBIGUOUS: &str = "0O1lI|`'\"";

/// Generate a random password. Guarantees at least one character from each
/// enabled class (when the length allows it).
pub fn generate(opts: &GenerateOptions) -> Result<Zeroizing<String>> {
    if opts.length < 4 || opts.length > 256 {
        return Err(Error::InvalidInput("length must be between 4 and 256".into()));
    }

    let filter = |set: &str| -> Vec<char> {
        set.chars()
            .filter(|c| !opts.avoid_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    };

    let lower = filter("abcdefghijklmnopqrstuvwxyz");
    let mut classes: Vec<Vec<char>> = vec![lower];
    if opts.upper {
        classes.push(filter("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }
    if opts.digits {
        classes.push(filter("0123456789"));
    }
    if opts.symbols {
        classes.push(filter(SYMBOLS));
    }

    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    let mut rng = OsRng;

    // One guaranteed pick per class, rest from the full alphabet.
    let mut chars: Vec<char> = classes
        .iter()
        .take(opts.length)
        .map(|class| class[rng.gen_range(0..class.len())])
        .collect();
    while chars.len() < opts.length {
        chars.push(alphabet[rng.gen_range(0..alphabet.len())]);
    }

    // Fisher-Yates so the guaranteed picks are not clustered at the front.
    for i in (1..chars.len()).rev() {
        let j = rng.gen_range(0..=i);
        chars.swap(i, j);
    }

    Ok(Zeroizing::new(chars.into_iter().collect()))
}

/// Generate a word-based passphrase, e.g. `copper-lantern-orbit-thrive-melon`.
///
/// The built-in list has 256 words → 8 bits of entropy per word.
pub fn generate_passphrase(words: usize, separator: &str) -> Result<Zeroizing<String>> {
    if !(3..=16).contains(&words) {
        return Err(Error::InvalidInput("word count must be between 3 and 16".into()));
    }
    let list = wordlist();
    let mut rng = OsRng;
    let picked: Vec<&str> = (0..words).map(|_| list[rng.gen_range(0..list.len())]).collect();
    Ok(Zeroizing::new(picked.join(separator)))
}

/// Rough entropy estimate in bits based on observed character classes.
pub fn entropy_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let mut pool = 0usize;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32;
    }
    (pool.max(1) as f64).log2() * password.chars().count() as f64
}

/// Human label for an entropy estimate.
pub fn strength_label(bits: f64) -> &'static str {
    match bits {
        b if b < 40.0 => "very weak",
        b if b < 60.0 => "weak",
        b if b < 80.0 => "fair",
        b if b < 100.0 => "strong",
        _ => "very strong",
    }
}

/// 256 common, distinct English words (8 bits each). Shared with the
/// recovery-phrase generator.
pub(crate) fn wordlist() -> &'static [&'static str] {
    &[
        "acorn", "alarm", "amber", "anchor", "apple", "april", "arrow", "atlas",
        "autumn", "badge", "bagel", "bamboo", "banana", "banner", "basil", "beach",
        "beacon", "berry", "birch", "bishop", "blanket", "blossom", "bolt", "border",
        "bottle", "breeze", "brick", "bridge", "bronze", "brook", "brush", "bubble",
        "bucket", "butter", "button", "cabin", "cactus", "camera", "candle", "canoe",
        "canyon", "carbon", "carpet", "castle", "cedar", "cellar", "chalk", "cherry",
        "chess", "chimney", "circle", "citrus", "clover", "cobalt", "coconut", "comet",
        "compass", "copper", "coral", "cotton", "cradle", "crater", "crystal", "curtain",
        "cypress", "daisy", "dawn", "delta", "denim", "desert", "diamond", "dolphin",
        "domino", "donkey", "dragon", "drum", "duster", "eagle", "easel", "echo",
        "ember", "engine", "estate", "fabric", "falcon", "feather", "fennel", "ferry",
        "fiddle", "flame", "flint", "forest", "fossil", "fountain", "frost", "galaxy",
        "garden", "garlic", "geyser", "ginger", "glacier", "goblet", "granite", "grape",
        "gravel", "grove", "guitar", "hammer", "harbor", "harvest", "hazel", "helmet",
        "hermit", "hickory", "hillside", "honey", "horizon", "hotel", "icicle", "indigo",
        "island", "ivory", "jacket", "jaguar", "jasmine", "jigsaw", "jungle", "juniper",
        "kayak", "kettle", "kitten", "ladder", "lagoon", "lantern", "lately", "laurel",
        "lava", "lemon", "lilac", "linen", "lizard", "lobster", "locket", "lotus",
        "lumber", "magnet", "mango", "maple", "marble", "meadow", "melon", "mesa",
        "meteor", "mint", "mirror", "molar", "monsoon", "morning", "mosaic", "mustard",
        "nectar", "nickel", "night", "nimble", "north", "nutmeg", "oasis", "ocean",
        "olive", "onion", "opal", "orbit", "orchard", "otter", "oyster", "paddle",
        "pagoda", "palace", "panda", "paper", "parrot", "pasture", "pearl", "pebble",
        "pelican", "pepper", "petal", "pigeon", "pillow", "pinecone", "pistachio", "planet",
        "plaza", "plume", "pocket", "polar", "pond", "poplar", "poppy", "prairie",
        "prism", "pumpkin", "quartz", "quill", "rabbit", "raccoon", "radish", "rainbow",
        "raisin", "raven", "reef", "ribbon", "ridge", "river", "rocket", "rooster",
        "rosemary", "ruby", "saddle", "saffron", "sage", "salmon", "sandal", "sapphire",
        "scarf", "scooter", "shadow", "shell", "silver", "sketch", "sleet", "slipper",
        "smoke", "sparrow", "spice", "spiral", "spruce", "squash", "stable", "summit",
        "sunset", "taffy", "tango", "teapot", "temple", "thistle", "thrive", "thunder",
        "tiger", "timber", "topaz", "trellis", "trumpet", "tulip", "tunnel", "turtle",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_256_unique() {
        let list = wordlist();
        assert_eq!(list.len(), 256);
        let set: std::collections::HashSet<_> = list.iter().collect();
        assert_eq!(set.len(), 256);
    }

    #[test]
    fn respects_length_and_classes() {
        let pw = generate(&GenerateOptions::default()).unwrap();
        assert_eq!(pw.chars().count(), 20);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn lowercase_only() {
        let opts = GenerateOptions {
            upper: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        let pw = generate(&opts).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn ambiguous_excluded() {
        let opts = GenerateOptions { avoid_ambiguous: true, length: 100, ..Default::default() };
        let pw = generate(&opts).unwrap();
        assert!(!pw.chars().any(|c| "0O1lI".contains(c)));
    }

    #[test]
    fn passphrase_word_count() {
        let p = generate_passphrase(5, "-").unwrap();
        assert_eq!(p.split('-').count(), 5);
    }

    #[test]
    fn entropy_monotonic() {
        assert!(entropy_bits("aaaaaaaaaaaaaaaaaaaa") < entropy_bits("aA1!aA1!aA1!aA1!aA1!"));
        assert_eq!(strength_label(30.0), "very weak");
        assert_eq!(strength_label(120.0), "very strong");
    }
}
