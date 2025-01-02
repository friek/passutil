use clap::Parser;
use pwhash::bcrypt::{self};
use pwhash::{md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, unix_crypt};
use rand::Rng;
use random_word::Lang;

// Mapping enum representing random_word::Lang
#[derive(clap::ValueEnum, Clone, Debug)]
enum Language {
    De,
    En,
    Es,
    Fr,
    Ja,
    Zh,
}

#[derive(Parser, Debug)]
#[command(about = "Generate a password and output encrypted versions",
    version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"), long_about = None)]
#[command(arg_required_else_help = true)]
struct Args {
    /// Encrypt existing password
    #[arg(short, long, default_value_t = false)]
    existing_password: bool,

    /// Echo back the entered password
    #[arg(long, default_value_t = false)]
    echo: bool,

    /// Password length
    #[arg(short, long, default_value_t = 12)]
    length: u8,

    /// Use symbols in addition to letters and numbers
    #[arg(short, long, default_value_t = false)]
    use_symbols: bool,

    /// Language in case of generating passwords consisting of words
    #[arg(long)]
    language: Option<Language>,

    /// Generate this many words
    #[arg(long, short, default_value_t = 3)]
    num_words: usize,

    /// Generate a password using words
    #[arg(long, short, default_value_t = false)]
    words: bool,

    /// Maximum length of a word
    #[arg(long, short, default_value_t = 6)]
    max_word_length: usize,
}
fn main() {
    let args = Args::parse();
    // Use the existing password or generate a new one with the given length
    let password = if args.existing_password {
        rpassword::prompt_password("Enter password: ").unwrap()
    } else {
        if args.words {
            generate_words(args.language, args.num_words, args.max_word_length)
        } else {
            generate_random_password(args.length, args.use_symbols)
        }
    };

    println!();
    if (args.existing_password && args.echo) || !args.existing_password {
        println!("Password\t: {}", password);
    }

    print_encrypted_password(&password);
}

#[allow(deprecated)]
fn print_encrypted_password(password: &str) {
    println!("MD5\t\t: {}", md5_crypt::hash(&password).unwrap());
    println!("DES\t\t: {}", unix_crypt::hash(&password).unwrap());
    println!("SHA1\t\t: {}", sha1_crypt::hash(&password).unwrap());
    println!("SHA256\t\t: {}", sha256_crypt::hash(&password).unwrap());
    println!("SHA512\t\t: {}", sha512_crypt::hash(&password).unwrap());
    println!("bcrypt\t\t: {}", bcrypt::hash(&password).unwrap());
    println!();
}

fn generate_random_password(pw_length: u8, use_symbols: bool) -> String {
    let letters = vec![
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    ];
    let numbers = vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
    let symbols = [
        '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']',
        '|', '\\', ':', ';', '<', '>', ',', '.', '?', '/', '`',
    ];

    let mut char_set = Vec::new();
    char_set.extend(letters.to_vec());
    char_set.extend(numbers.to_vec());
    if use_symbols {
        char_set.extend(symbols.to_vec());
    }

    generate_random_string(pw_length, char_set)
}

fn generate_random_string(length: u8, chars: Vec<char>) -> String {
    let mut rng = rand::thread_rng(); // Thread-local random number generator
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..chars.len()); // Pick a random index
            chars[idx] // Get the character at the random index
        })
        .collect() // Collect the characters into a string
}

fn generate_words(lang: Option<Language>, num_words: usize, max_word_length: usize) -> String {
    let l = match lang {
        Some(l) => match l {
            Language::De => Lang::De,
            Language::En => Lang::En,
            Language::Es => Lang::Es,
            Language::Fr => Lang::Fr,
            Language::Ja => Lang::Ja,
            Language::Zh => Lang::Zh,
        },
        _ => Lang::En,
    };

    let mut words = Vec::new();
    for _ in 0..num_words {
        let mut generated;
        loop {
            generated = random_word::gen(l);
            if generated.len() <= max_word_length {
                break;
            }
        }

        words.push(generated);
    }

    words.join(" ")
}
