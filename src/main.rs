use clap::Parser;
use passwords::PasswordGenerator;
use pwhash::bcrypt::{self};
use pwhash::{md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, unix_crypt};
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
    /// Encrypt existing password. Needs to be entered on prompt
    #[arg(short, long, default_value_t = false, conflicts_with_all = &["random_password", "words"])]
    existing_password: bool,

    /// Generate a random password
    #[arg(short, long, default_value_t = false, conflicts_with_all = &["existing_password", "words"])]
    random_password: bool,

    /// Generate a password using words
    #[arg(long, short, default_value_t = false, conflicts_with_all = &["existing_password", "random_password"])]
    words: bool,

    /// Echo back the entered password
    #[arg(long, default_value_t = false)]
    echo: bool,

    /// Password length
    #[arg(short, long, default_value_t = 12)]
    length: usize,

    /// Use symbols in addition to letters and numbers
    #[arg(short, long, default_value_t = false)]
    use_symbols: bool,

    /// Language in case of generating passwords consisting of words
    #[arg(long)]
    language: Option<Language>,

    /// Generate this many words
    #[arg(long, short, default_value_t = 3)]
    num_words: usize,

    /// Maximum length of a word
    #[arg(long, short, default_value_t = 6)]
    max_word_length: usize,
}
fn main() {
    let args = Args::parse();
    // Use the existing password or generate a new one with the given length
    let password = if args.existing_password {
        rpassword::prompt_password("Enter password: ").unwrap()
    } else if args.words {
        generate_words(&args)
    } else if args.random_password {
        generate_random_password(args.length, args.use_symbols)
    } else {
        println!("Don't know what to do. Use --help for more info");
        return;
    };

    println!();
    if !args.existing_password || args.echo {
        println!("Password\t: {}", password);
    }

    print_encrypted_password(&password);
}

#[allow(deprecated)]
fn print_encrypted_password(password: &str) {
    println!("MD5\t\t: {}", md5_crypt::hash(password).unwrap());
    println!("DES\t\t: {}", unix_crypt::hash(password).unwrap());
    println!("SHA1\t\t: {}", sha1_crypt::hash(password).unwrap());
    println!("SHA256\t\t: {}", sha256_crypt::hash(password).unwrap());
    println!("SHA512\t\t: {}", sha512_crypt::hash(password).unwrap());
    println!("bcrypt\t\t: {}", bcrypt::hash(password).unwrap());
    println!();
}

fn generate_random_password(pw_length: usize, use_symbols: bool) -> String {
    let pg = PasswordGenerator {
        length: pw_length,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: use_symbols,
        spaces: false,
        exclude_similar_characters: false,
        strict: true,
    };

    pg.generate_one().unwrap()
}

// fn generate_words(lang: Option<Language>, num_words: usize, max_word_length: usize) -> String {
fn generate_words(args: &Args) -> String {
    let l = match &args.language {
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
    for _ in 0..args.num_words {
        let mut generated;
        loop {
            generated = random_word::gen(l);
            if generated.len() <= args.max_word_length {
                break;
            }
        }

        words.push(generated);
    }

    words.join(" ")
}
