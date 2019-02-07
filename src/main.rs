use std::fs::File;
use std::io::{ Read, Write, BufReader, BufRead };
use std::str;
use std::borrow::Cow;

use pcsc::*;
use url::Url;
use libreauth::oath::TOTPBuilder;
use clipboard::{ ClipboardProvider, ClipboardContext };

mod crypto;
mod mpi;
mod packets;
use packets::{ Packets, SymmetricKey };
mod smartcard;

fn main() {
    // Establish a PC/SC context.
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("Failed to establish context: {}", err);
            std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            eprintln!("Failed to list readers: {}", err);
            std::process::exit(1);
        }
    };

    // Find YubiKey
    let yubikey = loop {
        let reader = readers.next();
        match reader {
            Some(name) => {
                let name = name.to_str().unwrap();
                if name.contains("Yubico") {
                    println!("Found {}", name);
                    break reader;
                }
            },
            None => break None,
        };
    };
    if yubikey.is_none() {
        eprintln!("No YubiKey connected");
        std::process::exit(1);
    }

    // Connect to the card.
    let card = match ctx.connect(yubikey.unwrap(), ShareMode::Shared, Protocols::ANY) {
        Ok(card) => card,
        Err(Error::NoSmartcard) => {
            println!("A smartcard is not present in the reader.");
            return;
        }
        Err(err) => {
            eprintln!("Failed to connect to card: {}", err);
            std::process::exit(1);
        }
    };

    let mut card = smartcard::PGPCard::new(&card);
    card.select_pgp().unwrap();
    println!("{}", card.get_cardholder_info().unwrap());
    card.get_keys().unwrap();

    let mut f: Option<File> = None;
    for entry in walkdir::WalkDir::new("C:\\Users\\petsc\\Documents\\GitHub\\passwords") {
        let entry = entry.unwrap();
        let name = entry.path().to_str().unwrap();
        if name.contains(&std::env::args().last().unwrap()) {
            println!("Reading {}:", entry.path().display());
            f = Some(File::open(entry.path()).unwrap());
            break;
        }
    }

    if f.is_none() {
        eprintln!("File not found");
        std::process::exit(1);
    }

    let mut buffer = Vec::new();
    f.unwrap().read_to_end(&mut buffer).unwrap();
    if str::from_utf8(&buffer).is_ok() {
        // Parse from armored text
        let mut reader = BufReader::new(buffer.as_slice());
        buffer = sloppy_rfc4880::armor::read_armored(&mut reader).expect("Invalid PGP armored file");
    }
    read_packets(&mut card, buffer.as_slice());
}

fn read_packets(card: &smartcard::PGPCard, data: &[u8]) {
    let mut key: Option<SymmetricKey> = None;

    let packets = packets::read(data);
    for packet in packets {
        match packet {
            Packets::PublicKeyEncryptedSessionKey(packet) => {
                if &card.dec_key[card.dec_key.len() - 8..] == packet.key_id {
                    let mut pin = String::new();
                    print!("PIN > ");
                    std::io::stdout().flush().unwrap();
                    std::io::stdin().read_line(&mut pin).expect("Unable to read input");
                    if !card.authenticate(&pin.trim()).unwrap() {
                        std::process::exit(1);
                    }

                    key = Some(packet.decrypt_with_card(&card).unwrap());
                }
            },
            Packets::SymIntData(packet) => {
                if key.is_none() {
                    println!("Found encrypted data packet but didn't have key to decrypt");
                    continue;
                }
                read_packets(&card, &packet.decrypt(key.take().unwrap()));
            },
            Packets::Compressed(packet) => {
                read_packets(&card, &packet.get_packets());
            },
            Packets::Literal(packet) => {
                let data = packet.to_string();
                let url = Url::parse(&data);
                let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();

                if url.is_ok() && url.as_ref().unwrap().scheme() == "otpauth" {
                    let url = url.unwrap();
                    assert_eq!(url.domain().unwrap(), "totp", "Only TOTP supported");
                    let mut digits: usize = 6;
                    let mut secret = String::new();
                    for keyvalue in url.query_pairs() {
                        match keyvalue.0 {
                            Cow::Borrowed("digits") => digits = keyvalue.1.parse::<usize>().unwrap(),
                            Cow::Borrowed("secret") => secret = keyvalue.1.to_string(),
                            _ => {},
                        }
                    }
                    let totp = TOTPBuilder::default()
                        .base32_key(&secret)
                        .output_len(digits)
                        .finalize()
                        .unwrap();
                    ctx.set_contents(totp.generate()).unwrap();
                    let name = url.path_segments().unwrap().next().unwrap();
                    let name = percent_encoding::percent_decode(name.as_bytes()).decode_utf8().unwrap();
                    println!("\nCopied code for {} to clipboard", name);
                }
                else {
                    // Let's consider this plain text (i.e. a normal pass entry)
                    let buffer = BufReader::new(data.as_bytes());

                    ctx.set_contents(buffer.lines().next().unwrap().unwrap()).unwrap();
                    println!("\n{}", data);
                }
            },
            _ => {},
        };
    }
}
