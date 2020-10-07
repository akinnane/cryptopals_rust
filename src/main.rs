use phf::{phf_map, Map};
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::io::BufRead;

#[cfg(not(test))]
use log::debug;

#[cfg(test)]
use std::println as debug;

fn main() {}

fn from_hex_to_base64<T: AsRef<[u8]>>(input: T) -> String {
    let output = hex::decode(input).unwrap();
    base64::encode(output)
}

#[test]
fn s1c1_convert_hex_to_base64() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let output = from_hex_to_base64(input);

    assert_eq!(output, expected);
}

fn xor<S: AsRef<[u8]>>(s1: S, s2: S) -> Vec<u8> {
    s1.as_ref()
        .iter()
        .zip(s2.as_ref().iter())
        .map(|b| b.0 ^ b.1)
        .collect::<Vec<u8>>()
}

#[test]
fn s1c2_fixed_xor() {
    let input = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let key = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();
    let output = xor(input, key.to_vec());

    assert_eq!(output, expected);
}

static ENGLISH_LETTER_FREQUENCIES: Map<char, f64> = phf_map! {
    'A' => 0.0651738,
    'B' => 0.0124248,
    'C' => 0.0217339,
    'D' => 0.0349835,
    'E' => 0.1041442,
    'F' => 0.0197881,
    'G' => 0.0158610,
    'H' => 0.0492888,
    'I' => 0.0558094,
    'J' => 0.0009033,
    'K' => 0.0050529,
    'L' => 0.0331490,
    'M' => 0.0202124,
    'N' => 0.0564513,
    'O' => 0.0596302,
    'P' => 0.0137645,
    'Q' => 0.0008606,
    'R' => 0.0497563,
    'S' => 0.0515760,
    'T' => 0.0729357,
    'U' => 0.0225134,
    'V' => 0.0082903,
    'W' => 0.0171272,
    'X' => 0.0013692,
    'Y' => 0.0145984,
    'Z' => 0.0007836,
    ' ' => 0.1918182,
};

fn detect_english(input: &str) -> f64 {
    let mut char_frequency = BTreeMap::new();

    let weight = 1.0 / input.len() as f64;
    input
        .chars()
        .for_each(|c| *char_frequency.entry(c.to_ascii_uppercase()).or_insert(0.0) += weight);

    ENGLISH_LETTER_FREQUENCIES
        .entries()
        .fold(0.0, |mut acc, kv| {
            let overlap = char_frequency.get(kv.0).unwrap_or(&0.0) * *kv.1;
            acc += overlap.sqrt();
            acc
        })
}

#[derive(Debug, Default)]
struct SingleByteXorResult {
    score: f64,
    byte: u8,
    decrypted: String,
}

fn single_byte_xor<S: AsRef<[u8]>>(input: S) -> SingleByteXorResult {
    let mut best = SingleByteXorResult::default();
    for byte in 0_u8..=255 {
        let key = vec![byte; input.as_ref().len()];
        let output = xor(input.as_ref(), &key);
        let as_string = String::from_utf8(output);

        if let Ok(decrypted) = as_string {
            let score = detect_english(&decrypted);
            if score > best.score {
                best = SingleByteXorResult {
                    score,
                    byte,
                    decrypted,
                };
            }
        }
    }
    best
}

#[test]
fn s1c3_single_byte_xor_cipher() {
    let input = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        .unwrap();
    let output = single_byte_xor(input);
    assert_eq!(output.byte, 88_u8);
    assert_eq!(output.decrypted, "Cooking MC\'s like a pound of bacon");
}

#[test]
fn s1c4_detect_single_character_xor() {
    let f = File::open("4.txt").unwrap();
    let reader = io::BufReader::new(f);
    let mut best = SingleByteXorResult::default();
    for line in reader.lines() {
        if let Ok(l) = line {
            let decoded = hex::decode(l).unwrap();
            let r = single_byte_xor(&decoded);
            if r.score > best.score {
                best = r;
            }
        }
    }
    assert_eq!(best.byte, 53_u8);
    assert_eq!(best.decrypted, "Now that the party is jumping\n");
}
