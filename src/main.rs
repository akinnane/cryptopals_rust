use lazy_static::lazy_static;
use openssl::symm::{Cipher, Crypter, Mode};
use phf::{phf_map, Map};
use rand::prelude::*;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::iter;
// #[cfg(not(test))]

#[cfg(test)]
use {std::io, std::io::BufRead};

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

fn xor<S: AsRef<[u8]>, S1: AsRef<[u8]>>(s1: S, s2: S1) -> Vec<u8> {
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

static ENGLISH_LETTER_FREQUENCIES: Map<u8, f64> = phf_map! {
    b'A' => 0.0651738,
    b'B' => 0.0124248,
    b'C' => 0.0217339,
    b'D' => 0.0349835,
    b'E' => 0.1041442,
    b'F' => 0.0197881,
    b'G' => 0.0158610,
    b'H' => 0.0492888,
    b'I' => 0.0558094,
    b'J' => 0.0009033,
    b'K' => 0.0050529,
    b'L' => 0.0331490,
    b'M' => 0.0202124,
    b'N' => 0.0564513,
    b'O' => 0.0596302,
    b'P' => 0.0137645,
    b'Q' => 0.0008606,
    b'R' => 0.0497563,
    b'S' => 0.0515760,
    b'T' => 0.0729357,
    b'U' => 0.0225134,
    b'V' => 0.0082903,
    b'W' => 0.0171272,
    b'X' => 0.0013692,
    b'Y' => 0.0145984,
    b'Z' => 0.0007836,
    b' ' => 0.1918182,
};

fn detect_english<T: AsRef<[u8]>>(input: T) -> f64 {
    let mut char_frequency = BTreeMap::new();

    let weight = 1.0 / input.as_ref().len() as f64;
    input
        .as_ref()
        .iter()
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

fn detect_single_byte_xor<'a, I, T: 'a, E: 'a>(iter: &mut I) -> SingleByteXorResult
where
    I: Iterator<Item = Result<T, E>>,
    T: AsRef<[u8]>,
{
    let mut best = SingleByteXorResult::default();
    while let Some(item) = iter.next() {
        if let Ok(i) = item {
            let decoded = hex::decode(i.as_ref()).unwrap();
            let r = single_byte_xor(&decoded);
            if r.score > best.score {
                best = r;
            }
        }
    }
    best
}

#[test]
fn s1c4_detect_single_character_xor() {
    let f = File::open("4.txt").unwrap();
    let reader = io::BufReader::new(f);
    let best = detect_single_byte_xor(&mut reader.lines());

    assert_eq!(best.byte, 53_u8);
    assert_eq!(best.decrypted, "Now that the party is jumping\n");
}

fn repeating_key_xor<T>(input: T, key: T) -> Vec<u8>
where
    T: AsRef<[u8]> + Clone,
{
    let k = key
        .as_ref()
        .iter()
        .cycle()
        .take(input.as_ref().len())
        .cloned()
        .collect::<Vec<_>>();
    xor(input, k)
}

#[test]
fn s1c5_implement_repeating_key_xor() {
    let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let result = repeating_key_xor(&input, &key);
    let hex = hex::encode(result);

    assert_eq!(hex, expected);
}

fn hamming_distance<T: AsRef<[u8]>>(one: T, two: T) -> usize {
    let x = xor(one, two);
    let mut distance = 0;
    for byte in x.iter() {
        let mut b = byte.clone();
        for _ in 0..8 {
            let bit = b & 1;
            if bit == 1 {
                distance += 1;
            }
            b = b >> 1;
        }
    }
    distance
}

#[test]
fn test_hamming_distance() {
    let one = "this is a test";
    let two = "wokka wokka!!!";
    let result = hamming_distance(one, two);
    assert_eq!(result, 37);
}

fn load_base64_file(path: &str) -> Vec<u8> {
    let file = File::open(path).unwrap();

    let mut reader = BufReader::new(file);

    let mut contents = Vec::new();
    reader.read_to_end(&mut contents).unwrap();

    // https://github.com/marshallpierce/rust-base64/issues/105 :(
    contents = contents
        .iter()
        .filter(|b| !b" \n\t\r\x0b\x0c".contains(b))
        .cloned()
        .collect();
    base64::decode(&contents).unwrap()
}

#[test]
fn test_load_base64_file() {
    let v = load_base64_file("6.txt");
    assert_eq!(v.len(), 2876);
}

fn hamming_distance_for_key_size<T: AsRef<[u8]>>(bytes: T, key_size: usize) -> f64 {
    let leading_bytes = bytes.as_ref().chunks(key_size).take(1);
    let trailing_bytes = bytes.as_ref()[key_size..].chunks(key_size).take(1);

    let total_distance: usize = leading_bytes
        .zip(trailing_bytes)
        .map(|chunks| hamming_distance(chunks.0, chunks.1))
        .sum();
    total_distance as f64 / key_size as f64
}

#[derive(Debug, PartialEq)]
struct KeySize {
    size: usize,
    score: f64,
}

fn key_size_hamming_distances<T: AsRef<[u8]>>(cipher_text: T) -> Vec<KeySize> {
    let mut distance_scores = Vec::with_capacity(cipher_text.as_ref().len());
    for size in 1..50 {
        let score = hamming_distance_for_key_size(&cipher_text, size);
        distance_scores.push(KeySize { size, score });
    }
    distance_scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    distance_scores
}

#[test]
fn test_hamming_distance_key_size() {
    let data = load_base64_file("6.txt");
    let sizes_hamming_distance = key_size_hamming_distances(&data);
    assert_eq!(
        sizes_hamming_distance[0],
        KeySize {
            size: 1,
            score: 6.0
        }
    );
    assert_eq!(
        sizes_hamming_distance[1],
        KeySize {
            size: 6,
            score: 4.0
        }
    );
}

fn transpose_blocks<T: AsRef<[u8]>>(ctext: T, key_size: usize) -> Vec<Vec<u8>> {
    let mut blocks = Vec::with_capacity(key_size);
    let block_size = ((ctext.as_ref().len() as f64 / key_size as f64).ceil()) as usize;
    for _ in 0..key_size {
        blocks.push(Vec::with_capacity(block_size));
    }
    for b in ctext.as_ref().chunks(key_size) {
        for (i, c) in b.iter().enumerate() {
            blocks[i].push(*c);
        }
    }
    blocks
}

#[test]
fn test_transpose_blocks() {
    let test = "1aA2bB3cC4dD5eE";
    let result = transpose_blocks(test, 3);

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], vec![b'1', b'2', b'3', b'4', b'5']);
    assert_eq!(result[1], vec![b'a', b'b', b'c', b'd', b'e']);
    assert_eq!(result[2], vec![b'A', b'B', b'C', b'D', b'E']);
}

fn key_from_xor_vec(xor_vec: &Vec<SingleByteXorResult>) -> Vec<u8> {
    let mut key = Vec::new();
    for byte in xor_vec {
        key.push(byte.byte);
    }
    key
}

#[test]
fn test_break_repeasting_key_xor() {
    let cipher_text = load_base64_file("6.txt");
    let sizes = key_size_hamming_distances(&cipher_text);
    let mut keys = vec![];
    for key_size in &sizes {
        let mut key = vec![];
        let blocks = transpose_blocks(&cipher_text, key_size.size);
        for block in blocks {
            key.push(single_byte_xor(&mut block.iter()));
        }
        keys.push(key);
    }

    let mut scores = vec![];

    for key in &keys {
        let key = key_from_xor_vec(key);
        let plain_text = repeating_key_xor(&cipher_text, &key);
        let score = detect_english(&plain_text);
        scores.push((score, key, plain_text));
    }
    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    let key = String::from_utf8(scores[0].1.clone()).unwrap();

    assert_eq!(&key, "Terminator X: Bring the noise");
}

fn aes_ecb_decrypt<T: AsRef<[u8]>, S: AsRef<[u8]>>(input: T, key: S, pad: bool) -> Vec<u8> {
    let mut decrypter =
        Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key.as_ref(), None).unwrap();
    let block_size = 16;
    decrypter.pad(pad);
    let mut output = vec![0; input.as_ref().len() + block_size];
    let mut count = decrypter.update(input.as_ref(), &mut output).unwrap();
    count += decrypter.finalize(&mut output[count..]).unwrap();
    output.truncate(count);
    output
}

#[test]
fn s1c7_aes_decrypt() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let cipher_text = load_base64_file("7.txt");

    let output = aes_ecb_decrypt(&cipher_text, key, true);

    let plain_text = String::from_utf8(output).unwrap();

    assert_eq!(plain_text.len(), 2876);

    let block_size = 16;

    assert_eq!(
        &plain_text[..block_size * 2],
        "I\'m back and I\'m ringin\' the bel"
    );

    assert_eq!(
        &plain_text[plain_text.len() - block_size * 2..],
        "Come on \nPlay that funky music \n"
    );
}

fn is_aes_ecb<T: AsRef<[u8]>>(cipher_text: T, block_size: usize) -> bool {
    let mut h = HashSet::new();
    cipher_text
        .as_ref()
        .chunks(block_size)
        .find(|chunk| !h.insert(chunk.clone()))
        .is_some()
}

#[test]
fn s1c9_detect_aes_ecb() {
    let f = File::open("8.txt").unwrap();
    let cipher_texts = io::BufReader::new(f);
    let aes_ecb = cipher_texts
        .lines()
        .map(|line| hex::decode(line.unwrap()).unwrap())
        .filter(|text| is_aes_ecb(&text, 16))
        .collect::<Vec<Vec<u8>>>();
    assert_eq!(aes_ecb.len(), 1)
}

fn pkcs7_pad(input: &mut Vec<u8>, block_size: usize) {
    let padding_size = block_size - input.len() % block_size;
    let padding_bytes = iter::repeat(padding_size as u8).take(padding_size);
    input.extend(padding_bytes);
}

fn pkcs7_unpad(input: &mut Vec<u8>) {
    let padding = input.last().unwrap();
    let length_without_padding = input.len() - *padding as usize;
    input.truncate(length_without_padding);
}

#[test]
fn s2c10_implement_pkcs7() {
    let mut input = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_pad(&mut input, 20);
    assert_eq!(
        input,
        "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec()
    );
}

fn aes_ecb_encrypt<T: AsRef<[u8]>, S: AsRef<[u8]>>(input: T, key: S, pad: bool) -> Vec<u8> {
    let mut encrypter =
        Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key.as_ref(), None).unwrap();
    encrypter.pad(pad);
    let block_size = 16;
    let mut output = vec![0; input.as_ref().len() + block_size];
    let mut count = encrypter.update(input.as_ref(), &mut output).unwrap();
    count += encrypter.finalize(&mut output[count..]).unwrap();
    output.truncate(count);
    output
}

#[test]
fn test_aes_ecb_encrpyt() {
    let cipher_text = load_base64_file("7.txt");
    let key = "YELLOW SUBMARINE".as_bytes();
    let decrypted = aes_ecb_decrypt(&cipher_text, key, true);

    let plain_text = String::from_utf8(decrypted.clone()).unwrap();
    assert!(plain_text.contains(&"Play that funky music"));

    let reencrypted = aes_ecb_encrypt(&decrypted, key, true);
    assert_eq!(reencrypted, cipher_text);
}

fn aes_cbc_encrypt<I: AsRef<[u8]>, P: AsRef<[u8]>, T: AsRef<[u8]>>(
    iv: I,
    plain_text: P,
    key: T,
) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(plain_text.as_ref().len());

    let mut previous_block = iv.as_ref().to_vec();

    let block_size = 16;

    let mut plain_text = plain_text.as_ref().clone().to_vec();
    pkcs7_pad(&mut plain_text, block_size);

    let blocks = plain_text.chunks(block_size);

    for block in blocks {
        let xored = xor(block, previous_block);

        let encrypted_block = aes_ecb_encrypt(xored, key.as_ref(), false);

        output.extend(&encrypted_block);

        previous_block = encrypted_block;
    }

    output
}

#[test]
fn test_aes_cbc_encrypt() {
    let cipher_text = load_base64_file("10.txt");
    let key = "YELLOW SUBMARINE";
    let iv = vec![0; 16];

    let decrypted = aes_cbc_decrypt(&iv, &cipher_text, &key);

    let plain_text = String::from_utf8(decrypted.clone()).unwrap();

    assert_eq!(plain_text.len(), 2876);

    let block_size = 16;
    assert_eq!(
        &plain_text[..block_size * 2],
        "I\'m back and I\'m ringin\' the bel"
    );

    assert_eq!(
        &plain_text[plain_text.len() - block_size * 2..],
        "Come on \nPlay that funky music \n"
    );

    let encrypted = aes_cbc_encrypt(&iv, &decrypted, &key);

    assert_eq!(encrypted, cipher_text);
}

fn aes_cbc_decrypt<I: AsRef<[u8]>, P: AsRef<[u8]>, T: AsRef<[u8]>>(
    iv: I,
    plain_text: P,
    key: T,
) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(plain_text.as_ref().len());

    let mut previous_block = iv.as_ref();

    let block_size = 16;
    let blocks = plain_text.as_ref().chunks(block_size);

    for block in blocks {
        let decrypted_block = aes_ecb_decrypt(block, key.as_ref(), false);

        let xored = xor(decrypted_block, previous_block);

        output.extend(&xored);

        previous_block = block;
    }

    pkcs7_unpad(&mut output);

    output
}

#[test]
fn s2c10_implement_aes_cbc_mode() {
    let cipher_text = load_base64_file("10.txt");
    let key = "YELLOW SUBMARINE";
    let iv = vec![0; 16];

    let decrypted = aes_cbc_decrypt(iv, cipher_text, key);

    let plain_text = String::from_utf8(decrypted).unwrap();

    assert_eq!(plain_text.len(), 2876);

    let block_size = 16;
    assert_eq!(
        &plain_text[..block_size * 2],
        "I\'m back and I\'m ringin\' the bel"
    );

    assert_eq!(
        &plain_text[plain_text.len() - block_size * 2..],
        "Come on \nPlay that funky music \n"
    );
}

fn random_bytes(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    data.to_vec()
}

#[derive(Debug, PartialEq, Eq)]
enum EncryptionType {
    CBC,
    ECB,
}

#[derive(Debug)]
struct OracleOutput {
    encryption: EncryptionType,
    cipher_text: Vec<u8>,
}

fn encryption_oracle<T: AsRef<[u8]>>(plain_text: T) -> OracleOutput {
    let mut rng = rand::thread_rng();
    let key = random_bytes(16);
    let iv = random_bytes(16);
    let random_size = rng.gen_range(5, 10);
    let prefix = random_bytes(random_size);
    let postfix = random_bytes(random_size);
    let payload = prefix
        .iter()
        .chain(plain_text.as_ref().iter())
        .chain(postfix.iter())
        .cloned()
        .collect::<Vec<u8>>();
    dbg!(payload.len());
    if rng.gen_range(0, 2) > 0 {
        let cipher_text = aes_cbc_encrypt(iv, payload, key);
        OracleOutput {
            encryption: EncryptionType::CBC,
            cipher_text: cipher_text,
        }
    } else {
        let cipher_text = aes_ecb_encrypt(payload, key, true);
        OracleOutput {
            encryption: EncryptionType::ECB,
            cipher_text: cipher_text,
        }
    }
}

#[test]
fn s2_c11_an_ecb_cbc_detection_oracle() {
    let plain_text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    dbg!(plain_text.len());
    for _i in 0..100 {
        let oracle = encryption_oracle(plain_text);
        let encryption_type = match is_aes_ecb(&oracle.cipher_text, 16) {
            true => EncryptionType::ECB,
            false => EncryptionType::CBC,
        };
        assert_eq!(encryption_type, oracle.encryption);
    }
}

lazy_static! {
    static ref S2_C12_SECRET_KEY: Vec<u8> = random_bytes(16);
}

const S2_S12_UNKNOWN_STRING: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                               aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                               dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                               YnkK";

fn s2_c12_encryption_oracle<T: AsRef<[u8]>>(plain_text: T) -> OracleOutput {
    let key = S2_C11_SECRET_KEY.clone();
    let payload = plain_text
        .as_ref()
        .iter()
        .chain(base64::decode(&S2_S11_UNKNOWN_STRING).unwrap().iter())
        .cloned()
        .collect::<Vec<u8>>();

    let cipher_text = aes_ecb_encrypt(payload, key, true);
    OracleOutput {
        encryption: EncryptionType::ECB,
        cipher_text: cipher_text,
    }
}

fn s2_c12_detect_block_size_2() -> usize {
    const MAX_SAMPLES: usize = 100;
    let mut block_sizes = (0..MAX_SAMPLES)
        .map(|n| s2_c11_encryption_oracle("a".repeat(n)).cipher_text.len())
        .collect::<Vec<usize>>();

    block_sizes.sort();
    block_sizes.dedup();

    block_sizes[1] - block_sizes[0]
}

fn bytes_as_ascii<T: AsRef<[u8]>>(bytes: T, block_size: usize) -> String {
    let mut output = String::new();
    for slice in bytes.as_ref().chunks(block_size) {
        let block = &slice.iter().map(|b| *b as char).collect::<String>();
        output.push_str(&block);
        output.push('\n');
    }
    output
}

fn make_lookup_hashmap(padding: &mut Vec<u8>, block_number: usize, block_size: usize) -> HashMap::<Vec<u8>, u8> {
    padding.push(0u8);
    (0u8..=255u8)
        .map(|n| {
            *padding.last_mut().expect("Can't mutate padding") = n;

            let block = s2_c11_encryption_oracle(&padding)
                .cipher_text[(block_number - 1 ) * block_size..block_number * block_size].to_vec();

            (
                block,
                n,
            )
        })
        .collect::<HashMap<Vec<u8>, u8>>()
}


#[test]
fn s2_c12_byte_at_a_time_ecb_decrpytion() {
    let block_size = s2_c11_detect_block_size_2();
    assert_eq!(block_size, 16);

    let total_size =  s2_c11_encryption_oracle(vec![]).cipher_text.len();

    let mut known = vec![];
    let mut block_number = 1;

    loop {
        let mut padding = vec![0u8; (block_number * block_size) - known.len() - 1];
        padding.extend_from_slice(known.as_slice());

        let block_lookup = make_lookup_hashmap(&mut padding, block_number, block_size);

        let oracle_result = s2_c11_encryption_oracle(vec![0u8; (block_number * block_size) - known.len() - 1]);


        let first_block = &oracle_result.cipher_text[(block_number - 1 ) * block_size..block_number * block_size];

        let decrypted_byte =  *block_lookup.get(first_block).expect("block of oracle result not in block_lookup");

        known.push(decrypted_byte);

        if known.len() % 16 == 0 {
            block_number += 1;
        }

        // Why 7?
        if known.len() >  total_size - 7 {
            break
        }
    }
    println!("{}", &std::str::from_utf8(&known).unwrap());
    assert_eq!(known, base64::decode(&S2_S11_UNKNOWN_STRING).unwrap());
}
