use crypto::aessafe::*;
use crypto::symmetriccipher::BlockEncryptor;
use crypto::sha1::Sha1;
use crypto::digest::Digest;

use crate::packets::SymmetricKey;

// pub enum EncryptionAlgorithm {
// 	AES128 = 0x07,
// 	AES192 = 0x08,
// 	AES256 = 0x09,
// }
pub const BLOCK_SIZE: usize = 16;

pub fn encrypt(key: &SymmetricKey, mut prefixrandom: Vec<u8>, plaintext: &[u8]) -> Vec<u8> {
	assert!(key.algo == 0x09, "AES-256 must be used currently");
	assert!(prefixrandom.len() == BLOCK_SIZE + 2, "Incorrect number of bytes in prefix data");

	prefixrandom[BLOCK_SIZE] = prefixrandom[BLOCK_SIZE - 2];
	prefixrandom[BLOCK_SIZE + 1] = prefixrandom[BLOCK_SIZE - 1];

	let mut mdc_content = Vec::new();
	mdc_content.extend(&prefixrandom);
	mdc_content.extend(plaintext);
	mdc_content.push(0xD3); // MDC header
	mdc_content.push(0x14); // Length of SHA-1 hash (20 bytes)
	let mdc = sha1(&mdc_content);

	let mut plaintext = Vec::new();
	plaintext.extend(mdc_content);
	plaintext.extend(&mdc);

	let cipher = AesSafe256Encryptor::new(&key.key);
	let mut fr = [0u8; BLOCK_SIZE];
	let mut fre = [0u8; BLOCK_SIZE];
	let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext.len() + 2 + BLOCK_SIZE * 2);

	cipher.encrypt_block(&fr, &mut fre);
	for i in 0..BLOCK_SIZE {
		ciphertext[i] = fre[i] ^ prefixrandom[i];
	}

	fr.copy_from_slice(&ciphertext[..BLOCK_SIZE]);
	cipher.encrypt_block(&fr, &mut fre);

	ciphertext[BLOCK_SIZE + 0] = fre[0] ^ prefixrandom[BLOCK_SIZE + 0];
	ciphertext[BLOCK_SIZE + 1] = fre[1] ^ prefixrandom[BLOCK_SIZE + 1];

	fr.copy_from_slice(&ciphertext[..BLOCK_SIZE]);
	cipher.encrypt_block(&fr, &mut fre);

	for i in 0..BLOCK_SIZE {
		ciphertext[BLOCK_SIZE + 2 + i] = fre[i + 2] ^ plaintext[i];
	}
	for n in (BLOCK_SIZE..plaintext.len() + 2).step_by(BLOCK_SIZE) {
		let begin = n;
		fr.copy_from_slice(&ciphertext[begin..begin + BLOCK_SIZE]);
		cipher.encrypt_block(&fr, &mut fre);
		for i in 0..BLOCK_SIZE {
			ciphertext[BLOCK_SIZE + begin + i] = fre[i] ^ plaintext[n + i - 2];
		}
	}
	ciphertext.truncate(plaintext.len() + 2 + BLOCK_SIZE);
	ciphertext
}

pub fn decrypt(key: &SymmetricKey, cipher_text: &[u8]) -> Vec<u8> {
	assert!(key.algo == 0x09, "AES-256 must be used currently");
	let cipher = AesSafe256Encryptor::new(&key.key);

	let mut plaintext = vec![0; cipher_text.len() - BLOCK_SIZE];
	let mut i_buffer = [0u8; BLOCK_SIZE];
	let mut a_buffer = [0u8; BLOCK_SIZE];

	cipher.encrypt_block(&i_buffer.clone(), &mut i_buffer);
	for i in 0..BLOCK_SIZE {
		a_buffer[i] = cipher_text[i];
		i_buffer[i] ^= a_buffer[i];
	}

	cipher.encrypt_block(&a_buffer.clone(), &mut a_buffer);

	if  i_buffer[BLOCK_SIZE - 2] != (a_buffer[0] ^ cipher_text[BLOCK_SIZE]) ||
		i_buffer[BLOCK_SIZE - 1] != (a_buffer[1] ^ cipher_text[BLOCK_SIZE + 1]) {
		panic!("Invalid key!");
	}

	let mut j = 0;
	for i in 0..BLOCK_SIZE {
		i_buffer[i] = cipher_text[i];
	}
	for n in (BLOCK_SIZE..cipher_text.len()).step_by(BLOCK_SIZE) {
		cipher.encrypt_block(&i_buffer, &mut a_buffer);

		for i in 0..BLOCK_SIZE {
			if i + n >= cipher_text.len() { break; }
			i_buffer[i] = cipher_text[n + i];
			if j < plaintext.len() {
				plaintext[j] = a_buffer[i] ^ i_buffer[i];
				j += 1;
			}
		}
	}
	// Get rid of two IV bytes that carry over
	plaintext.drain(0..2);

	// Check MDC
	let mdc_result = mdc(cipher, &mut i_buffer, &mut a_buffer, cipher_text);
	let mut everything = Vec::new();
	everything.extend_from_slice(&mdc_result);
	everything.extend_from_slice(&plaintext[..plaintext.len() - 20]); // MDC hash is 20 bytes long
	assert_eq!(&sha1(&everything), &plaintext[plaintext.len() - 20..], "Invalid MDC!");
	plaintext
}

fn mdc<B: BlockEncryptor>(cipher: B, mut i_buffer: &mut [u8], mut a_buffer: &mut [u8], cipher_text: &[u8]) -> [u8; BLOCK_SIZE + 2] {
	let mut result = [0u8; BLOCK_SIZE + 2];
	let prefix = &cipher_text[0..BLOCK_SIZE + 2];
	cipher.encrypt_block(&[0; BLOCK_SIZE], &mut i_buffer);
	for i in 0..BLOCK_SIZE {
		a_buffer[i] = prefix[i];
		i_buffer[i] ^= a_buffer[i];
		result[i] = i_buffer[i];
	}

	let mut a_buffer_readable = [0u8; BLOCK_SIZE];
	a_buffer_readable.copy_from_slice(&a_buffer);
	cipher.encrypt_block(&a_buffer_readable, &mut a_buffer);
	result[BLOCK_SIZE] = a_buffer[0] ^ prefix[BLOCK_SIZE];
	result[BLOCK_SIZE + 1] = a_buffer[1] ^ prefix[BLOCK_SIZE + 1];
	result
}

pub fn sha1(input: &[u8]) -> [u8; 20] {
	let mut hasher = Sha1::new();
	hasher.input(&input);
	let mut hash = [0u8; 20];
	hasher.result(&mut hash);
	hash
}
