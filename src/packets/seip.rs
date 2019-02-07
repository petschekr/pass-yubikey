use std::fmt;

use crate::packets::{ Packet, SymmetricKey };
use crate::crypto;
use crate::smartcard::PGPCard;

pub struct SEIPPacket {
    ciphertext: Vec<u8>,
}
impl fmt::Debug for SEIPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Symmetrically Encrypted Integrity Protected Data")
			.field("length", &self.ciphertext.len())
			.finish()
    }
}
impl fmt::Display for SEIPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ciphertext: {} bytes", self.ciphertext.len())
    }
}

impl SEIPPacket {
	pub fn encrypt(key: &SymmetricKey, plaintext: &[u8], card: &PGPCard) -> Self {
		let prefixrandom = card.get_random_bytes(crypto::BLOCK_SIZE as u8 + 2).unwrap();
		let ciphertext = crypto::encrypt(key, prefixrandom, plaintext);
		Self { ciphertext }
	}
	pub fn decrypt(&self, key: SymmetricKey) -> Vec<u8> {
		assert_eq!(key.algo, 0x09, "Encryption types other than AES-256 not yet supported");
		crypto::decrypt(&key, &self.ciphertext)
	}
}
impl Packet for SEIPPacket {
    fn parse(mut data: Vec<u8>) -> SEIPPacket {
        assert_eq!(data.remove(0), 0x01, "Incorrect version");
		Self {
            ciphertext: data
        }
    }
	fn serialize(&self) -> Vec<u8> {
		let mut packet = Vec::with_capacity(self.ciphertext.len() + 1);
		packet.push(0x01); // RFC-defined version
		packet.extend(&self.ciphertext);
		packet
	}
}
