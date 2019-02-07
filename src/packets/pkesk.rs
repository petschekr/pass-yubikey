use std::{ fmt, cmp };

use crate::mpi::MPI;
use crate::packets::{ Packet, SymmetricKey };
use crate::packets::public_key::PublicKeyPacket;
use crate::smartcard::{ PGPCard, Error };

const KEY_LEN: usize = 32;

pub struct PKESKPacket {
    pub key_id: [u8; 8],
    pub algo: u8,
	ciphertext: MPI,
}
impl fmt::Debug for PKESKPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Public Key Encrypted Session Key")
            .field("key_id", &format!("{:x?}", self.key_id))
            .field("algorithm", &self.algo)
            .finish()
    }
}
impl fmt::Display for PKESKPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x?}", self.key_id)
    }
}
impl PKESKPacket {
	pub fn decrypt_with_card(&self, card: &PGPCard) -> Result<SymmetricKey, Error> {
		// Byte 0 is actually being reused for the padding byte which gets discarded by the YubiKey later but needs to be sent
		// Defined to be 0x00 by the standard but the YubiKey doesn't actually check this
		let data = &self.ciphertext.serialize()[1..];
		let size = data.len();
		assert_eq!(size, 256 + 1, "Encrypted text is wrong size");

		let mut offset: usize = 0;
		while offset < size {
			let current_length = cmp::min(254, size - offset);
			let is_last = offset + current_length >= size;
			let cla: u8 = if is_last { 0x00 } else { 1 << 4 };

			let mut apdu = vec![cla, 0x2A, 0x80, 0x86, current_length as u8];
			apdu.extend_from_slice(&data[offset..offset + current_length]);
			if is_last {
				apdu.push(0x00);
			}
			let response = card.send_data(&apdu)?.data;
			if is_last {
				let key_algo = response[0];
				let mut key = [0u8; KEY_LEN];
				key.copy_from_slice(&response[1..response.len() - 2]);

				let mut final_checksum = [0u8; 2];
				final_checksum.copy_from_slice(&response[response.len() - 2..]);
				let final_checksum = u16::from_be_bytes(final_checksum);

				let checksum = key.iter().map(|&x| x as usize).sum::<usize>() & 0xffff;
				assert_eq!(checksum as u16, final_checksum, "Session key checksum failed");
				return Ok(SymmetricKey { algo: key_algo, key });
			}
			offset += current_length;
		};
		Err(Error::from(pcsc::Error::UnknownError))
	}

	// TODO: allow for multiple recipients
	// TODO: don't require a smart card to get randomness
	pub fn encrypt(recipient: &PublicKeyPacket, card: &PGPCard) -> Result<Self, Error> {
		let mut psk = Vec::with_capacity(1 + KEY_LEN + 2);
		let mut session_key = card.get_random_bytes(KEY_LEN as u8)?;
		// TODO: Don't statically use AES-256 for encryption
		psk.push(0x09);
		psk.append(&mut session_key);
		let checksum = session_key.iter().map(|&x| x as usize).sum::<usize>() & 0xffff;
		psk.push((checksum >> 8) as u8);
		psk.push((checksum >> 0) as u8);

		assert!(psk.len() <= 256 - 11, "Message size too big");
		let mut plaintext = vec![0x00, 0x02];
		let padding_length = 256 - 3 - psk.len();
		let mut padding: Vec<u8> = vec![0; padding_length];
		// The padding bytes cannot contain 0x00
		while padding.contains(&0) {
			padding = card.get_random_bytes(padding_length as u8)?;
		}
		plaintext.extend_from_slice(&padding);
		plaintext.push(0x00);
		plaintext.extend_from_slice(&psk);
		assert_eq!(plaintext.len(), 256, "PKCS #1 failed");

		let plaintext = MPI::from_bytes(&plaintext);
		let ciphertext = MPI::from_num(plaintext.modpow(&recipient.exponent, &recipient.modulus));

		let mut key_id = [0u8; 8];
		key_id.copy_from_slice(&recipient.fingerprint[20 - 8..]);

		Ok(Self {
			key_id,
			algo: 0x01, // RSA is public-key algorithm
			ciphertext,
		})
	}

	pub fn serialize(&self) -> Vec<u8> {
		let mut packet = vec![0x03];
		packet.extend(&self.key_id);
		packet.push(self.algo);
		packet.extend(self.ciphertext.serialize());
		packet
	}
}
impl Packet for PKESKPacket {
    fn parse(data: Vec<u8>) -> PKESKPacket {
        assert_eq!(data[0], 0x03, "Malformed PKESK version");
		assert_eq!(data[9], 0x01, "Only RSA supported");
		assert!(data.len() > 12, "PKESK packet too short");

		// Byte 9: 0x01 (version)
		// Byte 10 - 11: MPI size in bits (skip over)
		let mut key_id = [0u8; 8];
		key_id.copy_from_slice(&data[1..9]);
		let ciphertext = MPI::parse(&data[10..]);
		assert!((ciphertext.size_in_bytes() - 2) & 0xff == 0, "Invalid ciphertext in packet");

		Self {
			key_id,
			algo: data[9],
			ciphertext,
		}
    }
	fn serialize(&self) -> Vec<u8> {
		let mut packet = Vec::new();
		packet.push(0x03); // Static version as defined in the RFC
		packet.extend(self.key_id.iter());
		packet.push(0x01); // RSA
		packet.extend(self.ciphertext.serialize());
		packet
	}
}
