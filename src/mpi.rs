use std::ops::Deref;
use num::*;

pub struct MPI {
    /// Size of MPI in bits
    size: u16,
    backing: BigUint
}
impl MPI {
    pub fn from_num(num: BigUint) -> Self {
        Self {
            size: num.bits() as u16,
            backing: num,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let backing = BigUint::from_bytes_be(bytes);
        MPI::from_num(backing)
    }
    pub fn parse(bytes: &[u8]) -> Self {
        assert!(bytes.len() > 2, "Invalid MPI");

        let size = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self {
            size,
            backing: BigUint::from_bytes_be(&bytes[2..MPI::bits_to_bytes(size)]),
        }
    }
    fn bits_to_bytes(bits: u16) -> usize {
        let size = (bits + 8 - 1) / 8;
        (size + 2) as usize
    }

    pub fn size_in_bytes(&self) -> usize {
        MPI::bits_to_bytes(self.size)
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = self.backing.to_bytes_be();
        let bits = (self.backing.bits() as u16).to_be_bytes();
        bytes.insert(0, bits[0]);
        bytes.insert(1, bits[1]);
        bytes
    }
}
impl Deref for MPI {
    type Target = BigUint;
    fn deref(&self) -> &BigUint {
        &self.backing
    }
}
