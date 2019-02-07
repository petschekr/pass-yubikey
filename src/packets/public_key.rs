use std::fmt;
use crypto::sha1::Sha1;
use crypto::digest::Digest;

use crate::mpi::MPI;
use crate::packets::Packet;

pub struct PublicKeyPacket {
    pub timestamp: u32,
    pub modulus: MPI,
    pub exponent: MPI,
    pub fingerprint: [u8; 20],
}
impl fmt::Debug for PublicKeyPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Public Key")
            .field("fingerprint", &format!("{:x?}", self.fingerprint))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}
impl fmt::Display for PublicKeyPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x?}", self.fingerprint)
    }
}
impl PublicKeyPacket {

}
impl Packet for PublicKeyPacket {
    fn parse(data: Vec<u8>) -> PublicKeyPacket {
        assert_eq!(data[0], 0x04, "Only public keys of version 4 are supported");
        assert_eq!(data[5], 0x01, "Only RSA keys are currently supported");

        let mut hasher = Sha1::new();
        let mut fingerprint_header: Vec<u8> = vec![0x99];
        fingerprint_header.extend(&(data.len() as u16).to_be_bytes());
        fingerprint_header.extend(&data);
        hasher.input(&fingerprint_header);
        let mut fingerprint = [0u8; 20];
        hasher.result(&mut fingerprint);

        let mut timestamp = [0u8; 4];
        timestamp.copy_from_slice(&data[1..5]);
        let timestamp = u32::from_be_bytes(timestamp);
        let mpis = &data[6..];
        let n = MPI::parse(mpis);
        let e = MPI::parse(&mpis[MPI::size_in_bytes(&n)..]);
        Self {
            timestamp,
            modulus: n,
            exponent: e,
            fingerprint,
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x04);
        packet.extend(self.timestamp.to_be_bytes().iter());
        packet.push(0x01); // RSA
        packet.extend(self.modulus.serialize());
        packet.extend(self.exponent.serialize());
        packet
    }
}
