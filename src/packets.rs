use std::io::Read;
use std::ops::Drop;
use sloppy_rfc4880::{ Parser, Tag };

//use crate::packets::public_key::PublicKeyPacket;
mod public_key;
use public_key::PublicKeyPacket;
mod pkesk;
use pkesk::PKESKPacket;
mod seip;
use seip::SEIPPacket;
mod data;
use data::{ LiteralPacket, CompressedPacket };

#[derive(Debug)]
pub enum Packets {
    PublicKey(PublicKeyPacket),
    PublicKeyEncryptedSessionKey(PKESKPacket),
    SymIntData(SEIPPacket),
    Literal(LiteralPacket),
    Compressed(CompressedPacket),
    Unknown(Tag, UnknownPacket),
}
pub trait Packet {
    fn parse(data: Vec<u8>) -> Self;
    fn serialize(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub struct UnknownPacket { data: Vec<u8> }
impl Packet for UnknownPacket {
    fn parse(data: Vec<u8>) -> UnknownPacket {
        UnknownPacket { data: data.to_vec() }
    }
    fn serialize(&self) -> Vec<u8> { self.data.clone() }
}

pub struct SymmetricKey {
    pub algo: u8,
    pub key: [u8; 32],
}
impl Drop for SymmetricKey {
    fn drop(&mut self) {
        for i in 0..self.key.len() {
            self.key[i] = 0;
        }
    }
}

pub fn read<R: Read>(input: R) -> Vec<Packets> {
    let mut parser = Parser::new(input);
    let mut packets: Vec<Packets> = Vec::new();

    while let Some((tag, packet)) = parser.next() {
        packets.push(match tag {
            Tag::PublicKey | Tag::PublicSubkey => Packets::PublicKey(PublicKeyPacket::parse(packet)),
            Tag::PublicKeyEncryptedSessionKey => Packets::PublicKeyEncryptedSessionKey(PKESKPacket::parse(packet)),
            Tag::SymIntData => Packets::SymIntData(SEIPPacket::parse(packet)),
            Tag::LiteralData => Packets::Literal(LiteralPacket::parse(packet)),
            Tag::CompressedData => Packets::Compressed(CompressedPacket::parse(packet)),
            _ => Packets::Unknown(tag, UnknownPacket::parse(packet)),
        });
    }
    packets
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
