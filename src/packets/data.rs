use std::fmt;
use std::str;
use std::string::ToString;
use std::io::Read;

use crate::packets::Packet;

#[derive(Debug, Clone, Copy)]
pub enum DataType {
	Binary = 0x62,
	Text = 0x74,
	UTF8 = 0x75,
	Unknown,
}

pub struct LiteralPacket {
    pub data_type: DataType,
	pub filename: String,
	pub timestamp: u32,
	pub data: Vec<u8>,
}
impl fmt::Debug for LiteralPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Literal Data")
			.field("type", &self.data_type)
			.field("filename", &self.filename)
			.field("timestamp", &self.timestamp)
			.field("length", &self.data.len())
			.finish()
    }
}
// impl fmt::Display for LiteralPacket {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "Literal data: {} bytes", self.data.len())
//     }
// }
impl ToString for LiteralPacket {
	fn to_string(&self) -> String {
		String::from_utf8(self.data.clone()).unwrap()
	}
}

impl LiteralPacket {
	fn new(filename: &str, timestamp: u32, text: &str) -> Self {
		Self {
			data_type: DataType::UTF8,
			filename: filename.to_string(),
			timestamp,
			data: text.as_bytes().to_vec(),
		}
	}
}
impl Packet for LiteralPacket {
    fn parse(mut data: Vec<u8>) -> LiteralPacket {
		let data_type = match data[0] {
			0x62 => DataType::Binary,
			0x74 => DataType::Text,
			0x75 => DataType::UTF8,
			_ => DataType::Unknown,
		};
		let filename_length = data[1] as usize;
		let filename = str::from_utf8(&data[2..2 + filename_length]).unwrap().to_string();

		let mut timestamp = [0u8; 4];
		timestamp.copy_from_slice(&data[2 + filename_length..2 + filename_length + 4]);
		let timestamp = u32::from_be_bytes(timestamp);

		data.drain(..6 + filename_length);
		Self {
			data_type,
			filename,
			timestamp,
			data,
		}
    }
	fn serialize(&self) -> Vec<u8> {
		let mut packet = Vec::new();
		packet.push(self.data_type as u8);
		packet.push(self.filename.len() as u8);
		packet.extend(self.filename.bytes());
		packet.extend(self.timestamp.to_be_bytes().iter());
		packet.extend(&self.data);
		packet
	}
}

#[derive(Debug, Copy, Clone)]
pub enum CompressionAlgorithm {
	Uncompressed = 0,
	ZIP = 1,
	ZLib = 2,
	BZip2 = 3,
}
pub struct CompressedPacket {
    pub compression: CompressionAlgorithm,
	pub data: Vec<u8>,
}
impl fmt::Debug for CompressedPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Compressed Data")
			.field("type", &self.compression)
			.field("length", &self.data.len())
			.finish()
    }
}
impl fmt::Display for CompressedPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Compressed data: {} bytes", self.data.len())
    }
}

impl CompressedPacket {
	pub fn get_packets(&self) -> Vec<u8> {
		let mut decoded = Vec::new();
		match self.compression {
			CompressionAlgorithm::ZIP => libflate::deflate::Decoder::new(self.data.as_slice()).read_to_end(&mut decoded).unwrap(),
			CompressionAlgorithm::ZLib => libflate::zlib::Decoder::new(self.data.as_slice()).unwrap().read_to_end(&mut decoded).unwrap(),
			_ => panic!("Compression type {:?} not supported", self.compression),
		};
		decoded
	}
}
impl Packet for CompressedPacket {
    fn parse(mut data: Vec<u8>) -> CompressedPacket {
		let compression = match data.remove(0) {
			1 => CompressionAlgorithm::ZIP,
			2 => CompressionAlgorithm::ZLib,
			3 => CompressionAlgorithm::BZip2,
			_ => CompressionAlgorithm::Uncompressed,
		};
		Self {
			compression,
			data,
		}
    }
	fn serialize(&self) -> Vec<u8> {
		let mut packet = Vec::with_capacity(self.data.len() + 1);
		packet.push(self.compression as u8);
		packet.extend(&self.data);
		packet
	}
}
