use bitvec::prelude::*;

#[derive(Debug)]
pub enum DnsParseError {
    // Max length and length of given data
    DataExceedMaxLen(usize, usize),
    UndefinedMessageType,
}

#[derive(Clone, Copy)]
pub enum RecordType {
    A,
}

impl RecordType {
    fn value(self) -> u16 {
        match self {
            Self::A => 1,
        }
    }
    pub fn serialize<T: BitStore>(self, target_bv: &mut BitVec<T, Msb0>) {
        target_bv.extend_from_bitslice(self.value().view_bits::<Msb0>());
    }
}

#[derive(Clone, Copy)]
pub enum RecordClass {
    IN,

    // Following Fields only valid in QCLASS field of question section.
    ALL,
}

impl RecordClass {
    fn value(self) -> u16 {
        match self {
            Self::IN => 1,

            Self::ALL => 255,
        }
    }
    fn serialize<T: BitStore>(self, target_bv: &mut BitVec<T, Msb0>) {
        target_bv.extend_from_bitslice(self.value().view_bits::<Msb0>());
    }
}

impl TryFrom<u16> for RecordClass {
    type Error = DnsParseError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RecordClass::IN),

            255 => Ok(RecordClass::ALL),

            _ => Err(DnsParseError::UndefinedMessageType),
        }
    }
}
pub enum DnsName {
    Str(Vec<String>),
    // Pointer to name label already in buffer.
    // Compress repeated domain names (or part of it, E.g a.b.com b.com).
    Offset(u16),
}

impl DnsName {
    fn serialize<T: BitStore>(&self, target_bv: &mut BitVec<T, Msb0>) {
        match self {
            DnsName::Str(labels) => {
                for label in labels {
                    let len: u8 = label.len().try_into().unwrap();
                    // TODO: String length check
                    target_bv.extend_from_bitslice(len.view_bits::<Msb0>());
                    label
                        .chars()
                        .map(|ch| ch.try_into().unwrap())
                        .for_each(|b: u8| target_bv.extend_from_bitslice(b.view_bits::<Msb0>()))
                }
                target_bv.extend_from_bitslice(0u8.view_bits::<Msb0>());
            }
            DnsName::Offset(offset) => {
                // TODO: Offset in range
                // TODO: Write test to check first two bit
                target_bv.extend_from_bitslice((offset | 0xCu16).view_bits::<Msb0>());
            }
        };
    }
}

impl TryFrom<&String> for DnsName {
    type Error = DnsParseError;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        // TODO: Check length error
        Ok(DnsName::Str(
            value.split('.')
                 .map(|str| String::from(str))
                 .collect()))
    }
}

impl FromStr for DnsName {
    type Err = DnsParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DnsName::Str(
            s.split('.')
             .map(|str| String::from(str))
             .collect()))
    }
}

#[derive(Default)]
struct Header {
    id: u16,
    flags: u16,
    questions_count: u16,
    answers_count: u16,
    authorities_count: u16,
    additional_count: u16,
}

impl Header {
    pub fn serialize<T: BitStore>(&self, target_bv: &mut BitVec<T, Msb0>) {
        target_bv.extend_from_bitslice(self.id.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.flags.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.questions_count.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.answers_count.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.authorities_count.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.additional_count.view_bits::<Msb0>());
    }
}

struct Question {
    qname: DnsName,
    qtype: RecordType,
    qclass: RecordClass,
}

impl Question {
    pub fn serialize<T: BitStore>(&self, target_bv: &mut BitVec<T, Msb0>) {
        self.qname.serialize(target_bv);
        self.qtype.serialize(target_bv);
        self.qclass.serialize(target_bv);
    }
}

struct Record {
    rname: DnsName,
    rtype: RecordType,
    rclass: RecordClass,
    ttl: u32,
    data_length: u16,
    data: BitVec<u8, Msb0>,
}

impl Record {
    pub fn serialize<T: BitStore>(&self, target_bv: &mut BitVec<T, Msb0>) {
        self.rname.serialize(target_bv);
        self.rtype.serialize(target_bv);
        self.rclass.serialize(target_bv);
        target_bv.extend_from_bitslice(self.ttl.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.data_length.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(&self.data);
    }
}

pub struct Message {
    header: Header,

    questions: Vec<Question>,

    answers: Vec<Record>,

    authorities: Vec<Record>,

    additional: Vec<Record>,
}

impl Message {
    pub fn new() -> Self {
        Message {
            header: Default::default(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    fn header_gen(&mut self, id: u16) -> Result<(), DnsParseError> {
        // Fill id and length fields in header
        let try_usize_to_u16 = |x: usize| match x.try_into() {
            Ok(y) => Ok(y),
            Err(_) => Err(DnsParseError::DataExceedMaxLen(std::u16::MAX as usize, x)),
        };
        self.header.id = id;
        self.header.questions_count = try_usize_to_u16(self.questions.len())?; 
        self.header.answers_count = try_usize_to_u16(self.answers.len())?;
        self.header.authorities_count = try_usize_to_u16(self.authorities.len())?;
        self.header.additional_count = try_usize_to_u16(self.additional.len())?;
        Ok(())
    }

    pub fn serialize(&mut self, id: u16) -> Result<BitVec<u8, Msb0>, DnsParseError> {
        let mut buf = bitvec![u8, Msb0;];
        self.header_gen(id)?;

        self.header.serialize(&mut buf);
        self.questions.iter().for_each(|q| q.serialize(&mut buf));
        self.answers.iter().for_each(|a| a.serialize(&mut buf));
        self.authorities.iter().for_each(|a| a.serialize(&mut buf));
        self.additional.iter().for_each(|a| a.serialize(&mut buf));

        Ok(buf)
    }

}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

use std::borrow::BorrowMut;
use std::collections::hash_map::DefaultHasher;
use std::net::{SocketAddrV4, UdpSocket};
use std::str::FromStr;

#[test]
fn check_buffer_bit_order() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:34254")?;
    let mut m = Message {
        questions: vec![ Question {
            qname: DnsName::from_str("abc.xyz.com").unwrap(),
            qtype: RecordType::A,
            qclass: RecordClass::IN
        }],
        ..Default::default()
    };
    let buf: BitVec<u8, Msb0> = m.serialize(1).unwrap();
    assert_eq!(buf.len(), 232);
    assert_eq!(&buf.as_raw_slice()[12..25], [
        0b11,
        0b1100001,
        0b1100010,
        0b1100011,
        0b11,
        0b1111000,
        0b1111001,
        0b1111010,
        0b11,
        0b1100011,
        0b1101111,
        0b1101101,
        0b0
    ]);

    // let dest = SocketAddrV4::from_str("127.0.0.1:53").unwrap();
    // socket.send_to(buf.as_raw_slice(), dest)?;

    Ok(())
}
