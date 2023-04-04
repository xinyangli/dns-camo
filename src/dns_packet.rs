use bitvec::prelude::*;
use std::convert::TryInto;
use std::error;
use std::fmt;

#[derive(Debug)]
pub enum DnsParseError {
    // Max length and length of given data
    DataExceedMaxLen(usize, usize),
    UndefinedRecordType(u16),
    StreamFormatError,
}

impl fmt::Display for DnsParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DnsParseError::DataExceedMaxLen(max_len, len) => write!(
                f,
                "Data exceed max length of the field ({}/{})",
                len, max_len
            ),
            DnsParseError::UndefinedRecordType(num) => write!(f, "Undefined record type / record class: {}", num),
            DnsParseError::StreamFormatError => write!(f, "Wrong format in DNS packet"),
        }
    }
}

impl error::Error for DnsParseError {
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    fn deserialize<'a, I>(&mut self, mut iter: I) -> Result<(), DnsParseError>
    where
        I: Iterator<Item = &'a u8>,
    {
        let bytes: [u8; 2] = [*iter.next().unwrap(), *iter.next().unwrap()];
        match u16::from_be_bytes(bytes) {
            1 => {
                *self = Self::A;
                Ok(())
            }
            n => Err(DnsParseError::UndefinedRecordType(n)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    fn deserialize<'a, I>(&mut self, mut iter: I) -> Result<(), DnsParseError>
    where
        I: Iterator<Item = &'a u8>,
    {
        let bytes: [u8; 2] = [*iter.next().unwrap(), *iter.next().unwrap()];
        match u16::from_be_bytes(bytes) {
            1 => {
                *self = Self::IN;
                Ok(())
            }
            255 => {
                *self = Self::ALL;
                Ok(())
            }
            n => Err(DnsParseError::UndefinedRecordType(n)),
        }
    }
}

impl TryFrom<u16> for RecordClass {
    type Error = DnsParseError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RecordClass::IN),

            255 => Ok(RecordClass::ALL),

            n => Err(DnsParseError::UndefinedRecordType(n)),
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
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
    fn deserialize<'a, I>(&mut self, mut iter: I) -> Result<(), DnsParseError>
    where
        I: Iterator<Item = &'a u8>,
    {
        loop {
            let count: usize = match iter.next() {
                Some(0) => {
                    break;
                }
                Some(&val) => val as usize,
                None => {
                    return Err(DnsParseError::StreamFormatError);
                }
            };
            let s = String::from_iter((&mut iter).take(count).map(|&ch| ch as char));
            match self {
                Self::Str(v) => v.push(s),
                Self::Offset(_) => return Err(DnsParseError::StreamFormatError),
            }
        }
        Ok(())
    }
}

impl TryFrom<&String> for DnsName {
    type Error = DnsParseError;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        // TODO: Check length error
        Ok(DnsName::Str(
            value.split('.').map(|str| String::from(str)).collect(),
        ))
    }
}

impl FromStr for DnsName {
    type Err = DnsParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DnsName::Str(
            s.split('.').map(|str| String::from(str)).collect(),
        ))
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
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

    pub fn deserialize<'a, I>(&mut self, mut iter: I) -> Result<(), DnsParseError>
    where
        I: Iterator<Item = &'a u8>,
    {
        let to_modify = [
            &mut self.id,
            &mut self.flags,
            &mut self.questions_count,
            &mut self.answers_count,
            &mut self.authorities_count,
            &mut self.additional_count,
        ];
        for member in to_modify {
            *member = u16::from_be_bytes(
                (&mut iter)
                    .take(2)
                    .cloned()
                    .collect::<Vec<u8>>()
                    .as_slice()
                    .try_into()
                    .map_err(|_| DnsParseError::StreamFormatError)?,
            );
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Question {
    qname: DnsName,
    qtype: RecordType,
    qclass: RecordClass,
}

impl Question {
    fn new() -> Self {
        Question {
            qname: DnsName::Str(vec![]),
            qtype: RecordType::A,
            qclass: RecordClass::ALL,
        }
    }
    pub fn serialize<T: BitStore>(&self, target_bv: &mut BitVec<T, Msb0>) {
        self.qname.serialize(target_bv);
        self.qtype.serialize(target_bv);
        self.qclass.serialize(target_bv);
    }

    pub fn deserialize<'a, I>(&mut self, mut iter: I) -> Result<(), DnsParseError>
    where
        I: Iterator<Item = &'a u8>,
    {
        self.qname.deserialize(&mut iter)?;
        self.qtype.deserialize(&mut iter)?;
        self.qclass.deserialize(&mut iter)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Record {
    rname: DnsName,
    rtype: RecordType,
    rclass: RecordClass,
    ttl: u32,
    data_length: u16,
    data: BitVec<u8, Msb0>,
}

impl Record {
    fn new() -> Self {
        Self {
            rname: DnsName::Str(vec![]),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl: 0,
            data_length: 0,
            data: BitVec::new(),
        }
    }

    pub fn serialize<T: BitStore>(&self, target_bv: &mut BitVec<T, Msb0>) {
        self.rname.serialize(target_bv);
        self.rtype.serialize(target_bv);
        self.rclass.serialize(target_bv);
        target_bv.extend_from_bitslice(self.ttl.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.data_length.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(&self.data);
    }

    fn deserialize<'a, I>(&mut self, mut iter: I) -> Result<(), DnsParseError>
    where
        I: Iterator<Item = &'a u8>,
    {
        self.rname.deserialize(&mut iter)?;
        self.rtype.deserialize(&mut iter)?;
        self.rclass.deserialize(&mut iter)?;
        self.ttl = u32::from_be_bytes(
            (&mut iter)
                .take(4)
                .cloned()
                .collect::<Vec<u8>>()
                .as_slice()
                .try_into()
                .map_err(|_| DnsParseError::StreamFormatError)?,
        );
        self.data_length = u16::from_be_bytes(
            (&mut iter)
                .take(2)
                .cloned()
                .collect::<Vec<u8>>()
                .as_slice()
                .try_into()
                .map_err(|_| DnsParseError::StreamFormatError)?,
        );
        self.data = (&mut iter).take(self.data_length as usize).collect();
        if self.data.len() != self.data_length as usize {
            return Err(DnsParseError::StreamFormatError);
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Packet {
    header: Header,

    questions: Vec<Question>,

    answers: Vec<Record>,

    authorities: Vec<Record>,

    additional: Vec<Record>,
}

impl Packet {
    pub fn new() -> Self {
        Packet {
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

    pub fn deserialize<'a, I>(&mut self, mut iter: I) -> Result<(), DnsParseError>
    where
        I: Iterator<Item = &'a u8>,
    {
        let to_modify = [
            (self.header.answers_count, &mut self.answers),
            (self.header.answers_count, &mut self.authorities),
            (self.header.answers_count, &mut self.additional),
        ];
        self.header.deserialize(&mut iter)?;
        for _ in 0..self.header.questions_count {
            let mut q = Question::new();
            q.deserialize(&mut iter)?;
            self.questions.push(q);
        }
        for (count, modify) in to_modify {
            for _ in 0..count {
                let mut a = Record::new();
                a.deserialize(&mut iter)?;
                modify.push(a);
            }
        }
        Ok(())
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}

// Tests
use std::net::{SocketAddrV4, UdpSocket};
use std::str::FromStr;

#[test]
fn check_request() -> Result<(), Box<dyn error::Error>> {
    let socket = UdpSocket::bind("127.0.0.1:34254")?;
    let mut p = Packet {
        questions: vec![Question {
            qname: DnsName::from_str("abc.xyz.com").unwrap(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        }],
        ..Default::default()
    };
    let binding = p.serialize(1).unwrap();
    let buf = binding.as_raw_slice();
    assert_eq!(binding.len(), 232);
    assert_eq!(
        &buf[12..25],
        [
            0b11, 0b1100001, 0b1100010, 0b1100011, 0b11, 0b1111000, 0b1111001, 0b1111010, 0b11,
            0b1100011, 0b1101111, 0b1101101, 0b0
        ]
    );

    // let dest = SocketAddrV4::from_str("127.0.0.1:53").unwrap();
    // socket.send_to(buf.as_raw_slice(), dest)?;
    let mut p_check = Packet::new();
    p_check.deserialize(buf.iter())?;
    assert_eq!(p_check, p);
    Ok(())
}

#[test]
fn check_response() -> Result<(), Box<dyn error::Error>> {

    Ok(())
}
