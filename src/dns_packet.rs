use crate::payload::Payload;
use bitvec::prelude::*;
use data_encoding::BASE32_DNSSEC;
use std::borrow::BorrowMut;
use std::collections::btree_map::Iter;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::path::Path;
use std::iter;

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
            DnsParseError::UndefinedRecordType(num) => {
                write!(f, "Undefined record type / record class: {}", num)
            }
            DnsParseError::StreamFormatError => write!(f, "Wrong format in DNS packet"),
        }
    }
}

impl error::Error for DnsParseError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecordType {
    A,
    AAAA,
}

impl RecordType {
    fn value(self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
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
            28 => {
                *self = Self::AAAA;
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DnsName {
    Str(Vec<String>),
    // TODO: offset should process in serialization phase, DELETE this member
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
    const FLAG_RESPONSE: u16 = 0b10000000_00000000;
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

#[derive(Debug, PartialEq, Eq, Clone)]
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

    pub fn serialize<T: BitStore + Default + Clone>(&self, target_bv: &mut BitVec<T, Msb0>) {
        self.rname.serialize(target_bv);
        self.rtype.serialize(target_bv);
        self.rclass.serialize(target_bv);
        target_bv.extend_from_bitslice(self.ttl.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(self.data_length.view_bits::<Msb0>());
        target_bv.extend_from_bitslice(&self.data);
        // TODO: More elegant way of alignment
        let gap: i64 = (self.data_length as usize * 8 - self.data.len()).try_into().unwrap();
        if gap > 0 {
            let v: Vec<T> = vec![Default::default(); (gap / 8) as usize];
            target_bv.extend_from_raw_slice(v.as_slice());
        } else if gap < 0 {
            panic!("Wrong data length in record")
        }
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

    is_response: bool,
}

impl Packet {
    pub fn new(is_response: bool) -> Self {
        Packet {
            is_response: is_response,
            ..Self::default()
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
        self.header.flags = if self.is_response {
            Header::FLAG_RESPONSE
        } else {
            0
        };
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
        self.header.deserialize(&mut iter)?;
        let to_modify = [
            (self.header.answers_count, &mut self.answers),
            (self.header.authorities_count, &mut self.authorities),
            (self.header.additional_count, &mut self.additional),
        ];
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
        if self.header.flags & Header::FLAG_RESPONSE == Header::FLAG_RESPONSE {
            self.is_response = true;
        }
        Ok(())
    }

    pub fn embed_data(&mut self, data: &[u8], request: Option<&Packet>) -> Result<(), DnsParseError> {
        // If packet is request, then embed data into prefix of query name
        // else embed data into ip address of answers(or additional if query is inadequate)
        if self.is_response {
            match request {
                Some(req) => {
                    self.questions = req.questions.clone();
                },
                None => {
                    panic!("request not provided for response message!")
                }
            };
            let mut data_iter = data.iter().peekable();
            // TODO: Alignment
            for question in &self.questions {
                let chunk_size: u16 = match question.qtype {
                    RecordType::A => 4,
                    RecordType::AAAA => 16,
                };
                self.answers.push(Record {
                    rname: question.qname.clone(),
                    rtype: question.qtype,
                    rclass: question.qclass,
                    // TODO: Random ttl?
                    ttl: 256,
                    data_length: chunk_size,
                    data: (&mut data_iter).take(chunk_size as usize).collect::<BitVec<u8, Msb0>>(),
                });
            }
            while data_iter.peek() != None {
                self.additional.push(Record {
                    rname: DnsName::Str(vec![String::from("reply"), String::from("com")]),
                    rtype: RecordType::AAAA,
                    rclass: RecordClass::IN,
                    // TODO: Random ttl?
                    ttl: 256,
                    data_length: 16,
                    data: (&mut data_iter).take(16).collect(),
                });
            }
        } else {
            for data_chunk in data.chunks(5) {
                self.questions.push(Question {
                    qname: DnsName::Str(vec![
                        BASE32_DNSSEC.encode(data_chunk),
                        String::from("baidu"),
                        String::from("com"),
                    ]),
                    qtype: RecordType::A,
                    qclass: RecordClass::IN,
                });
            }
        }
        Ok(())
    }

    pub fn extract_data(&mut self) -> Vec<u8> {
        let mut data = Vec::new();
        if self.is_response {
            for answer in &self.answers {
                data.extend_from_slice(answer.data.as_raw_slice())
            }
            for additional in &self.additional {
                data.extend_from_slice(additional.data.as_raw_slice())
            }
        } else {
            for q in &self.questions {
                let data_str = match &q.qname {
                    DnsName::Str(str) => str,
                    DnsName::Offset(_) => panic!("Embeded data can't use offset"),
                };
                data.append(
                    &mut BASE32_DNSSEC
                        .decode(data_str[0].as_bytes())
                        .expect("Error decoding"),
                );
            }
        }
        data
    }
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            header: Default::default(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),

            is_response: false
        }
    }
}

// Tests
use std::net::{SocketAddrV4, UdpSocket};
use std::str::FromStr;

#[test]
fn check_request() -> Result<(), Box<dyn error::Error>> {
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
    let mut p_check = Packet::new(false);
    p_check.deserialize(buf.iter())?;
    assert_eq!(p_check, p);
    Ok(())
}

#[test]
fn check_response() -> Result<(), Box<dyn error::Error>> {
    Ok(())
}
