use std::{
    error,
    net::{SocketAddrV4, UdpSocket}, str::FromStr,
    path::Path
};

use dns_camo::dns_packet::{Packet, RecordType};
use dns_camo::payload::Payload;

fn main() {    
    let data: &[u8] = "Hello World!".as_bytes();
    // let data = [0x0; 32];
    let mut payload = Payload::new(data.to_vec(), Path::new("/tmp/key"), None);
    payload.encrypt().expect("");
    let mut packet = Packet::new(None);
    packet.embed_data(payload.as_slice()).expect("embed error");
    
    let socket = UdpSocket::bind("127.0.0.1:34254").expect("Error open port");
    let dest = SocketAddrV4::from_str("127.0.0.1:31853").unwrap();
    socket.connect(dest).expect("connect error");
    socket.send(packet.serialize(1).expect("serialization error").as_raw_slice()).expect("send error");

}
