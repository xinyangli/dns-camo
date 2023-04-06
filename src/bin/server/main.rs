use std::net::UdpSocket;
use std::path::Path;

use dns_camo::dns_packet::Packet;
use dns_camo::payload::Payload;

fn main() {    
    let mut buf = [0u8; 512];
    let socket = UdpSocket::bind("127.0.0.1:31853").expect("Error open port");
    loop {
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf).expect("error listening");
        let mut packet = Packet::new(None);
        packet.deserialize(buf.iter().take(number_of_bytes)).expect("deserialize error");
        let data = packet.extract_data();
        let mut payload = Payload::new(data, Path::new("/tmp/key"), None);
        payload.decrypt().expect("decrypt error");
        println!("{:?}", payload);
        
        let mut reply_packet = Packet::new(Some(&packet));
        let reply_data = payload.as_slice().to_vec();
        let mut reply_payload = Payload::new(reply_data, Path::new("/tmp/key"), None);
        reply_payload.encrypt().expect("encrypt error");
        reply_packet.embed_data(reply_payload.as_slice()).expect("embed error");

        socket.connect(src_addr).expect("connect error");
        socket.send(reply_packet.serialize(1).expect("serialize error").as_raw_slice()).expect("send error");
    }
}
