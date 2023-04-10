use std::net::{Ipv4Addr, UdpSocket};
use std::path::Path;

use clap::Parser;

use dns_camo::dns_packet::Packet;
use dns_camo::payload::Payload;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to key file
    #[arg(short, long)]
    key: String,

    /// Server listening port
    port: u16,
}

fn main() {
    let args = Args::parse();
    let mut buf = [0u8; 512];
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, args.port)).expect("Error open port");
    loop {
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf).expect("error listening");
        let mut packet = Packet::new(false);
        packet
            .deserialize(buf.iter().take(number_of_bytes))
            .expect("deserialize error");
        let data = packet.extract_data();
        let mut payload = Payload::new(data, Path::new("/tmp/key"), None);
        payload.decrypt().expect("decrypt error");
        println!("{}", payload);

        let mut reply_packet = Packet::new(true);
        let mut reply_data = Vec::new();
        reply_data.push(payload.as_slice().to_vec().len().try_into().expect(""));
        let mut reply_payload = Payload::new(reply_data, Path::new("/tmp/key"), None);
        reply_payload.encrypt().expect("encrypt error");
        reply_packet
            .embed_data(reply_payload.as_slice(), Some(&packet))
            .expect("embed error");

        socket
            .send_to(
                reply_packet
                    .serialize(1)
                    .expect("serialize error")
                    .as_raw_slice(),
                src_addr
            )
            .expect("send error");
    }
}
