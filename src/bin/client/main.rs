use std::{
    error,
    io::{self, Read},
    net::{IpAddr, SocketAddr, UdpSocket},
    path::Path,
    str::FromStr,
};

use clap::Parser;

use dns_camo::dns_packet::{Packet, RecordType};
use dns_camo::payload::Payload;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to key file
    #[arg(short, long)]
    key: String,

    /// String to be send
    #[arg(long)]
    data: Option<String>,

    /// Server IP address
    dest: String,

    /// Server listening port
    port: u16,
}

fn main() {
    let args = Args::parse();
    let mut stdin_buffer = Vec::new();
    let data: &[u8] = match &args.data {
        Some(str) => str.as_bytes(),
        None => {
            let mut stdin = io::stdin();
            stdin.read_to_end(&mut stdin_buffer).expect("io error");
            stdin_buffer.as_slice()
        }
    };
    let dest_addr = SocketAddr::new(
        IpAddr::from_str(&args.dest).expect("Invalid IP address provided"),
        args.port.into(),
    );

    let mut payload = Payload::new(data.to_vec(), Path::new(&args.key), None);
    let mut packet = Packet::new(false);
    payload.encrypt().expect("");
    packet
        .embed_data(payload.as_slice(), None)
        .expect("embed error");

    let socket = UdpSocket::bind("0.0.0.0:0").expect("");
    socket
        .send_to(
            packet
                .serialize(1)
                .expect("serialization error")
                .as_raw_slice(),
            &dest_addr,
        )
        .expect("send error");

    let mut buf = [0u8; 512];
    socket.recv_from(&mut buf).expect("recv error");
    let mut recv_packet = Packet::new(true);
    recv_packet
        .deserialize(buf.iter())
        .expect("deserialize error");
    let recv_data = recv_packet.extract_data();
    let mut recv_payload = Payload::new(recv_data.to_vec(), Path::new(&args.key), None);
    recv_payload.decrypt().expect("decrypt error");

    println!("{}", recv_payload);
}
