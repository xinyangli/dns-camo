# dns-camo

Hide your network traffic in dns requests.

> Sure, I’ll try to summarize the project again based on what I have learned from you.
> 
> The project at https://github.com/xinyangli/dns-camo is a combination of a DNS client and a DNS server that can communicate with each other using encrypted and camouflaged DNS traffic. The data is encrypted with chacha20poly1305 and encoded with base32. The encrypted data is embedded into prefix of DNS query names or as IP addresses in DNS response. The project is written in Rust and uses preshared keys for encryption and decryption. The keys are memorized by the user and not written down. The project can be used to bypass firewalls or censorship that block certain domains or protocols, or to transfer data securely and stealthily without attracting attention from network monitors. However, the project also has some ethical and legal concerns and should be used responsibly and ethically.
> 
> -- New Bing


## How to build

### Native Rust

```bash
cargo build --release
```

### docker-compose

```bash
docker-compose build
```

## Usage

### Client
```bash
Usage: client [OPTIONS] --key <KEY> <DEST> <PORT>

Arguments:
  <DEST>  Server IP address
  <PORT>  Server listening port

Options:
  -k, --key <KEY>    Path to key file
      --data <DATA>  String to be send
  -h, --help         Print help
  -V, --version      Print version
```

### Server

```bash
Usage: server --key <KEY> <PORT>

Arguments:
  <PORT>  Server listening port

Options:
  -k, --key <KEY>  Path to key file
  -h, --help       Print help
  -V, --version    Print version
```
