use std::net::{UdpSocket, Ipv4Addr, IpAddr, SocketAddr};
use std::time::Duration;
extern crate time;

fn main() {
    println!("Hello, world!");
    let local_ip = get_local_ip();
    println!("Got local ip: {}", local_ip);
    match local_ip {
        IpAddr::V4(ip) => discover(ip, Some(Duration::from_secs(5))),
        _ => println!("no ipv4"),
    }
    
}

fn get_local_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    socket.connect("8.8.8.8:53").expect("connect failed");
    let addr = socket.local_addr().expect("Could not get local addr");
    addr.ip()
}

fn discover(local_ip: Ipv4Addr, timeout: Option<Duration>) {
  let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), 0)).expect("bind failed");
  socket.set_read_timeout(timeout).expect("set_read_timeout failed");
  socket.set_broadcast(true).expect("set_broadcast failed");

  let addr = socket.local_addr().expect("Could not get local addr");
  let packet = hello_packet(local_ip, addr.port());
  println!("sending packet {:?} on socket {:?}", &packet[0..0x30], socket);
  socket.send_to(&packet, "255.255.255.255:80").expect("couldn't send data");

  let mut buf = [0; 1024];
  let (amt, src) = socket.recv_from(&mut buf).expect("read failed");

  println!("Data from {:?} : {:?}", src, &buf[0..amt]);
}

fn hello_packet(local_ip: Ipv4Addr, port: u16) -> [u8; 0x30] {
    let now = time::now();
    let timezoneOffset: i32 = now.tm_utcoff / 3600 * -1;
    let mut packet: [u8; 0x30] = [0; 0x30];
    if (timezoneOffset < 0) {
        packet[0x08] = (0xff + (timezoneOffset) - 1) as u8;
        packet[0x09] = 0xff;
        packet[0x0a] = 0xff;
        packet[0x0b] = 0xff;
    } else {
        packet[0x08] = timezoneOffset as u8;
    }
    // write_u32_le(&mut packet, timezoneOffset as u32, 0x08);
    let year = (now.tm_year + 1900);
    packet[0x0c] = (year & 0xff) as u8;
    packet[0x0d] = (year >> 8) as u8;
    // write_u16_le(&mut packet, (now.tm_year + 1900) as u16, 0x0c);
    // packet[0x0e] = now.tm_sec as u8;
    packet[0x0e] = now.tm_min as u8;
    packet[0x0f] = now.tm_hour as u8;
    packet[0x10] = (now.tm_year + 1900 - 2000) as u8;
    packet[0x11] = now.tm_wday as u8;
    packet[0x12] = now.tm_mday as u8;
    packet[0x13] = now.tm_mon as u8;
    packet[0x18] = local_ip.octets()[0];
    packet[0x19] = local_ip.octets()[1];
    packet[0x1a] = local_ip.octets()[2];
    packet[0x1b] = local_ip.octets()[3];
    packet[0x1c] = (port & 0xff) as u8;
    packet[0x1d] = (port >> 8) as u8;
    packet[0x26] = 6;
    let mut checksum: i32 = 0xbeaf;

    for i in 0..packet.len() {
        checksum += packet[i] as i32;
    }
    packet[0x20] = (checksum & 0xff) as u8;
    packet[0x21] = (checksum >> 8) as u8;
    // write_u16_le(&mut packet, (checksum & 0xffff) as u16 ,0x20);
    packet
}

fn write_u32_le(buffer: &mut [u8], value: u32, offset: usize) -> usize {
    let mut off = offset;
    if (off >= buffer.len()) { return off };
    buffer[off] = value as u8;
    off += 1;
    if (off >= buffer.len()) { return off };
    buffer[off] = (value >> 8) as u8;
    off += 1;
    if (off >= buffer.len()) { return off };
    buffer[off] = (value >> 16) as u8;
    off += 1;
    if (off >= buffer.len()) { return off };
    buffer[off] = (value >> 24) as u8;
    off += 1;
    off
}

fn write_u16_le(buffer: &mut [u8], value: u16, offset: usize) -> usize {
    let mut off = offset;
    if (off >= buffer.len()) { return off };
    buffer[off] = value as u8;
    off += 1;
    if (off >= buffer.len()) { return off };
    buffer[off] = (value >> 8) as u8;
    off += 1;
    off
}

#[test]
fn test_writes() {
    let mut buf: [u8; 4] = [0; 4];
    write_u32_le(&mut buf, 256, 0);
    assert_eq!(buf, [0, 1, 0, 0]);

    write_u32_le(&mut buf, 256, 2);
    assert_eq!(buf, [0, 1, 0, 1]);
}


#[test]
fn test_packets() {
    let mut packet: [u8; 3] = [0; 3];
    packet[0x0] = 0xff;
    packet[2] = 2;
    assert_eq!(packet, [0xff, 0, 2]);
}