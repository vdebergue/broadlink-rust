use std::net::{UdpSocket, Ipv4Addr, IpAddr, SocketAddr};
use std::time::Duration;
extern crate time;
extern crate crypto;

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
  socket.set_broadcast(true).expect("set_broadcast failed");

  let addr = socket.local_addr().expect("Could not get local addr");
  let packet = hello_packet(local_ip, addr.port());
  println!("sending packet {:?} on socket {:?}", &packet[0..0x30], socket);
  socket.send_to(&packet, "255.255.255.255:80").expect("couldn't send data");

  let mut buf = [0; 1024];
  socket.set_read_timeout(timeout).expect("set_read_timeout failed");
  let (amt, src) = socket.recv_from(&mut buf).expect("read failed");
  println!("Data from {:?} : {:?}", src, &buf[0..amt]);

  let device = gendevice(src, &buf);
  println!("Got device {:?}", device);

}

fn gendevice(src: SocketAddr, response: &[u8]) -> SP2 {
  let device_type: u16 = (response[0x34] as u16) | (response[0x35] as u16) << 8;
  println!("device type = {:x}", device_type);
  let mut mac = [0; 6];
  mac.copy_from_slice(&response[0x3a..0x40]);
  match device_type {
    0x2728 => {
      SP2::new(src, mac)
    },
    _ => panic!("Unsupported device type {}", device_type),
  }
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
    let year = (now.tm_year + 1900);
    packet[0x0c] = (year & 0xff) as u8;
    packet[0x0d] = (year >> 8) as u8;
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
    packet
}


trait Device {
  fn send_packet(&mut self, command: u8, payload: &[u8]) {
    let mut packet: [u8; 0x38] = [0; 0x38];
    self.device_info_mut().incr_count();
    packet[0x00] = 0x5a;
    packet[0x01] = 0xa5;
    packet[0x02] = 0xaa;
    packet[0x03] = 0x55;
    packet[0x04] = 0x5a;
    packet[0x05] = 0xa5;
    packet[0x06] = 0xaa;
    packet[0x07] = 0x55;
    packet[0x24] = 0x2a;
    packet[0x25] = 0x27;
    packet[0x26] = command;
    packet[0x28] = self.device_info().count as u8;
    packet[0x29] = (self.device_info().count >> 8) as u8;
    packet[0x2a] = self.device_info().mac[0];
    packet[0x2b] = self.device_info().mac[1];
    packet[0x2c] = self.device_info().mac[2];
    packet[0x2d] = self.device_info().mac[3];
    packet[0x2e] = self.device_info().mac[4];
    packet[0x2f] = self.device_info().mac[5];
    packet[0x30] = self.device_info().id[0];
    packet[0x31] = self.device_info().id[1];
    packet[0x32] = self.device_info().id[2];
    packet[0x33] = self.device_info().id[3];

    // payload checksum
    let mut checksum: i32 = 0xbeaf;
    for i in 0..payload.len() {
        checksum += payload[i] as i32;
    }
    packet[0x34] = (checksum & 0xff) as u8;
    packet[0x35] = (checksum >> 8) as u8;

    // encrypt payload
    // let encrypted = self.encrypt(payload);

  }

  fn encrypt(&self, payload: &[u8]) -> &[u8] {
    let mut encryptor = crypto::aes::cbc_encryptor(
      crypto::aes::KeySize::KeySize128,
      &self.device_info().key,
      &self.device_info().iv,
      crypto::blockmodes::PkcsPadding
    );
  }

  fn device_info(&self) -> &DeviceInfo;
  fn device_info_mut(&mut self) -> &mut DeviceInfo;
}

#[derive(Debug)]
struct DeviceInfo {
  addr: SocketAddr,
  mac: [u8; 6],
  count: u16,
  id: [u8; 4],
  iv: [u8; 16],
  key: [u8; 16]
}

impl DeviceInfo {
  fn new(addr: SocketAddr, mac: [u8; 6]) -> DeviceInfo {
    DeviceInfo {
      addr, mac,
      count: 0,
      id: [0; 4],
      iv: [0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58],
      key: [0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]
    }
  }

  fn incr_count(&mut self) {
    self.count = self.count + 1;
  }
}

#[derive(Debug)]
struct SP2 {
  device_info: DeviceInfo
}

impl SP2 {
  fn new(addr: SocketAddr, mac: [u8; 6]) -> SP2 {
    SP2 {
      device_info: DeviceInfo::new(addr, mac)
    }
  }
}

impl Device for SP2 {
  fn device_info(&self) -> &DeviceInfo {
    &self.device_info
  }

  fn device_info_mut(&mut self) -> &mut DeviceInfo {
    &mut self.device_info
  }
}
