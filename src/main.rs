//! Minimal DTLS example using rust-openssl

use openssl::error::ErrorStack;
use openssl::sha::Sha256;
use openssl::ssl::{self, Ssl, SslContextBuilder, SslMethod, SslVerifyMode};

use std::io::{Read, Write};
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

const SERVER_ADDRESS: &str = "localhost:1234";
const CLIENT_ADDRESS: &str = "localhost:4321";

const TIMEOUT_MS: u64 = 300;

const CA_FILE: &str = "src/certs/ca-cert.pem";
const SERVER_CERT: &str = "src/certs/server-cert.pem";
const SERVER_KEY: &str = "src/keys/server-key.pem";
const CLIENT_CERT: &str = "src/certs/client-cert.pem";
const CLIENT_KEY: &str = "src/keys/client-key.pem";

// Size of a cookie in bytes which is also the size of a SHA256 sum.
const COOKIE_LEN: usize = 32;

// Signal to stop the DoS client
static STOP: AtomicBool = AtomicBool::new(false);

/// Wrapper around UdpSocket that implements the Read and Write traits required
/// by Ssl::connect and Ssl::accept methods.
#[derive(Debug)]
struct UdpStream {
    socket: UdpSocket,
    connected: bool,
}

impl Read for UdpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.connected {
            self.socket.recv(buf)
        } else {
            match self.socket.recv_from(buf) {
                Ok((bytes, addr)) => {
                    self.connect(addr)?;
                    Ok(bytes)
                }
                Err(e) => Err(e),
            }
        }
    }
}

impl Write for UdpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.send(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl UdpStream {
    /// Binds to the given address and sets timeouts to reasonable values.
    pub fn new<A: ToSocketAddrs>(addr: A) -> std::io::Result<UdpStream> {
        let socket = UdpSocket::bind(addr)?;
        let duration = Duration::from_millis(TIMEOUT_MS);
        socket.set_read_timeout(Some(duration))?;
        socket.set_write_timeout(Some(duration))?;
        Ok(UdpStream {
            socket,
            connected: false,
        })
    }
    /// Connects the UDP socket to the given address.
    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> std::io::Result<()> {
        self.socket.connect(addr)?;
        self.connected = true;
        Ok(())
    }
}

/// Copy the address pointed to by the `SslRef` pointer to the first few bytes
/// of the salted buffer then use that to compute a SHA256 sum.
fn compute_hash(ssl_ptr: *const ssl::SslRef, buf: &mut [u8], cookie: &mut [u8]) {
    let buf_ptr: *mut *const ssl::SslRef = buf.as_mut_ptr().cast();
    unsafe {
        *buf_ptr = ssl_ptr;
    }

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let hash = hasher.finish();

    for (src, val) in cookie.iter_mut().zip(hash.iter()) {
        *src = *val;
    }
}

/// Server that accepts connection. Attempts to prevent flooding using stateless cookies.
/// Mutually verifies the client by also requesting a certificate.
fn server_thread() {
    let mut context_builder = SslContextBuilder::new(SslMethod::dtls()).unwrap();
    context_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    context_builder.set_ca_file(CA_FILE).unwrap();
    context_builder
        .set_certificate_file(SERVER_CERT, ssl::SslFiletype::PEM)
        .unwrap();
    context_builder
        .set_private_key_file(SERVER_KEY, ssl::SslFiletype::PEM)
        .unwrap();

    // Buffer whose [start..] bytes contain a random salt. The [..start] bytes of
    // a copy of the buffer is used for writing the `SslRef` pointer.
    let salt: Arc<RwLock<[u8; COOKIE_LEN]>> = Arc::new(RwLock::new([0; COOKIE_LEN]));
    {
        // randomize the salt
        let start = std::mem::size_of::<*const ssl::SslRef>();
        let buf = &mut salt.write().unwrap()[start..];
        openssl::rand::rand_bytes(buf).unwrap();
    }
    let salt_clone = salt.clone();

    context_builder.set_options(ssl::SslOptions::COOKIE_EXCHANGE);
    context_builder.set_cookie_generate_cb(
        move |ssl: &mut ssl::SslRef, cookie: &mut [u8]| -> Result<usize, ErrorStack> {
            let ssl_ptr: *const ssl::SslRef = ssl;
            let mut buf = salt_clone.read().unwrap().clone();
            compute_hash(ssl_ptr, &mut buf, cookie);
            Ok(COOKIE_LEN)
        },
    );
    context_builder.set_cookie_verify_cb(move |ssl: &mut ssl::SslRef, cookie: &[u8]| -> bool {
        let ssl_ptr: *const ssl::SslRef = ssl;
        let mut buf = salt.read().unwrap().clone();
        let mut check: [u8; COOKIE_LEN] = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        compute_hash(ssl_ptr, &mut buf, &mut check);
        cookie == check
    });

    let ssl_context = context_builder.build();

    let mut res = [0; 1500];
    let mut fake = 0;
    loop {
        let ssl = Ssl::new(&ssl_context).unwrap();
        let socket = UdpStream::new(SERVER_ADDRESS).unwrap();
        if let Ok(mut stream) = ssl.accept(socket) {
            while let Ok(_) = stream.ssl_read(&mut res) {
                println!(
                    "Server: \"{}\", says the client.",
                    String::from_utf8_lossy(&res)
                );
                stream.ssl_write(b"Hi").unwrap();
            }
            stream.shutdown().unwrap();
            break;
        } else {
            fake += 1;
        }
    }
    println!("Server: I have received {} fake messages.", fake);
}

/// DTLS client that sends a message to the server.
fn client_thread() {
    let mut context_builder = SslContextBuilder::new(SslMethod::dtls()).unwrap();
    context_builder.set_verify(SslVerifyMode::PEER);

    context_builder.set_ca_file(CA_FILE).unwrap();
    context_builder
        .set_certificate_file(CLIENT_CERT, ssl::SslFiletype::PEM)
        .unwrap();
    context_builder
        .set_private_key_file(CLIENT_KEY, ssl::SslFiletype::PEM)
        .unwrap();

    let ssl_context = context_builder.build();

    let mut res = [0; 1500];
    // repeatedly attempt to send the message amidst the flooding by
    // the bogus client
    loop {
        let ssl = Ssl::new(&ssl_context).unwrap();
        let mut socket = UdpStream::new(CLIENT_ADDRESS).unwrap();
        socket.connect(SERVER_ADDRESS).unwrap();
        if let Ok(mut stream) = ssl.connect(socket) {
            stream.ssl_write(b"Hello").unwrap();
            if let Ok(_) = stream.ssl_read(&mut res) {
                println!(
                    "Client: \"{}\", says the server.",
                    String::from_utf8_lossy(&res)
                );
            }
            stream.shutdown().unwrap();
            break;
        }
    }
    STOP.store(true, Ordering::Relaxed);
}

/// Attempts to send invalid packets to the DTLS server.
fn bogus_client() {
    let start: u16 = 10000;
    let end: u16 = u16::max_value();
    for port_num in (start..=end).cycle() {
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        if let Ok(socket) = UdpSocket::bind(format!("localhost:{}", port_num)) {
            socket.send_to(b"DoS attack!", SERVER_ADDRESS).unwrap();
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn main() {
    let server = thread::spawn(server_thread);
    let bogus = thread::spawn(bogus_client);
    let client = thread::spawn(client_thread);
    client.join().unwrap();
    bogus.join().unwrap();
    server.join().unwrap();
}
