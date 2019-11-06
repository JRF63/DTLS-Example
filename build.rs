use std::fs::File;
use std::io::Write;
use std::process::Command;

fn main() -> std::io::Result<()> {
    let certs_dir = "src/certs";
    let keys_dir = "src/keys";
    let scratch_dir = "openssl-temp";
    let server_ext = &format!("{}/server_ext", scratch_dir);
    let client_ext = &format!("{}/client_ext", scratch_dir);

    for dir in &[certs_dir, keys_dir, scratch_dir] {
        // create if dir does not exist
        match std::fs::create_dir(dir) {
            _ => {}
        }
    }

    let mut file = File::create(server_ext).unwrap();
    file.write(b"basicConstraints=CA:false\nkeyUsage=critical,keyEncipherment")?;

    let mut file = File::create(client_ext).unwrap();
    file.write(b"basicConstraints=CA:false\nkeyUsage=critical,digitalSignature")?;

    // Generate self-signed CA
    Command::new("openssl")
        .args(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-subj",
            "/CN=ca",
            "-nodes",
            "-keyout",
            &format!("{}/ca-key.pem", keys_dir),
            "-out",
            &format!("{}/ca-cert.pem", certs_dir),
            "-addext",
            "keyUsage=critical,keyCertSign",
        ])
        .output()?;

    // Generate server key and CSR
    Command::new("openssl")
        .args(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-subj",
            "/CN=server",
            "-nodes",
            "-keyout",
            &format!("{}/server-key.pem", keys_dir),
            "-out",
            &format!("{}/server-csr.pem", scratch_dir),
        ])
        .output()?;

    // Sign server CSR
    Command::new("openssl")
        .args(&[
            "x509",
            "-req",
            "-CAcreateserial",
            "-CA",
            &format!("{}/ca-cert.pem", certs_dir),
            "-CAkey",
            &format!("{}/ca-key.pem", keys_dir),
            "-in",
            &format!("{}/server-csr.pem", scratch_dir),
            "-out",
            &format!("{}/server-cert.pem", certs_dir),
            "-extfile",
            server_ext,
        ])
        .output()?;

    // Generate client key and CSR
    Command::new("openssl")
        .args(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-subj",
            "/CN=client",
            "-nodes",
            "-keyout",
            &format!("{}/client-key.pem", keys_dir),
            "-out",
            &format!("{}/client-csr.pem", scratch_dir),
        ])
        .output()?;

    // Sign client CSR
    Command::new("openssl")
        .args(&[
            "x509",
            "-req",
            "-CAcreateserial",
            "-CA",
            &format!("{}/ca-cert.pem", certs_dir),
            "-CAkey",
            &format!("{}/ca-key.pem", keys_dir),
            "-in",
            &format!("{}/client-csr.pem", scratch_dir),
            "-out",
            &format!("{}/client-cert.pem", certs_dir),
            "-extfile",
            client_ext,
        ])
        .output()?;

    std::fs::remove_dir_all(scratch_dir)?;

    Ok(())
}
