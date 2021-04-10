use std::fs;
use std::io::Write;
mod dmi;
mod kcmdline;
mod vault;

fn cmdline_vars(cmdline: String) -> (String, String) {
    (
        kcmdline::cmdline_var(
            cmdline.clone(),
            "vault_url".to_string(),
            "http://maas:8200".to_string(),
        ),
        kcmdline::cmdline_var(
            cmdline.clone(),
            "vault_ssl_verify".to_string(),
            "false".to_string(),
        ),
    )
}

fn system_ids() -> (String, String) {
    (dmi::system_serial(), dmi::system_uuid())
}

fn main() {
    let keypath = String::from("/crypto_keyfile.bin");
    // Wipe key and exit if it already exists - post-decrypt execution
    if std::path::Path::new(&keypath).exists() {
        let zbuf = vec![0u8; fs::metadata(&keypath).unwrap().len() as usize];
        {
            let mut keyfile = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&keypath)
                .unwrap();
            keyfile.write_all(&zbuf);
        }
        fs::remove_file(&keypath);
        println!("Zeroed and erased keyfile at {}", keypath);
    } else {
        // Pull variables for Vault access, get data, write keyfile
        let sys_id = system_ids();
        let cvars = cmdline_vars(kcmdline::read_k_cmdline());
        let secret = vault::fetch_secret(sys_id, cvars);
        fs::write(&keypath, secret).expect("Unable to write keyfile");
        println!(
            "Acquired secret data from Vault and wrote key-file to {}",
            keypath
        );
    }
}
