use std::fs;
use smbioslib::*;
use hashicorp_vault as vault;
use reqwest::blocking::Client;

// Example mechanism for ensuring host-specific key materiel
// Can be expanded to read TPM registers and mix them in for entropy/token data
fn system_ids() -> (String, String) {
    let mut rser = String::new();
    let mut ruid = String::new();
    match table_load_from_device() {
        // Extract the nested contents of sysinfo as strings
        Ok(data) => {
            // Extract UUID
            match data.find_map(|sys_info: SMBiosSystemInformation| sys_info.uuid()) {
                Some(uuid) => {
                    match uuid {
                        SystemUuidData::Uuid(id) => ruid = format!("{:?}",id),
                        _ => println!("Wrong value for uuid")
                    }
                },
                None => println!("No System Information (Type 1) structure found with a UUID field"),
            };
            // Extract serial number
            match data.find_map(|sys_info: SMBiosSystemInformation| sys_info.serial_number()) {
                Some(serial) => { 
                    rser = serial.clone();
                },
                None => println!("No System Information (Type 1) structure found with a UUID field"),
            };
        },
        // Testing code for now, will need to panic/fail in prod
        Err(err) => { 
            println!("failure: {:?}", err);
            rser = "DummySerial".to_string();
            ruid = "DummyUUID".to_string();
        }
    };
    // Strip whitespace to simplify matters
    rser.retain(|c| !c.is_whitespace());
    ruid.retain(|c| !c.is_whitespace());
    (rser, ruid)
}

// The actual work - currently depends on forked repo to use custom reqwest Client
fn fetch_secret(sys_id: (String, String), cvars: (String, String)) -> String {
    let client = if cvars.1 == "false" {
        let rc = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        vault::Client::new_from_reqwest(cvars.0, sys_id.1, rc).unwrap()
    } else {
        vault::Client::new(cvars.0, sys_id.1).unwrap()
    };
    let key = client.get_secret(sys_id.0).unwrap();
    key
}

fn read_k_cmdline() -> String {
    let cmdline = match fs::read("/proc/cmdline") {
        Ok(v) => String::from_utf8(v)
            .unwrap()
            .strip_suffix("\n")
            .unwrap()
            .to_string(),
        Err(_e) => panic!("Could not read kernel commandline")
    };
    cmdline
}

fn cmdline_vars(cmdline: String) -> (String, String) {
    let vault_vars: Vec<String> = cmdline
        .clone()
        .split_whitespace()
        .into_iter()
        .filter(|e| e.to_string().starts_with("vault_"))
        .map(|e| e.to_string()).collect();
    // Extract vault_url=https://some.host:port from kernel commandline
    let bootvar = vault_vars
        .iter().find(|e| e.clone().to_string().starts_with("vault_url"));
    let url = match bootvar.as_deref() {
        Some(v) => v.split("=").last().unwrap().to_string(),
        _ => "http://maas:8200".to_string(),
    };
    // Extract vault_ssl_verify=true from kernel commandline
    let bootvar = vault_vars
        .iter().find(|e| e.clone().to_string().starts_with("vault_ssl_verify"));
    let ssl_verify = match bootvar.as_deref() {
        Some(v) => v.split("=").last().unwrap().to_string(),
        _ => "false".to_string(),
    };
    (url, ssl_verify)
}

fn main() {
    let sys_id = system_ids();
    let cvars = cmdline_vars(read_k_cmdline());
    // println!("Serial #: {}\nUUID: {}",sys_id.0, sys_id.1);
    let secret = fetch_secret(sys_id, cvars);
    // println!("Fetched secret: {:#?}",secret);
    fs::write("/crypto_keyfile.bin", secret).expect("Unable to write keyfile");
}
