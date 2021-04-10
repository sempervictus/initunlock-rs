use smbioslib::*;

// Example mechanism for ensuring host-specific key materiel
// Can be expanded to read TPM registers and mix them in for entropy/token data
pub fn system_uuid() -> String {
    let mut sys_uuid = String::new();
    match table_load_from_device() {
        Ok(data) => {
            match data.find_map(|sys_info: SMBiosSystemInformation| sys_info.uuid()) {
                Some(uuid) => match uuid {
                    SystemUuidData::Uuid(id) => sys_uuid = format!("{:?}", id),
                    _ => println!("Wrong value for uuid"),
                },
                None => {
                    println!("No System Information (Type 1) structure found with a UUID field");
                    sys_uuid = "DummyUUID".to_string();
                }
            };
        }
        Err(err) => {
            println!("failure: {:?}", err);
            sys_uuid = "DummyUUID".to_string();
        }
    };
    sys_uuid.retain(|c| !c.is_whitespace());
    sys_uuid
}

pub fn system_serial() -> String {
    let mut sys_serial = String::new();
    match table_load_from_device() {
        Ok(data) => {
            match data.find_map(|sys_info: SMBiosSystemInformation| sys_info.serial_number()) {
                Some(serial) => {
                    sys_serial = serial.clone();
                }
                None => {
                    println!(
                        "No System Information (Type 1) structure found with a serial number field"
                    );
                    sys_serial = "DummySerial".to_string();
                }
            };
        }
        Err(err) => {
            println!("failure: {:?}", err);
            sys_serial = "DummySerial".to_string();
        }
    };
    sys_serial.retain(|c| !c.is_whitespace());
    sys_serial
}
