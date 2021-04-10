use hashicorp_vault as vault;
use reqwest::blocking::Client;

pub fn fetch_secret(sys_id: (String, String), cvars: (String, String)) -> String {
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
