use std::fs;

pub fn read_k_cmdline() -> String {
    let cmdline = match fs::read("/proc/cmdline") {
        Ok(v) => String::from_utf8(v)
            .unwrap()
            .strip_suffix("\n")
            .unwrap()
            .to_string(),
        Err(_e) => panic!("Could not read kernel commandline"),
    };
    cmdline
}

pub fn cmdline_var(cmdline: String, varname: String, defaultval: String) -> String {
    let clvar = cmdline
        .split_whitespace()
        .into_iter()
        .find(|e| e.to_string().starts_with(&varname));

    let varval = match clvar {
        Some(v) => v.split("=").last().unwrap().to_string(),
        None => defaultval,
    };
    varval
}
