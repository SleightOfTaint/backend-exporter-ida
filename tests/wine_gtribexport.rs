use config;
use idapro::IDA;
use std::{path::Path, collections::HashMap};

#[test]
fn test_wine_gtirbexport() {
    let mut settings = config::Config::default();
    // safe to panic here with unwrap since it's a test
    settings
        .merge(config::File::with_name("TestConfig"))
        .expect("Couldn't find TestConfig.toml");
    let conf = settings
        .try_into::<HashMap<String, String>>()
        .expect("Failed to parse settings");

    let ida_path = conf.get("ida_path").expect("no ida_path specified");
    let ida = IDA::new(ida_path).expect("ida launch failed");

    let target = conf.get("target_binary").expect("no target binary specified");

    let script_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ida_gtirbexport.py");

    let out = conf.get("gtirb_dump").expect("no binexport output dump path specified");
    
    assert!(ida.run(script_path.to_str().unwrap(), Some(&out), target).unwrap(), true);
}
