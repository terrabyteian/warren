//! The example configuration in docs/examples parses.

use warren_control::config::{Approval, Config};

#[test]
fn the_example_configuration_is_valid() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/examples/control-plane.yaml"
    );
    let config = Config::load(std::path::Path::new(path)).unwrap();
    assert_eq!(config.trust_domain, "example.com");
    assert_eq!(config.public_host, "warren.example.com");
    assert_eq!(config.device_approval, Approval::Manual);
    assert!(config.reserved().contains(&"idp.example.com".to_owned()));
}
