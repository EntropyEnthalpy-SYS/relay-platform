use relay_platform::nat::Mapping;
use relay_platform::state::{read_json, remove_if_present, write_json_atomic};

#[test]
fn mapping_state_is_atomic_and_reloadable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nested/mapping.json");
    let mapping = Mapping {
        gateway: "192.0.2.1:5351".parse().unwrap(),
        internal_port: 9000,
        external_port: 40000,
        lifetime_secs: 3600,
        epoch: 7,
    };
    write_json_atomic(&path, &mapping).unwrap();
    let loaded: Mapping = read_json(&path).unwrap().unwrap();
    assert_eq!(loaded.external_port, 40000);
    assert_eq!(loaded.epoch, 7);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
    remove_if_present(&path).unwrap();
    remove_if_present(&path).unwrap();
    assert!(read_json::<Mapping>(&path).unwrap().is_none());
}

#[test]
fn invalid_mapping_state_is_an_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("mapping.json");
    std::fs::write(&path, b"{not json").unwrap();
    assert!(read_json::<Mapping>(&path).is_err());
}
