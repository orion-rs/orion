use hex::decode;
use orion::hazardous::kem::{mlkem1024, mlkem512, mlkem768};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

pub mod c2sp_wycheproof;
pub mod nist_encap_decap;
pub mod nist_keygen;

#[test]
fn c2spcctv_mlkem_bad_encapsulation_keys_1024() {
    let path_to_test_file = "./tests/test_data/third_party/c2sp_cctv/ml-kem/bad_ek_ML-KEM-1024.txt";
    let test_file = File::open(path_to_test_file)
        .unwrap_or_else(|_| panic!("TestCaseReader: Unable to open file: {path_to_test_file}"));

    let reader = BufReader::new(test_file);
    let lines = reader.lines();

    for line in lines.map_while(Result::ok) {
        let raw_ek_bytes = decode(line).unwrap();
        assert!(mlkem1024::EncapsulationKey::from_slice(&raw_ek_bytes).is_err());
    }
}

#[test]
fn c2spcctv_mlkem_bad_encapsulation_keys_768() {
    let path_to_test_file = "./tests/test_data/third_party/c2sp_cctv/ml-kem/bad_ek_ML-KEM-768.txt";
    let test_file = File::open(path_to_test_file)
        .unwrap_or_else(|_| panic!("TestCaseReader: Unable to open file: {path_to_test_file}"));

    let reader = BufReader::new(test_file);
    let lines = reader.lines();

    for line in lines.map_while(Result::ok) {
        let raw_ek_bytes = decode(line).unwrap();
        assert!(mlkem768::EncapsulationKey::from_slice(&raw_ek_bytes).is_err());
    }
}

#[test]
fn c2spcctv_mlkem_bad_encapsulation_keys_512() {
    let path_to_test_file = "./tests/test_data/third_party/c2sp_cctv/ml-kem/bad_ek_ML-KEM-512.txt";
    let test_file = File::open(path_to_test_file)
        .unwrap_or_else(|_| panic!("TestCaseReader: Unable to open file: {path_to_test_file}"));

    let reader = BufReader::new(test_file);
    let lines = reader.lines();

    for line in lines.map_while(Result::ok) {
        let raw_ek_bytes = decode(line).unwrap();
        assert!(mlkem512::EncapsulationKey::from_slice(&raw_ek_bytes).is_err());
    }
}
