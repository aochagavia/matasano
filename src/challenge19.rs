pub fn crack_things() {
    use std::io::BufRead;
    let file = std::fs::File::open("challenge-data/20.txt").unwrap();
    let ciphertexts: Vec<_> = std::io::BufReader::new(file)
        .lines()
        .map(|line| crate::base64::decode(line.unwrap().trim().as_bytes()))
        .collect();

    let ciphertexts: Vec<_> = ciphertexts.iter().map(|ciphertext| ciphertext.as_slice()).collect();

    let decrypted = crate::aes::crack_aes_ctr_fixed_nonce(&ciphertexts);

    for line in decrypted {
        println!("{}", String::from_utf8_lossy(&line));
    }
}
