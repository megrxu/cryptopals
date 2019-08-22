use set_2::challenge_11_detection_oracle::{distinguisher, encryption_oracle};

#[test]
fn test_detection() {
    let input = vec![0; 48];
    for _ in 0..1000 {
        let (result, ciphertext) = encryption_oracle(&input);
        assert_eq!(result, distinguisher(ciphertext));
    }
}
