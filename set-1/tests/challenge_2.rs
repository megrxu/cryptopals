use hex_literal::hex;
use set_1::challenge_2_fixed_xor::*;

#[test]
fn challenge_2() {
    assert_eq!(
        xor(
            &hex!("1c0111001f010100061a024b53535009181c"),
            &hex!("686974207468652062756c6c277320657965")
        ),
        hex!("746865206b696420646f6e277420706c6179")
    )
}
