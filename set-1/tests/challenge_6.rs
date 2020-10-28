use set_1::challenge_1_base64::*;
use set_1::challenge_3_single_byte_xor_cipher::crack_key;
use set_1::challenge_5_repeating_key_xor::*;
use set_1::challenge_6_break_repeating_key_xor::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn challenge_6_pre() {
    assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
}

#[test]
fn challenge_6() {
    let fc = File::open("data/6.txt").unwrap();
    let mut data: Vec<Vec<u8>> = vec![];
    for line in BufReader::new(fc).lines() {
        data.push(base64_decode(&line.unwrap()));
    }

    // Find keysize
    let keysize = find_keysize(&data.concat())[0];
    let mut transposed_data: Vec<Vec<u8>> = vec![vec![]; keysize];
    for chunk in data.concat().chunks_exact(keysize) {
        for (i, &byte) in chunk.iter().enumerate() {
            transposed_data[i].push(byte);
        }
    }

    // Find key bytes
    let mut key: Vec<u8> = vec![];
    for cols in transposed_data.iter() {
        key.push(crack_key(&cols[0..]).0);
    }

    // Check solution
    assert_eq!(
        String::from_utf8(repeating_key_xor_cipher(&key, &data.concat())).unwrap(),
        "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
    );

    assert_eq!(String::from_utf8(key).unwrap(), "Terminator X: Bring the noise");
}
