// learned from https://adriann.github.io/rust_parser.html
use std::str::FromStr;
use std::string::ToString;

use std::error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct ParsePairError;

impl fmt::Display for ParsePairError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "parse failed")
    }
}

impl error::Error for ParsePairError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Debug, PartialEq)]
enum ValueItem {
    Integer(i32),
    String(String),
    Bool(bool),
    Float(f32),
}

#[derive(Debug, PartialEq)]
pub struct Pair(String, ValueItem);

impl FromStr for ValueItem {
    type Err = ParsePairError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "true" | "True" => Ok(ValueItem::Bool(true)),
            "false" | "False" => Ok(ValueItem::Bool(true)),
            _ => {
                let res;
                if let Ok(int) = s.parse::<i32>() {
                    res = Ok(ValueItem::Integer(int));
                } else if let Ok(float) = s.parse::<f32>() {
                    res = Ok(ValueItem::Float(float));
                } else {
                    res = Ok(ValueItem::String(s.to_string()));
                }
                res
            }
        }
    }
}

impl FromStr for Pair {
    type Err = ParsePairError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kv: Vec<&str> = s.split('=').collect();
        Ok(Pair(kv[0].to_string(), kv[1].parse().unwrap()))
    }
}

impl ToString for Pair {
    fn to_string(&self) -> String {
        match self {
            Pair(key, ValueItem::Bool(true)) => key.to_string() + "=true",
            Pair(key, ValueItem::Bool(false)) => key.to_string() + "=false",
            Pair(key, ValueItem::Integer(value)) => key.to_string() + "=" + &value.to_string(),
            Pair(key, ValueItem::Float(value)) => key.to_string() + "=" + &value.to_string(),
            Pair(key, ValueItem::String(value)) => key.to_string() + "=" + &value,
        }
    }
}

pub fn decode(input: &str) -> Vec<Pair> {
    input.split('&').map(|kv| kv.parse().unwrap()).collect()
}

pub fn encode(input: Vec<Pair>) -> String {
    input.iter().fold("".to_string(), |res, next| {
        if !res.is_empty() { res + "&" + &next.to_string() } else { next.to_string() }
    })
}

pub fn profile_for(email: &str) -> Vec<Pair> {
    vec![
        Pair(
            "email".to_string(),
            ValueItem::String(email.trim_matches(|c| c == '=' || c == '&').to_string()),
        ),
        Pair("uid".to_string(), ValueItem::Integer(10)),
        Pair("role".to_string(), ValueItem::String("user".to_string())),
    ]
}
