use clap::Parser;
use reqwest::blocking::get;
use reqwest::Result;
use serde::{Deserialize, Serialize};
use std::{process};
use regex::Regex;

#[derive(Parser, Debug)]
#[command(name = "Netcraft Checker")]
#[command(author = "Zetaky")]
#[command(version = "1.0")]
#[command(about = "Check URLs with Netcraft API, the presence of a pattern indicates that the URL has been confirmed to be malicious, risk score goes from 0 to 10.")]

struct Args {
    #[arg()]
    url: String,
}

#[derive(Debug, Deserialize, Serialize)]
enum Type {
    #[serde(rename = "phish_site")]
    PhishSite,
}

#[derive(Debug, Deserialize, Serialize)]
struct Pattern {
    #[serde(rename = "n_type")]
    n_type: Option<String>,
    subtype: Option<String>,
    #[serde(rename = "type")]
    type_: Option<Type>,
    #[serde(rename = "message_override")]
    message_override: Option<String>,
    pattern: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct NetcraftResponse {
    rank: Option<i64>,
    risk: Option<String>,
    patterns: Option<Vec<Pattern>>,
    firstseen: Option<String>,
    hoster: Option<String>,
    country: Option<String>,
}

fn build_url(target: &str) -> String {
    let trimmed_url = target.trim_end_matches('/');
    let prefix = if trimmed_url.starts_with("https://") {
        "https://"
    } else if trimmed_url.starts_with("http://") {
        "http://"
    } else {
        ""
    };

    let url_body = trimmed_url.trim_start_matches(prefix);
    let transformed_body = url_body.replace('/', "?x="); //Need to replace this for Netcraft
    format!("https://mirror.toolbar.netcraft.com/check_url/v3/{}{}/dodns/info", prefix, transformed_body)
}

fn defang_url(url: &str) -> String {
    let url = url.trim_end_matches('/');
    let re = Regex::new(r"^(http://|https://)").unwrap();
    re.replace(url, |caps: &regex::Captures| {
        if &caps[0] == "http://" {
            "hxxp://".to_string()
        } else {
            "hxxtp://".to_string()
        }
    }).to_string()
}

fn main() -> Result<()> {
    let args = Args::parse();
    let netcraft_url = build_url(&args.url);

    let response = match get(&netcraft_url) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("Error making request: {}", e);
            process::exit(1);
        }
    };

    let json_values = match response.json::<NetcraftResponse>() {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            process::exit(1);
        }
    };

    println!("");
    let defanged_url = defang_url(&args.url);
    println!("Url: {}", defanged_url);

    if let Some(rank) = json_values.rank {
        println!("Rank: {}", rank);
    } 

    if let Some(risk) = json_values.risk {
        println!("Risk: {}", risk);
    } 

    if let Some(ref patterns) = json_values.patterns {
        println!("Patterns: {}", patterns.len());
    }

    if let Some(firstseen) = json_values.firstseen {
        println!("Firstseen: {}", firstseen);
    } 

    if let Some(hoster) = json_values.hoster {
        println!("Hoster: {}", hoster);
    } 

    if let Some(country) = json_values.country {
        println!("Hoster: {}", country);
    } 

    Ok(())

}
