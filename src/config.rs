// Config.rs handles configuration parsing.
extern crate json;
extern crate regex;
use std::{collections::HashMap, fs, process};
use regex::RegexSet;

// The default configuration for the server to use.
pub const DEFAULT_CONFIG: &str = r#"{"cachingTimeout":4,"streamTimeout":20,"hsts":false,"proxy":[{"location":"proxy.local","host":"https://kittyhacker101.tk"},{"location":"r#localhost/proxy[0-9]","host":"https://kittyhacker101.tk"}],"redir":[{"location":"localhost/redir","dest":"https://kittyhacker101.tk"},{"location":"r#localhost/redir2.*","dest":"https://google.com"}],"auth":[{"location":"r#localhost/demopass.*","login":"admin:passwd"}],"hide":["src","r#tar.*"],"advanced":{"protect":true,"compressfiles":true,"logformat":"simple","httpAddr":"[::]:80","tlsAddr":"[::]:443"}}"#;

#[derive(Clone)]
pub struct Config {
	pub caching_timeout: i64,
	pub stream_timeout: u64,
	pub hsts: bool,
	pub hidden: Vec<String>,
	pub lredir: Vec<String>,
	pub lproxy: Vec<String>,
	pub lredirx: Vec<String>,
	pub lproxyx: Vec<String>,
	pub lauthx: Vec<String>,
	pub hiddenx: RegexSet,
	pub redirx: RegexSet,
	pub proxyx: RegexSet,
	pub authx: RegexSet,
	pub redirmap: HashMap<String, String>,
	pub proxymap: HashMap<String, String>,
	pub authmap: HashMap<String, String>,
	pub protect: bool,
	pub compress_files: bool,
	pub log_format: String,
	pub http_addr: String,
	pub tls_addr: String,
}

impl Config {
	// load_config loads a configuration from a string or file.
	pub fn load_config(data: String, is_path: bool) -> Self {
		let datar = if is_path {
			fs::read_to_string(data.clone()).unwrap_or_else(|_| DEFAULT_CONFIG.to_owned())
		} else {
			data.clone()
		};

		let confj = json::parse(&datar).unwrap_or_else(|_err| {
			println!("[Fatal]: Unable to parse configuration!");
			process::exit(1);
		});

		if is_path {
			fs::write(data, confj.pretty(2)).unwrap_or_else(|_err| {
				println!("[Warn]: Unable to write configuration!");
			});
		}

		Self {
			caching_timeout: confj["cachingTimeout"].as_i64().unwrap_or(0),
			stream_timeout: confj["streamTimeout"].as_u64().unwrap_or(20),
			hsts: confj["hsts"].as_bool().unwrap_or(false),
			hidden: match &confj["hide"] {
				json::JsonValue::Array(array) => {
					let mut tmp = sort_json(array, "");
					tmp.push("ssl".to_owned());
					tmp.push("redir".to_owned());
					tmp.sort_unstable();
					tmp
				},
				_ => Vec::new(),
			},
			hiddenx: match &confj["hide"] {
				json::JsonValue::Array(array) => parse_json_regex(array, "").unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap()),
				_ => RegexSet::new(&["$x"]).unwrap(),
			},
			lredir: match &confj["redir"] {
				json::JsonValue::Array(array) => sort_json(array, "location"),
				_ => Vec::new(),
			},
			lredirx: match &confj["redir"] {
				json::JsonValue::Array(array) => array_json_regex(array, "location"),
				_ => Vec::new(),
			},
			redirx: match &confj["redir"] {
				json::JsonValue::Array(array) => RegexSet::new(array_json_regex(array, "location").iter()).unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap()),
				_ => RegexSet::new(&["$x"]).unwrap(),
			},
			redirmap: match &confj["redir"] {
				json::JsonValue::Array(array) => map_json(array, "location", "dest"),
				_ => HashMap::new(),
			},

			lproxy: match &confj["proxy"] {
				json::JsonValue::Array(array) => sort_json(array, "location"),
				_ => Vec::new(),
			},
			lproxyx: match &confj["proxy"] {
				json::JsonValue::Array(array) => array_json_regex(array, "location"),
				_ => Vec::new(),
			},
			proxyx: match &confj["proxy"] {
				json::JsonValue::Array(array) => RegexSet::new(array_json_regex(array, "location").iter()).unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap()),
				_ => RegexSet::new(&["$x"]).unwrap(),
			},
			proxymap: match &confj["proxy"] {
				json::JsonValue::Array(array) => map_json(array, "location", "host"),
				_ => HashMap::new(),
			},

			lauthx: match &confj["auth"] {
				json::JsonValue::Array(array) => array_json_regex(array, "location"),
				_ => Vec::new(),
			},
			authx: match &confj["auth"] {
				json::JsonValue::Array(array) => RegexSet::new(array_json_regex(array, "location").iter()).unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap()),
				_ => RegexSet::new(&["$x"]).unwrap(),
			},
			authmap: match &confj["auth"] {
				json::JsonValue::Array(array) => map_json(array, "location", "login"),
				_ => HashMap::new(),
			},
			protect: confj["advanced"]["protect"].as_bool().unwrap_or(false),
			compress_files: confj["advanced"]["compressfiles"].as_bool().unwrap_or(false),
			log_format: confj["advanced"]["logformat"].as_str().unwrap_or("").to_owned(),
			http_addr: confj["advanced"]["httpAddr"].as_str().unwrap_or("[::]:80").to_owned(),
			tls_addr: confj["advanced"]["tlsAddr"].as_str().unwrap_or("[::]:443").to_owned(),
		}
	}
}

// Turn a JSON array into a sorted Vec<String>.
fn sort_json(array: &[json::JsonValue], attr: &str) -> Vec<String> {
	let mut tmp = Vec::new();
	for item in array {
		if attr == "" {
			tmp.push(item.as_str().unwrap_or("").to_owned())
		} else {
			tmp.push(item[attr].as_str().unwrap_or("").to_owned())
		}
	}
	tmp.sort_unstable();
	tmp
}

// Turn a JSON array into a HashMap<String, String>.
fn map_json(array: &[json::JsonValue], attr1: &str, attr2: &str) -> HashMap<String, String> {
	let mut tmp = HashMap::new();
	for item in array {
		tmp.insert(item[attr1].as_str().unwrap_or("").to_owned(), item[attr2].as_str().unwrap_or("").to_owned());
	}
	tmp
}

// Turn a JSON array into a Vec<String>, only adding items which contain regex.
// All regex strings must start with r#, so that the program knows they are regex. The r# will be trimmed from the string before the regex is parsed.
fn array_json_regex(array: &[json::JsonValue], attr: &str) -> Vec<String> {
	let mut tmp = Vec::new();
	for item in array {
		let itemt = if attr == "" {
			item.as_str().unwrap_or("").to_owned()
		} else {
		 	item[attr].as_str().unwrap_or("").to_owned()
		};
		if itemt.starts_with("r#") {
			tmp.push(itemt[2..].to_owned())
		}
	}
	tmp.sort_unstable();
	tmp
}

// Turn a JSON array into parsed regex.
fn parse_json_regex(array: &[json::JsonValue], attr: &str) -> Result<RegexSet, regex::Error> {
	RegexSet::new(&array_json_regex(array, attr))
}

// Unit tests
#[cfg(test)]
mod tests {
	use {config};
	fn default_conf() -> config::Config {
		config::Config::load_config(config::DEFAULT_CONFIG.to_owned(), false)
	}
	#[test]
	fn test_conf_defaults() {
		let conf = default_conf();
		assert_eq!(conf.caching_timeout, 4);
		assert_eq!(conf.stream_timeout, 20);
		assert_eq!(conf.hsts, false);

		assert_eq!(conf.hidden, vec!["r#tar.*", "redir", "src", "ssl"]);
		assert_eq!(conf.lredir, vec!["localhost/redir", "r#localhost/redir2.*"]);
		assert_eq!(conf.lproxy, vec!["proxy.local", "r#localhost/proxy[0-9]"]);

		assert_eq!(conf.lredirx, vec!["localhost/redir2.*"]);
		assert_eq!(conf.lproxyx, vec!["localhost/proxy[0-9]"]);
		assert_eq!(conf.lauthx, vec!["localhost/demopass.*"]);



		assert_eq!(conf.hiddenx.patterns().to_owned(), vec![r"tar.*"]);
		assert_eq!(conf.redirx.patterns().to_owned(), vec![r"localhost/redir2.*"]);
		assert_eq!(conf.proxyx.patterns().to_owned(), vec![r"localhost/proxy[0-9]"]);
		assert_eq!(conf.authx.patterns().to_owned(), vec![r"localhost/demopass.*"]);

		assert_eq!(conf.protect, true);
		assert_eq!(conf.compress_files, true);
		assert_eq!(conf.log_format, "simple".to_owned());
		assert_eq!(conf.http_addr, "[::]:80".to_owned());
		assert_eq!(conf.tls_addr, "[::]:443".to_owned());
	}
}
