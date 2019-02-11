// Config.rs handles configuration parsing.
// TODO: Clean up the code, to improve readability.
extern crate serde;
extern crate serde_derive;
extern crate toml;
extern crate regex;
use std::{collections::HashMap, fs, process};
use regex::RegexSet;

// The default configuration for the server to use.
pub const DEFAULT_CONFIG: &str = r##"# conf.toml - KatWebX's Configuration.
# Note that regex can be enabled for some fields by adding r# to the beginning of the string.

[server] # Server related settings.
# http_addr and tls_addr specify the address and port KatWebX should bind to.
# When using socket listening, these values are ignored.
http_addr = "[::]:80"
tls_addr = "[::]:443"

# stream_timeout controls the maximum amount of time the connection can stay open (in seconds).
stream_timeout = 20

# log_format controls the format used for logging requests.
# Supported values are combinedvhost, combined, commonvhost, common, simpleplus, simple, minimal, and none.
log_format = "simple"

# cert_folder controls the folder used for storing TLS certificates, encryption keys, and OCSP data.
cert_folder = "ssl"


[content] # Content related settings.
# protect allows prevention of some common security issues through the use of HTTP headers.
# Note that this can break some badly designed sites, and should be tested before use in production.
protect = true

# caching_timeout controls how long the content is cached by the client (in hours).
caching_timeout = 4

# compress_files allows the server to save brotli compressed versions of files to the disk.
# When this is disabled, all data will be compressed on-the-fly, severely reducing peformance.
# Note that this only prevents the creation of new brotli files, existing brotli files will still be served.
compress_files = true

# hsts forces clients to use HTTPS, through the use of HTTP headers and redirects.
# Note that this will also enable HSTS preloading. Once you are on the HSTS preload list, it's very difficult to get off of it.
# You can request for your site to be added to the HSTS preload list here: https://hstspreload.org/
hsts = false

# hide specifies a list of folders which can't be used to serve content. This field supports regex.
# Note that the certificate folder is automatically included in this, and hidden folders are always ignored.
hide = ["src", "r#tar.*"]


[[proxy]] # HTTP reverse proxy
# The host to be proxied. When using regex in this field, a URL without the protocol is provided as input instead.
location = "proxy.local"

# The destination for proxied requests. When using HTTPS, a valid TLS certificate is required.
dest = "https://kittyhacker101.tk"


[[proxy]]
location = "r#localhost/proxy[0-9]"
dest = "http://localhost:8081"


[[redir]] # HTTP redirects
# The url (without the protocol) that this redirect affects. This field supports regex.
location = "localhost/redir"

# The destination that the client is redirected to.
dest = "https://kittyhacker101.tk"


[[redir]]
location = "r#localhost/redir2.*"
dest = "https://google.com"


[[auth]] # HTTP basic authentication
# The url (without the protocol) that this affects. This field must be regex.
location = "r#localhost/demopass.*"

# The username and password required to get access to the resource, split by a ":" character.
login = "admin:passwd"
"##;

pub struct Config {
	pub caching_timeout: i64,
	pub stream_timeout: usize,
	pub hsts: bool,
	pub hidden: Vec<String>,
	pub lredir: Vec<String>,
	pub lproxy: Vec<String>,
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
	pub cert_folder: String,
}

#[derive(Clone, Deserialize)]
struct ConfStruct {
	server: ConfStructServer,
	content: ConfStructContent,
	proxy: Vec<ConfStructPrRe>,
	redir: Vec<ConfStructPrRe>,
	auth: Vec<ConfStructAuth>
}

#[derive(Clone, Deserialize)]
struct ConfStructServer {
	http_addr: String,
	tls_addr: String,
	stream_timeout: usize,
	log_format: String,
	cert_folder: String
}

#[derive(Clone, Deserialize)]
struct ConfStructContent {
	protect: bool,
	caching_timeout: i64,
	compress_files: bool,
	hsts: bool,
	hide: Vec<String>
}

#[derive(Clone, Deserialize)]
struct ConfStructPrRe {
	location: String,
	dest: String
}

#[derive(Clone, Deserialize)]
struct ConfStructAuth {
	location: String,
	login: String
}

impl Config {
	// load_config loads a configuration from a string or file.
	pub fn load_config(data: String, is_path: bool) -> Self {
		let datar = if is_path {
			fs::read_to_string(data.to_owned()).unwrap_or_else(|_| {
				println!("[Warn]: Unable to find configuration file, using default configuration.");
				fs::write(data, DEFAULT_CONFIG).unwrap_or_else(|_err| {
					println!("[Warn]: Unable to write default configuration to disk!");
				});
				DEFAULT_CONFIG.to_owned()
			})
		} else {
			data
		};

		let conft: ConfStruct = toml::from_str(&datar).unwrap_or_else(|err| {
			println!("[Fatal]: Unable to parse configuration! Debugging information will be printed below.");
			println!("{}", err);
			process::exit(1);
		});

		Self {
			caching_timeout: conft.content.caching_timeout,
			stream_timeout: conft.server.stream_timeout,
			hsts: conft.content.hsts,
			hidden: {
				let mut tmp = conft.content.hide.to_owned();
				tmp.push(conft.server.cert_folder.to_owned());
				tmp.push("redir".to_owned());
				tmp.sort_unstable();
				tmp
			},
			hiddenx: {
				parse_regex(conft.content.hide).unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap())
			},
			lredir: {
				let mut tmp = Vec::new();
				for item in conft.redir.to_owned() {
					tmp.push(item.location);
				}
				tmp.sort_unstable();
				tmp
			},
			redirx: {
				let mut tmp = Vec::new();
				for item in conft.redir.to_owned() {
					tmp.push(item.location);
				}
				parse_regex(tmp).unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap())
			},
			redirmap: {
				let mut tmp = HashMap::new();
				for item in conft.redir {
					tmp.insert(item.location, item.dest);
				}
				tmp
			},

			lproxy: {
				let mut tmp = Vec::new();
				for item in conft.proxy.to_owned() {
					tmp.push(item.location);
				}
				tmp.sort_unstable();
				tmp
			},
			proxyx: {
				let mut tmp = Vec::new();
				for item in conft.proxy.to_owned() {
					tmp.push(item.location);
				}
				parse_regex(tmp).unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap())
			},
			proxymap: {
				let mut tmp = HashMap::new();
				for item in conft.proxy {
					tmp.insert(item.location, item.dest);
				}
				tmp
			},

			authx: {
				let mut tmp = Vec::new();
				for item in conft.auth.to_owned() {
					tmp.push(item.location);
				}
				parse_regex(tmp).unwrap_or_else(|_| RegexSet::new(&["$x"]).unwrap())
			},
			authmap: {
				let mut tmp = HashMap::new();
				for item in conft.auth {
					tmp.insert(item.location, item.login);
				}
				tmp
			},
			protect: conft.content.protect,
			compress_files: conft.content.compress_files,
			log_format: conft.server.log_format,
			http_addr: conft.server.http_addr,
			tls_addr: conft.server.tls_addr,
			cert_folder: conft.server.cert_folder,
		}
	}
}

// Turn an array into a Vec<String>, only adding items which contain regex.
// All regex strings must start with r#, so that the program knows they are regex. The r# will be trimmed from the string before the regex is parsed.
fn array_get_regex(array: Vec<String>) -> Vec<String> {
	let mut tmp = Vec::new();
	for item in array {
		if item.starts_with("r#") {
			tmp.push(item[2..].to_owned())
		}
	}
	tmp
}

// Turn an array into parsed regex.
fn parse_regex(array: Vec<String>) -> Result<RegexSet, regex::Error> {
	RegexSet::new(&array_get_regex(array))
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

		assert_eq!(conf.hiddenx.patterns().to_owned(), vec![r"tar.*"]);
		assert_eq!(conf.redirx.patterns().to_owned(), vec![r"localhost/redir2.*"]);
		assert_eq!(conf.proxyx.patterns().to_owned(), vec![r"localhost/proxy[0-9]"]);
		assert_eq!(conf.authx.patterns().to_owned(), vec![r"localhost/demopass.*"]);

		assert_eq!(conf.redirmap.get("localhost/redir").map(|s| &**s), Some("https://kittyhacker101.tk"));
		assert_eq!(conf.redirmap.get("r#localhost/redir2.*").map(|s| &**s), Some("https://google.com"));

		assert_eq!(conf.proxymap.get("proxy.local").map(|s| &**s), Some("https://kittyhacker101.tk"));
		assert_eq!(conf.proxymap.get("r#localhost/proxy[0-9]").map(|s| &**s), Some("http://localhost:8081"));

		assert_eq!(conf.authmap.get("r#localhost/demopass.*").map(|s| &**s), Some("admin:passwd"));

		assert_eq!(conf.protect, true);
		assert_eq!(conf.compress_files, true);
		assert_eq!(conf.log_format, "simple".to_owned());
		assert_eq!(conf.http_addr, "[::]:80".to_owned());
		assert_eq!(conf.tls_addr, "[::]:443".to_owned());
		assert_eq!(conf.cert_folder, "ssl".to_owned());
	}
}
