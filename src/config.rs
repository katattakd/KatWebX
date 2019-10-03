// Config.rs handles configuration parsing.
extern crate serde;
extern crate serde_derive;
extern crate toml;
extern crate regex;
extern crate exitcode;
extern crate base64;
use std::{collections::HashMap, fs, process, path::Path};
use regex::{RegexSet, Regex, NoExpand};
use trim_prefix;

// ConfStruct objects are used for parsing the configuration, and aren't used for KatWebX's internal routing. KatWebX uses the Config object for storing and accessing the parsed content.
#[derive(Clone, Deserialize)]
struct ConfStruct {
	server: ConfStructServer,
	content: ConfStructContent,
	proxy: Option<Vec<ConfStructPrRe>>,
	redir: Option<Vec<ConfStructPrRe>>,
	auth: Option<Vec<ConfStructAuth>>,
}

#[derive(Clone, Deserialize)]
struct ConfStructServer {
	http_addr: Option<String>,
	tls_addr: Option<String>,
	stream_timeout: Option<usize>,
	log_format: Option<String>,
	cert_folder: Option<String>,
	root_folder: Option<String>,
	copy_chunk_size: Option<u64>,
	prefer_chacha_poly: Option<bool>
}

#[derive(Clone, Deserialize)]
struct ConfStructContent {
	protect: Option<bool>,
	caching_timeout: Option<i64>,
	compress_files: Option<bool>,
	hsts: Option<bool>,
	hide: Option<Vec<String>>,
	smaller_default: Option<bool>
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

// The shared configuration object that KatWebX uses. Routing info shouldn't be accessed directly, it should be accessed through the handle_path function instead.
#[derive(Debug)]
pub struct Config {
	pub caching_timeout: i64,
	pub stream_timeout: usize,
	pub hsts: bool,
	hidden: Vec<String>,
	lredir: Vec<String>,
	lproxy: Vec<String>,
	hiddenx: RegexSet,
	redirx: RegexSet,
	proxyx: RegexSet,
	authx: RegexSet,
	redirmap: HashMap<String, String>,
	proxymap: HashMap<String, String>,
	authmap: HashMap<String, String>,
	pub protect: bool,
	pub compress_files: bool,
	pub chacha: bool,
	pub log_format: String,
	pub http_addr: String,
	pub tls_addr: String,
	pub cert_folder: String,
	pub root_folder: String,
	pub max_streaming_len: u64,
	pub smaller_default: bool
}

impl Config {
	// Generates a Config object from provided TOML input. Input can be either a file path, or TOML data provided as a string.
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
			process::exit(exitcode::CONFIG);
		});

		// Parse the provided content into a Config object, using default values if an item can't be found.
		Self {
			caching_timeout: conft.content.caching_timeout.unwrap_or(12),
			stream_timeout: conft.server.stream_timeout.unwrap_or(20),
			hsts: conft.content.hsts.unwrap_or(false),
			hidden: {
				let mut tmp = conft.content.hide.to_owned().unwrap_or_else(Vec::new);
				tmp.push(conft.server.cert_folder.to_owned().unwrap_or_else(|| "ssl".to_owned()));
				tmp.push("redir".to_owned());
				tmp.sort_unstable();
				tmp
			},
			hiddenx: {
				parse_regex(conft.content.hide.unwrap_or_else(Vec::new)).unwrap_or_else(|err| {
					println!("[Fatal]: Unable to parse configuration! Debugging information will be printed below.");
					println!("{}", err);
					process::exit(exitcode::CONFIG);
				})
			},
			lredir: {
				let mut tmp = Vec::new();
				for item in conft.redir.to_owned().unwrap_or_else(Vec::new) {
					tmp.push(item.location);
				}
				tmp.sort_unstable();
				tmp
			},
			redirx: {
				let mut tmp = Vec::new();
				for item in conft.redir.to_owned().unwrap_or_else(Vec::new) {
					tmp.push(item.location);
				}
				parse_regex(tmp).unwrap_or_else(|err| {
					println!("[Fatal]: Unable to parse configuration! Debugging information will be printed below.");
					println!("{}", err);
					process::exit(exitcode::CONFIG);
				})
			},
			redirmap: {
				let mut tmp = HashMap::new();
				for item in conft.redir.unwrap_or_else(Vec::new) {
					tmp.insert(item.location, item.dest);
				}
				tmp
			},

			lproxy: {
				let mut tmp = Vec::new();
				for item in conft.proxy.to_owned().unwrap_or_else(Vec::new) {
					tmp.push(item.location);
				}
				tmp.sort_unstable();
				tmp
			},
			proxyx: {
				let mut tmp = Vec::new();
				for item in conft.proxy.to_owned().unwrap_or_else(Vec::new) {
					tmp.push(item.location);
				}
				parse_regex(tmp).unwrap_or_else(|err| {
					println!("[Fatal]: Unable to parse configuration! Debugging information will be printed below.");
					println!("{}", err);
					process::exit(exitcode::CONFIG);
				})
			},
			proxymap: {
				let mut tmp = HashMap::new();
				for item in conft.proxy.unwrap_or_else(Vec::new) {
					tmp.insert(item.location, item.dest);
				}
				tmp
			},

			authx: {
				let mut tmp = Vec::new();
				for item in conft.auth.to_owned().unwrap_or_else(Vec::new) {
					tmp.push(item.location);
				}
				parse_regex(tmp).unwrap_or_else(|err| {
					println!("[Fatal]: Unable to parse configuration! Debugging information will be printed below.");
					println!("{}", err);
					process::exit(exitcode::CONFIG);
				})
			},
			authmap: {
				let mut tmp = HashMap::new();
				for item in conft.auth.unwrap_or_else(Vec::new) {
					tmp.insert(item.location, base64::encode(item.login.as_bytes()));
				}
				tmp
			},
			protect: conft.content.protect.unwrap_or(true),
			compress_files: conft.content.compress_files.unwrap_or(true),
			log_format: conft.server.log_format.unwrap_or_else(|| "minimal".to_owned()),
			http_addr: conft.server.http_addr.unwrap_or_else(|| "[::]:80".to_owned()),
			tls_addr: conft.server.tls_addr.unwrap_or_else(|| "[::]:443".to_owned()),
			cert_folder: conft.server.cert_folder.unwrap_or_else(|| "ssl".to_owned()),
			root_folder: conft.server.root_folder.unwrap_or_else(|| ".".to_owned()),
			max_streaming_len: conft.server.copy_chunk_size.unwrap_or(65_536),
			chacha: conft.server.prefer_chacha_poly.unwrap_or(false),
			smaller_default: conft.content.smaller_default.unwrap_or(false),
		}
	}

	/* Generate the correct host and path, from raw data and a Config object. 
	Special cases:
	- If HTTP authentication fails, "unauth" will be returned as the path, and "redir" will be returned as the host.
	- If a redirect is set, "redir" will be returned as the host, and the location to redirect to will be returned as the path.
	- If a reverse proxy is set, "proxy" will be returned as the host, and the URL to proxy will be returned as the path.
	- If a normal file is being served, an optional full path (host+path) will be returned, along with the path and host.*/
	pub fn handle_path(&self, path: &str, host: &str, auth: &str) -> (String, String, Option<String>) {
		let mut host = trim_port(host);
		let hostn = host.to_owned();

		// Prevent the client from accessing data they aren't supposed to access, at the risk of breaking some (very badly designed) clients. A more elegant solution is possible, but it isn't worth implementing, as no popular clients are anywhere near this broken.
		let fp = &[host, path].concat();
		match path {
			_ if path.ends_with("/index.html") => return ("./".to_owned(), "redir".to_owned(), None),
			_ if path.contains("..") => return ("..".to_owned(), "redir".to_owned(), None),
			_ => (),
		}

		/* Check if the path is protected by HTTP authentication. If checking path authentication fails (due to either a badly formatted config or a bad Config object), act as if the endpoint doesn't have authentication.
		If it is protected, check if the auth input matches the correct login, and return if it is incorrect. */
		if self.authx.is_match(fp) {
			if let Some(regx) = self.authx.matches(fp).iter().next() {
				if let Some(eauth) = self.authmap.get(&["r#", &self.authx.patterns()[regx]].concat()) {
					let authx = trim_prefix("Basic ", auth);
					if authx != eauth {
						return ("unauth".to_owned(), "redir".to_owned(), None)
					}
				}
			}
		}

		// Check if a path has redirects set, and then return the redirects if they are present. If a regex redirect is set, trim matching content from the path, and then add the non-matching content to the redirect destination. 
		if self.redirx.is_match(fp) {
			if let Some(regx) = self.redirx.matches(fp).iter().next() {
				if let Some(link) = self.redirmap.get(&["r#", &self.redirx.patterns()[regx]].concat()) {
					return ([link.to_owned(), trim_regex(&self.redirx.patterns()[regx], fp)].concat(), "redir".to_owned(), None)
				}
			}
		}
		if self.lredir.binary_search(fp).is_ok() {
			if let Some(link) = self.redirmap.get(fp) {
				return (link.to_owned(), "redir".to_owned(), None)
			}
		}

		// Check if a reverse proxy is set, and return the proxy URL if it is present.
		if self.proxyx.is_match(fp) {
			if let Some(regx) = self.proxyx.matches(fp).iter().next() {
				if let Some(link) = self.proxymap.get(&["r#", &self.proxyx.patterns()[regx]].concat()) {
					return ([link.to_owned(), trim_regex(&self.proxyx.patterns()[regx], fp)].concat(), "proxy".to_owned(), None)
				}
			}
		}
		if self.lproxy.binary_search(&hostn).is_ok() {
			if let Some(link) = self.proxymap.get(host) {
				return ([link, path].concat(), "proxy".to_owned(), None)
			}
		}

		// If the host doesn't exist or is a location the client isn't allowed to access, use the default host instead.
		if self.hidden.binary_search(&hostn).is_ok() || self.hiddenx.is_match(&hostn) || host.is_empty() || &host[..1] == "." || host.contains('/') || host.contains('\\') || !Path::new(&hostn).exists() {
			host = "html"
		}

		// If we're serving a folder, return the index file from that folder.
		let pathn;
		if path.ends_with('/') {
			pathn = [path, "index.html"].concat()
		} else {
			pathn = path.to_owned()
		}

		// Return an optional "full path" variant of the path, for use with file requests.
		let full_path = [host, &*pathn].concat();
		(pathn, host.to_owned(), Some(full_path))
	}
}

// Trim the port from an IPv4 address, IPv6 address, or domain:port.
fn trim_port(path: &str) -> &str {
	if path.contains('[') && path.contains(']') {
		match path.rfind("]:") {
			Some(i) => return &path[..=i],
			None => return path,
		};
	}

	match path.rfind(':') {
		Some(i) => &path[..i],
		None => path,
	}
}

// Use regex to trim a string.
fn trim_regex(regex: &str, root: &str) -> String {
	let r = Regex::new(regex).unwrap_or_else(|_| Regex::new("$x").unwrap());
	r.replace_all(root, NoExpand("")).to_string()
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

// The default configuration for the server to use.
pub const DEFAULT_CONFIG: &str = r##"# conf.toml - KatWebX's Default Configuration.
# Note that regex can be enabled for some fields by adding r# to the beginning of the string.
# This configuration file covers all possible configuration options. For the server and content sections, default values are commented out.

[server] # Server related settings.
# http_addr and tls_addr specify the address and port KatWebX should bind to.
# When using socket listening, these values are ignored.
#http_addr = "[::]:80"
#tls_addr = "[::]:443"

# stream_timeout controls the maximum amount of time the connection can stay open (in seconds).
# The default value should be good enough for transfering small files. If you are serving large files, increasing this is recommended.
#stream_timeout = 20

# copy_chunk_size adjusts the maximum file size (in bytes) which can be directly copied into the response.
# Files larger than this value are copied into the response in chunks of this size, which increases latency.
# When the file is smaller than this value, it is copied directly into the response. This can heavily increase RAM usage on busy servers.
# The default value should be good enough for 99% of use cases, don't adjust this unless you know what you are doing.
#copy_chunk_size = 65536

# prefer_chacha_poly makes the server prefer using the CHACHA20_POLY1305_SHA256 ciphersuite, instead of using the ciphersuites that the client prefers (usually AES).
# On CPUs which don't support AES-NI (some very old x86 and most non-x86 CPUs), this can give a ~7x speedup. This should be left disabled on CPUs supporting AES-NI, as it can cut peformance in half.
#prefer_chacha_poly = false

# log_format controls the format used for logging requests.
# Supported values are combinedvhost, combined, commonvhost, common, simpleplus, simple, minimal, and none.
# Note that logging can have a peformance impact on heavily loaded servers. If your server is under extreme load (100+ requests/second), setting the logging format to "minimal" or "none" can significantly increase peformance.
log_format = "simple"

# cert_folder controls the folder used for storing TLS certificates, encryption keys, and OCSP data.
#cert_folder = "ssl"

# root_folder controls the web server root. The default folder (html) and per-domain folders will be stored in here.
#root_folder = "."


[content] # Content related settings.
# protect allows prevention of some common security issues through the use of HTTP security headers.
# Note that this can break some badly designed sites, and should be tested before use in production.
#protect = true

# caching_timeout controls how long the content is cached by the client (in hours).
#caching_timeout = 12

# compress_files allows the server to save brotli compressed versions of files to the disk.
# When this is disabled, all data will be compressed on-the-fly, severely reducing peformance.
# Note that this only prevents the creation of new brotli files, existing brotli files will still be served.
#compress_files = true

# hsts forces all clients to use HTTPS, through the use of HTTP headers and redirects.
# Note that this will also enable HSTS preloading. Once you are on the HSTS preload list, it's very difficult to get off of it.
# You can learn more about HSTS preloading and get your site added to the preload list here: https://hstspreload.org/
#hsts = false

# hide specifies a list of folders which can't be used to serve content. This field supports regex.
# Note that the certificate folder is automatically included in this, and folders starting with "." are always ignored.
hide = ["src", "target"]

# smaller_default tells the server to generate smaller error pages, and prevents the server from generating file listings of folders that do not contain an index file.
# This can make your server slightly more secure, but it is not necessary for the vast majority of deployments.
#smaller_default = false


#[[proxy]] # HTTP reverse proxy
# The host to be proxied. When using regex in this field, a URL without the protocol is provided as input instead.
#location = "proxy.local"

# The destination for proxied requests. When using HTTPS, a valid TLS certificate is required.
#dest = "https://kittyhacker101.tk"


#[[proxy]]
#location = "r#localhost/proxy[0-9]"
#dest = "http://localhost:8081"


#[[redir]] # HTTP redirects
# The url (without the protocol) that this redirect affects. This field supports regex.
#location = "localhost/redir"

# The destination that the client is redirected to.
#dest = "https://kittyhacker101.tk"


#[[redir]]
#location = "r#localhost/redir2.*"
#dest = "https://google.com"


#[[auth]] # HTTP basic authentication
# The url (without the protocol) that this affects. This field must be regex.
#location = "r#localhost/demopass.*"

# The username and password required to get access to the resource, split by a ":" character.
# Note that brute forcing logins isn't very difficult to do, so make sure you use a complex username and password.
#login = "admin:passwd"
"##;

#[cfg(test)]
mod tests {
    use super::*;
	use std::{fs, fs::File, io::Write};

    #[test]
	fn test_default_config() {
		let conf = Config::load_config(DEFAULT_CONFIG.to_string(), false);
		assert_eq!(conf.caching_timeout, 12);
		assert_eq!(conf.stream_timeout, 20);
		assert_eq!(conf.hsts, false);
		assert_eq!(conf.protect, true);
		assert_eq!(conf.compress_files, true);
		assert_eq!(conf.chacha, false);
		assert_eq!(conf.log_format, "simple".to_string());
		assert_eq!(conf.http_addr, "[::]:80".to_string());
		assert_eq!(conf.tls_addr, "[::]:443".to_string());
		assert_eq!(conf.cert_folder, "ssl".to_string());
		assert_eq!(conf.root_folder, ".".to_string());
		assert_eq!(conf.max_streaming_len, 65536);
		assert_eq!(conf.smaller_default, false);
	}

	#[test]
	fn test_empty_config() {
		let conf = Config::load_config("[server]\n[content]".to_string(), false);
		assert_eq!(conf.caching_timeout, 12);
		assert_eq!(conf.stream_timeout, 20);
		assert_eq!(conf.hsts, false);
		assert_eq!(conf.protect, true);
		assert_eq!(conf.compress_files, true);
		assert_eq!(conf.chacha, false);
		assert_eq!(conf.log_format, "minimal".to_string());
		assert_eq!(conf.http_addr, "[::]:80".to_string());
		assert_eq!(conf.tls_addr, "[::]:443".to_string());
		assert_eq!(conf.cert_folder, "ssl".to_string());
		assert_eq!(conf.root_folder, ".".to_string());
		assert_eq!(conf.max_streaming_len, 65536);
		assert_eq!(conf.smaller_default, false);
	}

	#[test]
	fn test_missing_config_file() {
		let conf = Config::load_config("test.toml".to_string(), true);
		assert_eq!(conf.caching_timeout, 12);
		assert_eq!(conf.stream_timeout, 20);
		assert_eq!(conf.hsts, false);
		assert_eq!(conf.protect, true);
		assert_eq!(conf.compress_files, true);
		assert_eq!(conf.chacha, false);
		assert_eq!(conf.log_format, "simple".to_string());
		assert_eq!(conf.http_addr, "[::]:80".to_string());
		assert_eq!(conf.tls_addr, "[::]:443".to_string());
		assert_eq!(conf.cert_folder, "ssl".to_string());
		assert_eq!(conf.root_folder, ".".to_string());
		assert_eq!(conf.max_streaming_len, 65536);
		assert_eq!(conf.smaller_default, false);
		fs::remove_file("test.toml").unwrap();
	}

	#[test]
	fn test_custom_config_file() {
		let mut conff = File::create("testx.toml").unwrap();
		conff.write_all(b"[server]\nhttp_addr = \"[::]:8080\"\ntls_addr = \"[::]:8181\"\nstream_timeout = 60\ncopy_chunk_size = 60000\nprefer_chacha_poly = true\nlog_format = \"none\"\ncert_folder = \"tls\"\nroot_folder = \"/myroot\"\n[content]\nprotect = false\ncaching_timeout = 72\ncompress_files = false\nhsts = true\nsmaller_default = true").unwrap();

		let conf = Config::load_config("testx.toml".to_string(), true);
		assert_eq!(conf.caching_timeout, 72);
		assert_eq!(conf.stream_timeout, 60);
		assert_eq!(conf.hsts, true);
		assert_eq!(conf.protect, false);
		assert_eq!(conf.compress_files, false);
		assert_eq!(conf.chacha, true);
		assert_eq!(conf.log_format, "none".to_string());
		assert_eq!(conf.http_addr, "[::]:8080".to_string());
		assert_eq!(conf.tls_addr, "[::]:8181".to_string());
		assert_eq!(conf.cert_folder, "tls".to_string());
		assert_eq!(conf.root_folder, "/myroot".to_string());
		assert_eq!(conf.max_streaming_len, 60000);
		assert_eq!(conf.smaller_default, true);

		fs::remove_file("testx.toml").unwrap();
	}

	#[test]
	fn test_path_handling() {
		let conf = Config::load_config("[server]\n[content]\nhide = [\"ci\",\"r#tar.*\"]
\n[[auth]]\nlocation = \"r#example.com/dapass.*\"\nlogin = \"admin:no\"\n[[redir]]\nlocation = \"localhost/redir\"\ndest = \"https://kittyhacker101.tk\"
\n[[redir]]\nlocation = \"r#localhost/da_redir.*\"\ndest = \"https://example.com\"\n[[proxy]]\nlocation = \"example.co\"\ndest = \"https://kittyhacker101.tk\"\n[[proxy]]\nlocation = \"r#localhost/daproxy[0-9]\"\ndest = \"https://google.com\"".to_string(), false);
		assert_eq!(conf.handle_path("/index.html", "localhost", ""), ("./".to_owned(), "redir".to_owned(), None));
		assert_eq!(conf.handle_path("..", "localhost", ""), ("..".to_owned(), "redir".to_owned(), None));

		assert_eq!(conf.handle_path("/", "localhost", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/default.toml", "localhost", ""), ("/default.toml".to_owned(), "html".to_owned(), Some("html/default.toml".to_owned())));
		assert_eq!(conf.handle_path("/demopass/", "localhost", ""), ("/demopass/index.html".to_owned(), "html".to_owned(), Some("html/demopass/index.html".to_owned())));
		assert_eq!(conf.handle_path("/demopass/test.txt", "localhost", ""), ("/demopass/test.txt".to_owned(), "html".to_owned(), Some("html/demopass/test.txt".to_owned())));

		assert_eq!(conf.handle_path("/", "src", ""), ("/index.html".to_owned(), "src".to_owned(), Some("src/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "ssl", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "ci", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "target", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", ".", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "..", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "/home", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "C:\\", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));
		assert_eq!(conf.handle_path("/", "nonexistantdir", ""), ("/index.html".to_owned(), "html".to_owned(), Some("html/index.html".to_owned())));

		assert_eq!(conf.handle_path("/dapass", "example.com", "YWRtaW46YWRtaW4="), ("unauth".to_owned(), "redir".to_owned(), None));
		assert_eq!(conf.handle_path("/dapass", "example.com", "YWRtaW46bm8="), ("/dapass".to_owned(), "html".to_owned(), Some("html/dapass".to_owned())));

		assert_eq!(conf.handle_path("/redir", "localhost", ""), ("https://kittyhacker101.tk".to_owned(), "redir".to_owned(), None));
		assert_eq!(conf.handle_path("/da_redir1", "localhost", ""), ("https://example.com".to_owned(), "redir".to_owned(), None));

		assert_eq!(conf.handle_path("/test.html", "example.co", ""), ("https://kittyhacker101.tk/test.html".to_owned(), "proxy".to_owned(), None));
		assert_eq!(conf.handle_path("/daproxy4/yeet", "localhost", ""), ("https://google.com/yeet".to_owned(), "proxy".to_owned(), None));
	}
}