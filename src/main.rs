#![deny(clippy::nursery)]
#![deny(clippy::pedantic)]
#![allow(clippy::cargo)] // Clippy can't read our cargo.toml properly
#![deny(clippy::all)]
// This issue can't be fixed, due to a limitation of actix-web's API. Actix-web's API doesn't currently allow creating acceptors that use &HttpRequest instead of HttpRequest.
#![allow(clippy::needless_pass_by_value)]

// TODO: Add unit tests!

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[cfg(unix)]
extern crate listenfd;
#[cfg(unix)]
extern crate signal_hook;
extern crate rustls;
extern crate futures;
extern crate actix;
extern crate actix_web;
extern crate actix_http;
extern crate actix_server;
extern crate mime_guess;
extern crate toml;
extern crate regex;
extern crate base64;
extern crate bytes;
extern crate chrono;
extern crate percent_encoding;
extern crate exitcode;
mod stream;
use stream::{trim_prefix, trim_suffix, trim_host, trim_port, open_meta};
mod ui;
mod config;
use config::Config;
mod certs;
use actix::System;
use futures::Future;
use actix_http::body::BodyStream;
use actix_web::{web, web::Payload, Either, HttpServer, client::ClientBuilder, App, http::{header, header::{HeaderValue, HeaderMap}, Method, ContentEncoding, StatusCode}, HttpRequest, HttpResponse, Error, middleware::BodyEncoding, dev::{Body, ConnectionInfo}};
use std::{env, process, fs, string::String, path::Path, time::Duration, sync::{Arc, RwLock, RwLockReadGuard}, ffi::OsStr, thread};
use bytes::Bytes;
use chrono::Local;
use percent_encoding::{percent_decode};
use rustls::{NoClientAuth, ServerConfig};
#[cfg(unix)]
use listenfd::ListenFd;
#[cfg(unix)]
use signal_hook::{iterator::Signals, SIGHUP};

lazy_static! {
	static ref BLANKHEAD: HeaderValue = HeaderValue::from_static("");
	static ref CONFM: RwLock<Config> = RwLock::new(Config::load_config(std::env::args().nth(1).unwrap_or_else(|| "conf.toml".to_owned()), true));
}

// rc converts a RwLock<Config> into a config.
fn rc(lock: &CONFM) -> RwLockReadGuard<Config> {
	lock.read().unwrap_or_else(|_| {
		println!("[Fatal]: Something seriously went wrong when KatWebX was reloading!");
		println!("Hot-reloading the config safely isn't perfect. You should never encounter this error, but if you do, please report it on KatWebX's GitHub.");
		process::exit(exitcode::SOFTWARE); // If the RwLock manages to get poisoned (which should be impossible), anything which requires access to the config will fail to function properly.
	})
}

/* Reverse proxy a request, passing through any compression.
Hop-by-hop headers are removed, to allow connection reuse. */
fn proxy_request(path: &str, method: Method, headers: &HeaderMap, body: Payload, client_ip: &str, c: &Config) -> Box<dyn Future<Item=HttpResponse, Error=Error>> {
	let mut req = ClientBuilder::new().timeout(Duration::from_secs(c.stream_timeout as u64))
		.max_redirects(5).finish().request(method, path).no_decompress();

	for (key, value) in headers.iter() {
		match key.as_str() {
			"connection" | "proxy-connection" | "host" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "transfer-encoding" | "upgrade" => (),
			"x-forwarded-for" => {
				req = req.set_header("X-Forwarded-For", [value.to_str().unwrap_or("127.0.0.1"), ", ", client_ip].concat());
				continue
			},
			_ => {
				req = req.header(key.to_owned(), value.to_owned());
				continue
			},
		};
	}
	req = req.set_header_if_none(header::USER_AGENT, "KatWebX-Proxy")
		.set_header_if_none("X-Forwarded-For", client_ip)
		.set_header_if_none(header::ACCEPT_ENCODING, "none");

	let smaller_default = c.smaller_default;

	Box::new(req.send_stream(body).map_err(move |_err| {
		// The only SendRequestError that could be caused by a user would be InvalidUrl, but we already do URL checking. All possible SendRequestErrors can't be caused by a client issue, only a server-side one.
		Error::from(ui::http_error(StatusCode::BAD_GATEWAY, "502 Bad Gateway", "The server was acting as a proxy and received an invalid response from the upstream server.", smaller_default))
		//Error::from(_err) // This should only be uncommented when debugging potential issues with KatWebX. In the future, KatWebX will implement more detailed error messages.
	}).map(|resp| {
		HttpResponse::Ok()
			.status(resp.status())
			.if_true(true, |req| {
				for (key, value) in resp.headers().iter() {
					match key.as_str() {
						"connection" | "proxy-connection" | "host" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "transfer-encoding" | "upgrade" => (),
						"content-encoding" => {req.header(key.to_owned(), value.to_owned()); req.encoding(ContentEncoding::Identity);}, // Make sure compressed data doesn't get recompressed.
						_ => {req.header(key.to_owned(), value.to_owned());},
					}
				}
			})
			.streaming(resp)
	}))
}

// Do a HTTP permanent redirect.
fn redir(path: &str) -> HttpResponse {
	HttpResponse::Ok()
		.status(StatusCode::PERMANENT_REDIRECT)
		.encoding(ContentEncoding::Auto)
		.header(header::LOCATION, path)
		.header(header::SERVER, "KatWebX")
		.content_type("text/html; charset=utf-8")
		.body(["<a href='", path, "'>If this redirect does not work, click here</a>"].concat())
}

// Logs a HTTP request to the console.
// Note: For security reasons, HTTP auth data is not included in logs.
fn log_data(format_type: &str, status: u16, head: &str, req: &HttpRequest, conn: &ConnectionInfo, length: Option<u64>) {
	if format_type == "" || format_type == "none" {
		return
	}

	if format_type == "minimal" {
		if status < 399 {
			return
		}

		return println!("[{}][{}{}] : {}", head, trim_port(conn.host()), req.path(), trim_port(conn.remote().unwrap_or("127.0.0.1")));
	}

	let version = req.version();
	let method = req.method();
	let client_ip = trim_port(conn.remote().unwrap_or("127.0.0.1"));
	let host = trim_port(conn.host());
	let path = percent_decode(req.path().as_bytes()).decode_utf8_lossy();
	let headers = req.headers();
	let time = Local::now().format("%d/%b/%Y:%H:%M:%S %z");

	let (lengthstr, mut referer, mut user_agent);
	if let Some(l) = length {lengthstr = l.to_string()} else {lengthstr = "-".to_owned()}

	if let Some(h) = headers.get(header::REFERER) {
		referer=h.to_str().unwrap_or("-").to_owned()
	} else {
		referer = "-".to_owned()
	}

	if let Some(h) = headers.get(header::USER_AGENT) {
		user_agent=h.to_str().unwrap_or("-").to_owned()
	} else {
		user_agent = "-".to_owned()
	}

	if referer != "-" {referer = ["\"", &referer, "\""].concat()}
	if user_agent != "-" {user_agent = ["\"", &user_agent, "\""].concat()}
	match format_type {
		"combinedvhost" => println!("{} {} - - [{}] \"{:#?} {} {:#?}\" {} {} {} {}", host, client_ip, time, method, path, version, status, lengthstr, referer, user_agent),
		"combined" => println!("{} - - [{}] \"{:#?} {} {:#?}\" {} {} {} {}", client_ip, time, method, path, version, status, lengthstr, referer, user_agent),
		"commonvhost" => println!("{} {} - - [{}] \"{:#?} {} {:#?}\" {} {}", host, client_ip, time, method, path, version, status, lengthstr),
		"common" => println!("{} - - [{}] \"{:#?} {} {:#?}\" {} {}", client_ip, time, method, path, version, status, lengthstr),
		"simple" => println!("[{}][{}{}] : {}", head, host, path, client_ip),
		"simpleplus" => println!("[{}][{} {}{} {:#?}][{}] : {}", head, method, host, path, version, user_agent, client_ip),
		_ => (),
	}
}

// Return a MIME type based on file extension. Assume that all text files are UTF-8, and don't try to guess the MIME type of unknown file extensions.
fn get_mime(path: &str) -> String {
	let guess = mime_guess::from_ext(path);
	if let Some(mime) = guess.first() {
		let mime = mime.to_string();

		if mime.starts_with("text/") && !mime.contains("charset") {
			return [&mime, "; charset=utf-8"].concat();
		}

		mime
	} else {
		"unknown/unknown".to_owned()
	}
}

// HTTP request handling
fn hsts(body: Payload, req: HttpRequest) -> Either<HttpResponse, Box<dyn Future<Item=HttpResponse, Error=Error>>> {
	let conf = rc(&CONFM);

	// If HSTS is enabled, only clients that add the update-insecure-requests header will get redirected to HTTPS. All widely used modern browsers apply this header.
	if !conf.hsts || req.headers().get(header::UPGRADE_INSECURE_REQUESTS).unwrap_or(&BLANKHEAD).to_str().unwrap_or("") != "1" {
		return index(body, req);
	}

	let conn_info = req.connection_info();
	let host = trim_port(conn_info.host());

	let tls_addr = conf.tls_addr.to_owned();
	let mut port = trim_host(&tls_addr);
	if port == ":443" {
		port = ""
	}

	log_data(&conf.log_format, 301, "WebHSTS", &req, &conn_info, None);
	Either::A(redir(&["https://", host, port, req.path()].concat()))
}

// HTTP(S) request handling.
fn index(body: Payload, req: HttpRequest) -> Either<HttpResponse, Box<dyn Future<Item=HttpResponse, Error=Error>>> {
	let conf = rc(&CONFM);

	let rawpath = &percent_decode(req.path().as_bytes()).decode_utf8_lossy();
	let conn_info = req.connection_info();

	let (path, host, fp) = conf.handle_path(rawpath, conn_info.host(), req.headers().get(header::AUTHORIZATION).unwrap_or(&BLANKHEAD).to_str().unwrap_or(""));

	if host == "redir" {
		if path == "unauth" {
			log_data(&conf.log_format, 401, "WebUnAuth", &req, &conn_info, None);
			return Either::A(ui::http_error(StatusCode::UNAUTHORIZED, "401 Unauthorized", "Valid credentials are required to acccess this resource.", conf.smaller_default))
		}
		log_data(&conf.log_format, 301, "WebRedir", &req, &conn_info, None);
		return Either::A(redir(&path));
	}

	if host == "proxy" {
		let mut path = path;
		if !req.query_string().is_empty() {
			path = path + "?" + req.query_string();
		}
		return Either::B(proxy_request(&path, req.method().to_owned(), req.headers(), body, conn_info.remote().unwrap_or("127.0.0.1"), &conf))
	}

	if req.method() != Method::GET && req.method() != Method::HEAD {
		log_data(&conf.log_format, 405, "WebBadMethod", &req, &conn_info, None);
		return Either::A(ui::http_error(StatusCode::METHOD_NOT_ALLOWED, "405 Method Not Allowed", "Only GET and HEAD methods are supported.", conf.smaller_default))
	}

	let mut full_path = match fp {
		Some(pf) => pf,
		None => [&*host, &*path].concat(),
	};

	let mime = get_mime(&full_path);
	let mim = trim_suffix("; charset=utf-8", &mime);

	// If the client accepts a brotli compressed response, then modify full_path to send one.
	let ce = req.headers().get(header::ACCEPT_ENCODING).unwrap_or(&BLANKHEAD).to_str().unwrap_or("");
	if ce.contains("br") {
		if conf.compress_files {
			if let Ok(path) = stream::get_compressed_file(&*full_path, mim) {full_path = path}
		} else if Path::new(&[&full_path, ".br"].concat()).exists() {
			full_path = [&full_path, ".br"].concat()
		}
	}

	// Open the file specified in full_path. If the file is not present, serve either a directory listing or an error.
	let (f, finfo);
	if let Ok((fi, m)) = open_meta(&full_path) {f = fi; finfo = m} else {
		if path.ends_with("/index.html") && !conf.smaller_default {
			log_data(&conf.log_format, 200, "WebDir", &req, &conn_info, None);
			return Either::A(ui::dir_listing(&[&*host, rawpath].concat(), &host))
		}

		log_data(&conf.log_format, 404, "WebNotFound", &req, &conn_info, None);
		return Either::A(ui::http_error(StatusCode::NOT_FOUND, "404 Not Found", &["The resource ", rawpath, " could not be found."].concat(), conf.smaller_default));
	}

	if finfo.is_dir() {
		return Either::A(redir(&[rawpath, "/"].concat()));
	}

	// Parse a ranges header if it is present, and then turn a File into a stream.
	let (length, offset) = stream::calculate_ranges(&req, finfo.len());
	let has_range = offset != 0 || length as u64 != finfo.len();
	let body = if length > conf.max_streaming_len || has_range {
		Body::from_message(BodyStream::new(stream::ChunkedReadFile {
			offset,
			size: length,
			file: Some(f),
			fut: None,
			counter: 0,
			chunk_size: conf.max_streaming_len,
		}))
	} else if length == 0 {
		Body::Bytes(Bytes::from("\n"))
	} else {
		Body::Bytes(stream::read_file(f).unwrap_or_else(|_| Bytes::from("")))
	};

	log_data(&conf.log_format, 200, "Web", &req, &conn_info, Some(length));

	// Craft a response.
	let cache_int = conf.caching_timeout;
	Either::A(HttpResponse::Ok()
			.if_true(&*mime != "unknown/unknown", |builder| { // Only specify a MIME type if we know one. If we do know one, don't let the browser override our decision.
				builder.content_type(&*mime);
				builder.header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
			})
			.header(header::ACCEPT_RANGES, "bytes")
			.header(header::CONTENT_LENGTH, length.to_string())
			.if_true(full_path.ends_with(".br"), |builder| {
				builder.header(header::CONTENT_ENCODING, "br");
				builder.encoding(ContentEncoding::Identity);
			})
			.if_true(!full_path.ends_with(".br") && stream::GZTYPES.binary_search(&&*mim).is_err(), |builder| {
				builder.encoding(ContentEncoding::Identity);
			})
			.if_true(has_range, |builder| {
				builder.status(StatusCode::PARTIAL_CONTENT);
				builder.header(header::CONTENT_RANGE, ["bytes ", &offset.to_string(), "-", &(offset+length-1).to_string(), "/", &finfo.len().to_string()].concat());
			})
			.if_true(cache_int == 0, |builder| {
				builder.header(header::CACHE_CONTROL, "no-store, must-revalidate");
			})
			.if_true(cache_int != 0, |builder| {
				builder.header(header::CACHE_CONTROL, ["max-age=", &(cache_int*3600).to_string(), ", public, stale-while-revalidate=", &(cache_int*900).to_string()].concat());
			})
			.if_true(conf.hsts, |builder| {
				builder.header(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000;includeSubDomains;preload");
			})
			.if_true(conf.protect, |builder| {
				builder.header(header::REFERRER_POLICY, "no-referrer");
				builder.header(header::CONTENT_SECURITY_POLICY, "upgrade-insecure-requests; default-src https: wss: data: 'unsafe-inline' 'unsafe-eval' 'self'; frame-ancestors 'self'");
				builder.header(header::X_XSS_PROTECTION, "1; mode=block");
			})
			.header(header::SERVER, "KatWebX")
			.body(body))
}

// Load configuration, SSL certs, then attempt to start the program.
fn main() {
	println!("[Warn]: You are using an unstable Git version of KatWebX. You WILL experience bugs, documentation will likely not be 100% accurate, and some functionality may not work properly. Never use Git versions in production, unless you know the code well, and are prepared to deal with issues as they come up.");
	println!("[Info]: Starting KatWebX...");
	let sys = System::new("katwebx");
	lazy_static::initialize(&CONFM);
	lazy_static::initialize(&BLANKHEAD);
	lazy_static::initialize(&stream::GZTYPES);
	let conf = Config::load_config(std::env::args().nth(1).unwrap_or_else(|| "conf.toml".to_owned()), true); // We can't hold the RwLock on the main thread, or we won't be able to reload the config. We'll have to read the config manually.
	env::set_current_dir(conf.root_folder.to_owned()).unwrap_or_else(|_| {
		println!("[Fatal]: Unable to open root folder!");
		process::exit(exitcode::NOINPUT); // If we let the webserver start where it isn't supposed to be, it could pose a security risk. Refusing to start outright is the best desision here.
	});

	let mut tconfig = ServerConfig::new(NoClientAuth::new());
	tconfig.ignore_client_order = conf.chacha; // Rustls has ChaChaPoly ciphers higher in the order than AES ciphers.

	let tls_folder = fs::read_dir(conf.cert_folder.to_owned()).unwrap_or_else(|_| {
		println!("[Fatal]: Unable to open certificate folder!");
		process::exit(exitcode::NOINPUT);
	});

	let mut cert_resolver = certs::ResolveCert::new([&conf.cert_folder, "/"].concat());
	for file in tls_folder {
		let f;
		if let Ok(fi) = file {
			f = fi;

			if f.path().extension() != Some(OsStr::new("crt")) {
				continue
			}

			let path = f.path();
			let pathnoext;
			if let Some(p) = path.file_stem() {
				pathnoext = p.to_string_lossy();
				cert_resolver.load(pathnoext.to_string()).unwrap_or_else(|err| {
					println!("[Warn]: {}", err)
				});
			}
		}
	}

	tconfig.cert_resolver = Arc::new(cert_resolver);

	#[cfg(unix)] {
		// Configuration reloading
		let signals = Signals::new(&[SIGHUP]).unwrap();
		thread::spawn(move || {
			for _ in signals.forever() {
				println!("[Info]: Reloading KatWebX's configuration...");
				let conf = Config::load_config(std::env::args().nth(1).unwrap_or_else(|| "conf.toml".to_owned()), true);
				// Although reloading the root folder when reloading the config may seem like a good idea, it could cause a lot of issues for users, especially those who specify a relative root folder path.
				//env::set_current_dir(conf.root_folder.to_owned()).unwrap_or_else(|_| {
				//	println!("[Fatal]: Unable to open root folder!");
				//	process::exit(exitcode::NOINPUT);
				//});
				let mut confw = CONFM.write().unwrap_or_else(|_| {
					// If the RwLock manages to get poisoned (which should be impossible), anything which requires access to the config will fail to function properly.
					println!("[Fatal]: Something seriously went wrong when KatWebX was reloading!");
					println!("Hot-reloading the config safely isn't perfect. You should never encounter this error, but if you do, please report it on KatWebX's GitHub.");
					process::exit(exitcode::SOFTWARE);
				});
				*confw = conf;
				println!("[Info]: Reload sucessful!");
			}
		});

		// Socket request handling
		let mut listenfd = ListenFd::from_env();
		if let Ok(Some(l)) = listenfd.take_tcp_listener(0) {
			HttpServer::new(
				|| App::new().route("/*", web::to(hsts)))
			.keep_alive(conf.stream_timeout as usize)
			.listen(l).unwrap_or_else(|_err| {
				println!("[Fatal]: Unable to initialize socket!");
				process::exit(exitcode::DATAERR);
			})
			.start();

			if let Ok(Some(li)) = listenfd.take_tcp_listener(1) {
				HttpServer::new(
					|| App::new().route("/*", web::to(index)))
				.keep_alive(conf.stream_timeout as usize)
				.listen_rustls(li, tconfig).unwrap_or_else(|_err| {
					println!("[Fatal]: Unable to initialize socket!");
					process::exit(exitcode::DATAERR);
				})
				.start();
			}

			println!("[Info]: Started KatWebX in socket mode.");
			let _ = sys.run();
			println!("\n[Info]: Stopping KatWebX...");
			return
		}
	}

	// TCP request handling
	HttpServer::new(
		|| App::new().route("/*", web::to(index)))
		.keep_alive(conf.stream_timeout as usize)
		.bind_rustls(&conf.tls_addr, tconfig)
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to ", &conf.tls_addr, "!"].concat());
			process::exit(exitcode::NOPERM);
		})
		.start();

	HttpServer::new(
		|| App::new().route("/*", web::to(hsts)))
		.keep_alive(conf.stream_timeout as usize)
		.bind(&conf.http_addr)
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to ", &conf.http_addr, "!"].concat());
			process::exit(exitcode::NOPERM);
		})
		.start();

	println!("[Info]: Started KatWebX.");
	let _ = sys.run();
	println!("\n[Info]: Stopping KatWebX...");
}