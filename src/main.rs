#[macro_use]
extern crate lazy_static;
extern crate bytes;
extern crate futures;
extern crate actix_web;
extern crate openssl;
extern crate mime;
extern crate mime_guess;
extern crate mime_sniffer;
extern crate json;
mod stream;
use actix_web::{server, server::ServerFlags, App, HttpRequest, HttpResponse, AsyncResponder, Error, http::StatusCode, http::header, http::Method, server::OpensslAcceptor};
use openssl::ssl::{SslMethod, SslAcceptor, SslFiletype};
use futures::future::{Future, result};
use std::{process, cmp, fs, fs::File, path::Path, io::Read};
use mime_sniffer::MimeTypeSniffer;

fn open_meta(path: &str) -> Result<(fs::File, fs::Metadata), Error> {
	let f = File::open(path)?;
	let m =  f.metadata()?;
	return Ok((f, m));
}

fn get_mime(data: &Vec<u8>, path: &str) -> String {
	let mut mime = mime_guess::guess_mime_type(path).to_string();
	if mime == "application/octet-stream" {
		let mreq = mime_sniffer::HttpRequest {
			content: data,
			url: &["http://localhost", path].concat(),
			type_hint: "unknown/unknown",
		};

		mime = mreq.sniff_mime_type().unwrap_or("text/plain; charset=utf-8").to_string();
	}
	if mime == "unknown/unknown" {
		mime = "application/octet-stream".to_string()
	}
	if mime.starts_with("text/") && !mime.contains("charset") {
		mime = [mime, "; charset=utf-8".to_string()].concat();
	}

	return mime
}

lazy_static! {
	static ref confraw: String = fs::read_to_string("conf.json").unwrap_or("{\"cachingTimeout\": 4,\"hide\": [\"src\"],\"advanced\": {\"protect\": true,\"httpPort\": 80,\"tlsPort\": 443}}".to_string());
	static ref config: json::JsonValue<> = json::parse(&confraw).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to parse configuration!");
		process::exit(1);
	});
}

fn index(_req: &HttpRequest) -> Box<Future<Item=HttpResponse, Error=Error>> {
	if _req.method() != Method::GET && _req.method() != Method::HEAD {
		return result(Ok(
			HttpResponse::Ok()
				.status(StatusCode::METHOD_NOT_ALLOWED)
				.content_type("text/plain")
				.body("405 Method Not Allowed")))
				.responder();
	}

	let mut pathd = [_req.path()].concat();
	if pathd.ends_with("/") {
		pathd = [pathd, "index.html".to_string()].concat();
	}
	let path = &pathd;

	let conn_info = _req.connection_info();
	let mut host = conn_info.host();
	if host == "ssl" || host.len() < 1 || host[0..1] == ".".to_string() || host.contains("/") || host.contains("\\") || config["hide"].contains(host) {
		host = "html"
	}
	println!("{:?}",[host, path].concat());
	if !Path::new(host).exists() {
		host = "html"
	}

	if path.contains("..") {
		return result(Ok(
			HttpResponse::Ok()
				.status(StatusCode::FORBIDDEN)
				.content_type("text/plain")
				.body("403 Forbidden")))
				.responder();
	}

	let (mut f, finfo);

	match open_meta(&[host, path].concat()) {
		Ok((fi, m)) => {f = fi; finfo = m},
		Err(_) => {
			return result(Ok(
				HttpResponse::Ok()
					.status(StatusCode::NOT_FOUND)
					.content_type("text/plain")
					.body("404 Not Found")))
					.responder();
		}
	}

	let mut sniffer_data = vec![0; cmp::min(512, finfo.len() as usize)];
	f.read_exact(&mut sniffer_data).unwrap_or(());

	let reader = stream::ChunkedReadFile {
		offset: 0,
		size: finfo.len(),
		cpu_pool: _req.cpu_pool().clone(),
		file: Some(f),
		fut: None,
		counter: 0,
	};

	let cache_int = config["cachingTimeout"].as_i64().unwrap_or(0);
	result(Ok(
		HttpResponse::Ok()
	        .content_type(get_mime(&sniffer_data, &[host, path].concat()))
			.if_true(cache_int == 0, |builder| {
				builder.header(header::CACHE_CONTROL, "no-store, must-revalidate");
			})
			.if_true(cache_int != 0, |builder| {
				builder.header(header::CACHE_CONTROL, ["max-age=".to_string(), (cache_int*3600).to_string(), ", public, stale-while-revalidate=".to_string(), (cache_int*900).to_string()].concat());
			})
			.if_true(config["advanced"]["protect"].as_bool().unwrap_or(false), |builder| {
				builder.header(header::REFERRER_POLICY, "no-referrer");
				builder.header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
				builder.header(header::CONTENT_SECURITY_POLICY, "default-src https: data: 'unsafe-inline' 'unsafe-eval' 'self'; frame-ancestors 'self'");
				builder.header(header::X_XSS_PROTECTION, "1; mode=block");
			})
			.header(header::SERVER, "KatWebX-Alpha")
            .streaming(reader)))
        	.responder()
}

fn main() {
	fs::write("conf.json", config.pretty(2)).unwrap_or_else(|_err| {
		println!("[Warn]: Unable to write configuration!");
	});

	let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to create OpenSSL builder!");
		process::exit(1);
	});
	builder.set_private_key_file("ssl/key.pem", SslFiletype::PEM).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to load ssl/key.pem!");
		process::exit(1);
	});
	builder.set_certificate_chain_file("ssl/cert.pem").unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to load ssl/cert.pem!");
		process::exit(1);
	});
	let acceptor = OpensslAcceptor::with_flags(builder, ServerFlags::HTTP1 | ServerFlags::HTTP2).unwrap_or_else(|_err| {
		println!("[Fatal]: Unable to create OpenSSL acceptor!");
		process::exit(1);
	});

    server::new(|| {
        vec![
			App::new()
				.default_resource(|r| r.f(index))
		]
	})
		.keep_alive(config["streamTimeout"].as_usize().unwrap_or(0)*4)
		.bind_with(["[::]:".to_string(), config["advanced"]["tlsPort"].as_u16().unwrap_or(443).to_string()].concat(), acceptor)
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to port ".to_string(), config["advanced"]["tlsPort"].as_u16().unwrap_or(443).to_string(), "!".to_string()].concat());
			process::exit(1);
		})
		.bind(["[::]:".to_string(), config["advanced"]["httpPort"].as_u16().unwrap_or(80).to_string()].concat())
		.unwrap_or_else(|_err| {
			println!("{}", ["[Fatal]: Unable to bind to port ".to_string(), config["advanced"]["httpPort"].as_u16().unwrap_or(80).to_string(), "!".to_string()].concat());
			process::exit(1);
		})
        .run();
}
