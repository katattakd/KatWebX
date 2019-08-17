// Stream.rs handles various internal HTTP functions. If you're working on a fork of KatWebX, don't expect the functionality of this file to be stable between releases.

// This is purely style based and can be ignored.
#![allow(clippy::filter_map)]
// This can't be easily fixed, due to a limitation of Rust's standard library.
#![allow(clippy::cast_possible_truncation)]

extern crate lazy_static;
extern crate actix_web;
extern crate futures;
extern crate futures_cpupool;
extern crate brotli;
extern crate bytes;

use futures::{Async, Future, Poll, Stream};
use bytes::Bytes;
use std::{io, io::{Error, Seek, Read}, fs::{File, Metadata}, cmp, path::Path};
use actix_web::{web, HttpRequest, http::header};
use actix_web::error::{BlockingError, ErrorInternalServerError};
use self::brotli::{BrotliCompress, enc::encode::BrotliEncoderInitParams};

lazy_static! {
	/* A non-exaustive list of MIME types that should compress well. Note that this list MUST be in alphabetical order, with no duplicate items.
	Mime types from https://github.com/abonander/mime_guess/blob/master/src/mime_types.rs must be used, because that is the library KatWebX uses to detect mime types of files. */
	pub static ref GZTYPES: Vec<&'static str> = vec!["application/atom+xml", "application/atomcat+xml", "application/atomsvc+xml", "application/ccxml+xml", "application/dash+xml", "application/davmount+xml", "application/docbook+xml", "application/dssc+xml", "application/ecmascript", "application/emma+xml", "application/fsharp-script", "application/geo+json", "application/gml+xml", "application/gpx+xml", "application/hjson", "application/inkml+xml", "application/javascript", "application/json", "application/json5", "application/jsonml+json", "application/ld+json", "application/lost+xml", "application/mads+xml", "application/manifest+json", "application/marcxml+xml", "application/mediaservercontrol+xml", "application/metalink+xml", "application/metalink4+xml", "application/mets+xml", "application/mods+xml", "application/oebps-package+xml", "application/olescript", "application/omdoc+xml", "application/opensearchdescription+xml", "application/patch-ops-error+xml", "application/pkcs10", "application/pkcs8", "application/postscript", "application/pskc+xml", "application/raml+yaml", "application/rdf+xml", "application/reginfo+xml", "application/resource-lists+xml", "application/resource-lists-diff+xml", "application/rsd+xml", "application/rss+xml", "application/sbml+xml", "application/shf+xml", "application/smil+xml", "application/sparql-results+xml", "application/srgs+xml", "application/sru+xml", "application/ssdl+xml", "application/ssml+xml", "application/tei+xml", "application/thraud+xml", "application/vnd.adobe.xdp+xml", "application/vnd.apple.installer+xml", "application/vnd.chemdraw+xml", "application/vnd.citationstyles.style+xml", "application/vnd.criticaltools.wbs+xml", "application/vnd.dece.ttml+xml", "application/vnd.eszigno3+xml", "application/vnd.hal+xml", "application/vnd.handheld-entertainment+xml", "application/vnd.irepository.package+xml", "application/vnd.las.las+xml", "application/vnd.llamagraphics.life-balance.exchange+xml", "application/vnd.mozilla.xul+xml", "application/vnd.oma.dd2+xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.openxmlformats-officedocument.presentationml.slide", "application/vnd.openxmlformats-officedocument.presentationml.slideshow", "application/vnd.openxmlformats-officedocument.presentationml.template", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.template", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.openxmlformats-officedocument.wordprocessingml.template", "application/vnd.recordare.musicxml", "application/vnd.recordare.musicxml+xml", "application/vnd.route66.link66+xml", "application/vnd.solent.sdkm+xml", "application/vnd.sun.xml.calc", "application/vnd.sun.xml.calc.template", "application/vnd.sun.xml.draw", "application/vnd.sun.xml.draw.template", "application/vnd.sun.xml.impress", "application/vnd.sun.xml.impress.template", "application/vnd.sun.xml.math", "application/vnd.sun.xml.writer", "application/vnd.sun.xml.writer.global", "application/vnd.sun.xml.writer.template", "application/vnd.syncml+xml", "application/vnd.syncml.dm+wbxml", "application/vnd.syncml.dm+xml", "application/vnd.uoml+xml", "application/vnd.wap.wbxml", "application/vnd.wap.wmlc", "application/vnd.wap.wmlscriptc", "application/vnd.yamaha.openscoreformat.osfpvg+xml", "application/vnd.zzazz.deck+xml", "application/voicexml+xml", "application/wasm", "application/windows-library+xml", "application/windows-search-connector+xml", "application/wspolicy+xml", "application/x-dtbncx+xml", "application/x-dtbook+xml", "application/x-dtbresource+xml", "application/x-httpd-php", "application/x-javascript", "application/x-pkcs12", "application/x-pkcs7-certificates", "application/x-sh", "application/x-subrip", "application/x-web-app-manifest+json", "application/x-x509-ca-cert", "application/x-xliff+xml", "application/xaml+xml", "application/xcap-diff+xml", "application/xenc+xml", "application/xhtml+xml", "application/xml", "application/xspf+xml", "application/xv+xml", "application/yin+xml", "chemical/x-cml", "image/svg+xml", "message/rfc822", "model/gltf+json", "model/vnd.collada+xml", "model/x3d+xml", "text/cache-manifest", "text/coffeescript", "text/css", "text/csv", "text/dlm", "text/h323", "text/html", "text/iuls", "text/jade", "text/jscript", "text/less", "text/markdown", "text/mathml", "text/n3", "text/plain", "text/prs.lines.tag", "text/richtext", "text/scriptlet", "text/sgml", "text/shex", "text/slim", "text/stylus", "text/tab-separated-values", "text/turtle", "text/uri-list", "text/vbscript", "text/vcard", "text/vnd.curl.mcurl", "text/vnd.dvb.subtitle", "text/vnd.fly", "text/vnd.fmi.flexstor", "text/vnd.graphviz", "text/vnd.in3d.3dml", "text/vnd.in3d.spot", "text/vnd.sun.j2me.app-descriptor", "text/vnd.wap.wml", "text/vnd.wap.wmlscript", "text/vtt", "text/webviewhtml", "text/x-c", "text/x-component", "text/x-fortran", "text/x-handlebars-template", "text/x-hdml", "text/x-html-insertion", "text/x-lua", "text/x-markdown", "text/x-ms-contact", "text/x-ms-group", "text/x-ms-iqy", "text/x-ms-rqy", "text/x-nfo", "text/x-opml", "text/x-pascal", "text/x-processing", "text/x-rust", "text/x-sass", "text/x-scss", "text/x-setext", "text/x-sfv", "text/x-suse-ymp", "text/x-toml", "text/x-uuencode", "text/x-vcard", "text/x-yaml", "text/xml", "x-world/x-vrml"];
}

// Trim the port from an IPv4 address, IPv6 address, or domain:port.
pub fn trim_port(path: &str) -> &str {
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

// Trim the host from an IPv4 address, IPv6 address, or domain:port.
pub fn trim_host(path: &str) -> &str {
	if path.contains('[') && path.contains(']') {
		match path.rfind("]:") {
			Some(i) => return &path[i+1..],
			None => return "",
		};
	}

	match path.rfind(':') {
		Some(i) => &path[i..],
		None => "",
	}
}

// Trim a substring (prefix) from the beginning of a string.
pub fn trim_prefix<'a>(prefix: &'a str, root: &'a str) -> &'a str {
	match root.find(prefix) {
		Some(i) => &root[i+prefix.len()..],
		None => root,
	}
}

// Trim a substring (suffix) from the end of a string.
pub fn trim_suffix<'a>(suffix: &'a str, root: &'a str) -> &'a str {
	match root.rfind(suffix) {
		Some(i) => &root[..i],
		None => root,
	}
}

// Open both a file, and the file's metadata.
pub fn open_meta(path: &str) -> Result<(File, Metadata), Error> {
	let f = File::open(path)?;
	let m =  f.metadata()?;
	Ok((f, m))
}

pub fn get_compressed_file(path: &str, mime: &str) -> Result<String, Error> {
	if Path::new(&[path, ".br"].concat()).exists() {
		return Ok([path, ".br"].concat())
	}

	if Path::new(&path).exists() && !Path::new(&[path, ".br"].concat()).exists() && GZTYPES.binary_search(&&*mime).is_ok() {
		let mut fileold = File::open(path)?;
		let mut filenew = File::create(&[path, ".br"].concat())?;
		let _ = BrotliCompress(&mut fileold, &mut filenew, &BrotliEncoderInitParams())?;
		return Ok([path, ".br"].concat())
	}

	Ok(path.to_string())
}

// The below code is copied from actix-files, with minor modifications. Actix Copyright (c) 2017 Nikolay Kim

pub fn calculate_ranges(req: &HttpRequest, length: u64) -> (u64, u64) {
	if let Some(ranges) = req.headers().get(header::RANGE) {
		if let Ok(rangesheader) = ranges.to_str() {
			if let Ok(rangesvec) = HttpRange::parse(rangesheader, length) {
				return (rangesvec[0].length, rangesvec[0].start)
			} else {
				return (length, 0);
			};
		} else {
			return (length, 0);
		};
	};
	(length, 0)
}

pub struct HttpRange {
    pub start: u64,
    pub length: u64,
}

static PREFIX: &str = "bytes=";
const PREFIX_LEN: usize = 6;

impl HttpRange {
    pub fn parse(header: &str, size: u64) -> Result<Vec<Self>, ()> {
        if header.is_empty() {
            return Ok(Vec::new());
        }
        if !header.starts_with(PREFIX) {
            return Err(());
        }

        let size_sig = size;
        let mut no_overlap = false;

        let all_ranges: Vec<Option<Self>> = header[PREFIX_LEN..]
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(|ra| {
                let mut start_end_iter = ra.split('-');

                let start_str = start_end_iter.next().ok_or(())?.trim();
                let end_str = start_end_iter.next().ok_or(())?.trim();

                if start_str.is_empty() {
                    let mut length: u64 = try!(end_str.parse().map_err(|_| ()));

                    if length > size_sig {
                        length = size_sig;
                    }

                    Ok(Some(Self {
                        start: (size_sig - length),
                        length,
                    }))
                } else {
                    let start: u64 = start_str.parse().map_err(|_| ())?;

                    //if start < 0 {
                    //    return Err(());
                    //}
                    if start >= size_sig {
                        no_overlap = true;
                        return Ok(None);
                    }

                    let length = if end_str.is_empty() {
                        size_sig - start
                    } else {
                        let mut end: u64 = end_str.parse().map_err(|_| ())?;

                        if start > end {
                            return Err(());
                        }

                        if end >= size_sig {
                            end = size_sig - 1;
                        }

                        end - start + 1
                    };

                    Ok(Some(Self {
                        start,
                        length,
                    }))
                }
            }).collect::<Result<_, _>>()?;

        let ranges: Vec<Self> = all_ranges.into_iter().filter_map(|x| x).collect();

        if no_overlap && ranges.is_empty() {
            return Err(());
        }

        Ok(ranges)
    }
}

pub fn read_file(mut f: File) -> Result<Bytes, Error> {
	let mut buffer = Vec::new();
	f.read_to_end(&mut buffer)?;

	Ok(Bytes::from(buffer))
}

type FileFut = Box<dyn Future<Item = (File, Bytes), Error = BlockingError<io::Error>>>;

pub struct ChunkedReadFile {
    pub size: u64,
    pub offset: u64,
    pub file: Option<File>,
    pub fut: Option<FileFut>,
    pub counter: u64,
	pub chunk_size: u64
}

fn handle_error(err: BlockingError<io::Error>) -> actix_web::Error {
    match err {
        BlockingError::Error(err) => err.into(),
        BlockingError::Canceled => ErrorInternalServerError("Unexpected error"),
    }
}

impl Stream for ChunkedReadFile {
    type Item = Bytes;
    type Error = actix_web::Error;

    fn poll(&mut self) -> Poll<Option<Bytes>, actix_web::Error> {
        if self.fut.is_some() {
            return match self.fut.as_mut().unwrap().poll().map_err(handle_error)? {
                Async::Ready((file, bytes)) => {
                    self.fut.take();
                    self.file = Some(file);
                    self.offset += bytes.len() as u64;
                    self.counter += bytes.len() as u64;
                    Ok(Async::Ready(Some(bytes)))
                }
                Async::NotReady => Ok(Async::NotReady),
            };
        }

        let size = self.size;
        let offset = self.offset;
        let counter = self.counter;
		let chunks = self.chunk_size;

        if size == counter {
            Ok(Async::Ready(None))
        } else {
            let mut file = self.file.take().expect("Use after completion");
            self.fut = Some(Box::new(web::block(move || {
                let max_bytes: u64;
                max_bytes = cmp::min(size.saturating_sub(counter), chunks);
                let mut buf = Vec::with_capacity(max_bytes as usize);
                file.seek(io::SeekFrom::Start(offset))?;
                let nbytes =
                    file.by_ref().take(max_bytes).read_to_end(&mut buf)?;
                if nbytes == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                Ok((file, Bytes::from(buf)))
            })));
            self.poll()
        }
    }
}
