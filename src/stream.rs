// Mostly copied from actix-files, with minor modifications. Actix Copyright (c) 2017 Nikolay Kim

// This is currently a non-issue, and can be ignored.
#![allow(clippy::filter_map)]

extern crate lazy_static;
extern crate actix_web;
extern crate futures;
extern crate futures_cpupool;
extern crate brotli;
extern crate bytes;

use futures::{Async, Future, Poll, Stream};
use bytes::Bytes;
use std::{io, io::{Error, Seek, Read}, fs::File, cmp, path::Path};
use actix_web::{web, HttpRequest, http::header};
use actix_web::error::{BlockingError, ErrorInternalServerError};
use self::brotli::{BrotliCompress, enc::encode::BrotliEncoderInitParams};

lazy_static! {
	pub static ref gztypes: Vec<&'static str> = vec!["application/javascript", "application/json", "application/x-javascript", "image/svg+xml", "text/css", "text/csv", "text/html", "text/plain", "text/xml"];
}

pub fn get_compressed_file(path: &str, mime: &str) -> Result<String, Error> {
	if Path::new(&[path, ".br"].concat()).exists() {
		return Ok([path, ".br"].concat())
	}

	if Path::new(&path).exists() && !Path::new(&[path, ".br"].concat()).exists() && gztypes.binary_search(&&*mime).is_ok() {
		let mut fileold = File::open(path)?;
		let mut filenew = File::create(&[path, ".br"].concat())?;
		let _ = BrotliCompress(&mut fileold, &mut filenew, &BrotliEncoderInitParams())?;
		return Ok([path, ".br"].concat())
	}

	Ok(path.to_string())
}

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

static PREFIX: &'static str = "bytes=";
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

type FileFut = Box<Future<Item = (File, Bytes), Error = BlockingError<io::Error>>>;

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
