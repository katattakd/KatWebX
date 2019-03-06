// Mostly copied from actix-web. Actix Copyright (c) 2017 Nikolay Kim
// Original source: https://github.com/actix/actix-web/blob/v0.7.8/src/fs.rs

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
use actix_web::{HttpRequest, http::header};
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

pub fn calculate_ranges(req: &HttpRequest, length: usize) -> (usize, usize) {
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
    pub start: usize,
    pub length: usize,
}

static PREFIX: &'static str = "bytes=";
const PREFIX_LEN: usize = 6;

impl HttpRange {
    pub fn parse(header: &str, size: usize) -> Result<Vec<Self>, ()> {
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
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|ra| {
                let mut start_end_iter = ra.split('-');

                let start_str = start_end_iter.next().ok_or(())?.trim();
                let end_str = start_end_iter.next().ok_or(())?.trim();

                if start_str.is_empty() {
                    let mut length: usize = try!(end_str.parse().map_err(|_| ()));

                    if length > size_sig {
                        length = size_sig;
                    }

                    Ok(Some(Self {
                        start: (size_sig - length),
                        length,
                    }))
                } else {
                    let start: usize = start_str.parse().map_err(|_| ())?;

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
                        let mut end: usize = end_str.parse().map_err(|_| ())?;

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

pub struct ChunkedReadFile {
    pub size: usize,
    pub offset: usize,
    pub cpu_pool: futures_cpupool::CpuPool,
    pub file: Option<File>,
    pub fut: Option<futures_cpupool::CpuFuture<(File, Bytes), io::Error>>,
    pub counter: usize,
	pub chunk_size: usize,
}

impl Stream for ChunkedReadFile {
    type Item = Bytes;
    type Error = actix_web::Error;
    fn poll(&mut self) -> Poll<Option<Bytes>, actix_web::Error> {
        if self.fut.is_some() {
            return match self.fut.as_mut().unwrap().poll()? {
                Async::Ready((file, bytes)) => {
                    self.fut.take();
                    self.file = Some(file);
                    self.offset += bytes.len();
                    self.counter += bytes.len();
                    Ok(Async::Ready(Some(bytes)))
                }
                Async::NotReady => Ok(Async::NotReady),
            };
        }
        let size = self.size;
        let offset = self.offset;
        let counter = self.counter;
        if size == counter {
            Ok(Async::Ready(None))
        } else {
            let mut file = self.file.take().expect("Use after completion");
			let chunk_sz = self.chunk_size.to_owned();
            self.fut = Some(self.cpu_pool.spawn_fn(move || {
                let max_bytes: usize;
                max_bytes = cmp::min(size.saturating_sub(counter), chunk_sz);
                let mut buf = Vec::with_capacity(max_bytes);
                file.seek(io::SeekFrom::Start(offset as u64))?;
                let nbytes = file.by_ref().take(max_bytes as u64).read_to_end(&mut buf)?;
                if nbytes == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                Ok((file, Bytes::from(buf)))
            }));
            self.poll()
        }
    }
}
