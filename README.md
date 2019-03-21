## KatWebX [![Build status](https://ci.appveyor.com/api/projects/status/9fjk67yk8ei7hnlg/branch/master?svg=true)](https://ci.appveyor.com/project/kittyhacker101/katwebx/branch/master) [![Build Status](https://travis-ci.com/kittyhacker101/KatWebX.svg?branch=master)](https://travis-ci.com/kittyhacker101/KatWebX) [![Percentage of issues still open](http://isitmaintained.com/badge/open/kittyhacker101/KatWebX.svg)](http://isitmaintained.com/project/kittyhacker101/KatWebX "Percentage of issues still open") [![Average time to resolve an issue](http://isitmaintained.com/badge/resolution/kittyhacker101/KatWebX.svg)](http://isitmaintained.com/project/kittyhacker101/KatWebX "Average time to resolve an issue")
An extremely fast static web-server and reverse proxy for the modern web. More info is available on [KatWebX.kittyhacker101.tk](https://katwebx.kittyhacker101.tk/).

## Important Info
KatWebX is stil a work in progress, and you may encounter issues. **KatWebX is not well tested, production use is not recommended!**  If you need something which will is well tested and can be used in production, check out [KatWeb](https://github.com/kittyhacker101/KatWeb) instead.

Interested in the project? You can help fund KatWebX's development by donating to the Bitcoin address `1KyggZGHF4BfHoHEXxoGzDmLmcGLaHN2x2`.

## Release Schedule
Approximate dates for the release of KatWebX (and discontinuing of KatWeb) are listed below.
- March - KatWebX's first release.
- April 7 - A tool is released to automatically migrate existing setups from KatWeb to KatWebX. All KatWeb users will be told to upgrade to KatWebX.
- June 13 - KatWeb is given EOL status, and is discontinued. For users who still rely on KatWeb, per-person upgrade support and additional patches to KatWeb will be available on request until December 16, 2019.

## Current Features
- Easy to read TOML configuration
- Flexible configuration parsing
- Regex-based redirects
- Compressed regex-based reverse proxy
- Websocket reverse proxying
- HTTP basic authentication
- Fast file serving
- Brotli file compression
- Systemd/systemfd socket listening
- HSTS support
- SNI and OCSP response stapling
- High performance HTTP/2 and TLS 1.3
- Multiple logging types
- Material design server-generated pages

## Possible Features (probably won't be implemented soon, but a possibility in the future)
- On-the-fly config reloading (Work in progress)
- Let's Encrypt integration (Difficult but practical to implement, possible in the future)
- Caching proxy (Currently very difficult to implement, unlikely to be implemented in the near future)
- Advanced load balancer (Likely to be implemented in the near future)

## Unlikely features (will not be implemented soon or at all)
- QUIC support (The underlying HTTP library (actix-web) doesn't support it, and [only 1 browser supports it out of the box](https://en.wikipedia.org/wiki/QUIC#Adoption). Until it gets more adoption, I'm not going to put effort into adding it myself.)
- FastCGI support (There are no existing client libraries for Rust, and there's no real reason to implement it anyways. [HTTP/2 can do everything that FastCGI does](https://ef.gy/fastcgi-is-pointless), and KatWebX has an HTTP/2 capable reverse proxy built-in.)
- SPDY support ([SPDY is dying](https://caniuse.com/#feat=spdy), as it's being replaced by HTTP/2. KatWebX has full support for HTTP/2.)
- TLS 1.1 or older ([All recent browsers support TLS 1.2 or higher](https://caniuse.com/#feat=tls1-2), and these older TLS protocols are very insecure.)
