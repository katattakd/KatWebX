## KatWebX [![Build status](https://ci.appveyor.com/api/projects/status/9fjk67yk8ei7hnlg/branch/master?svg=true)](https://ci.appveyor.com/project/kittyhacker101/katwebx/branch/master) [![Build Status](https://travis-ci.com/kittyhacker101/KatWebX.svg?branch=master)](https://travis-ci.com/kittyhacker101/KatWebX) [![Percentage of issues still open](http://isitmaintained.com/badge/open/kittyhacker101/KatWebX.svg)](http://isitmaintained.com/project/kittyhacker101/KatWebX "Percentage of issues still open") [![Average time to resolve an issue](http://isitmaintained.com/badge/resolution/kittyhacker101/KatWebX.svg)](http://isitmaintained.com/project/kittyhacker101/KatWebX "Average time to resolve an issue")
An extremely fast static web-server and reverse proxy for the modern web. More info is available on [KatWebX.kittyhacker101.tk](https://katwebx.kittyhacker101.tk/).

## Important Info
KatWebX is still a work in progress, and you may encounter issues. **KatWebX is not well tested, production use is not recommended!**  If you need something which will is well tested and can be used in production, check out [KatWeb](https://github.com/kittyhacker101/KatWeb) instead.

Interested in the project? You can help fund KatWebX's development by donating to the Bitcoin address `1KyggZGHF4BfHoHEXxoGzDmLmcGLaHN2x2`.

## Release Schedule
Approximate dates for the release of KatWebX (and discontinuing of KatWeb) are listed below.
- June - KatWebX's first release.
- July - A guide is released to automatically migrate existing setups from KatWeb to KatWebX. All KatWeb users will be told to upgrade to KatWebX.
- August - KatWeb is given EOL status, and is discontinued. For users who still rely on KatWeb, per-person upgrade support and additional patches to KatWeb will be available on request until December 16, 2019.

## Known issues (as of this document's writing)
- Pre-release 1 and older will slowly leak memory, especially with large files. Restarting the server occasionally will fix this issue. This has been fixed in the current git version.
- The current git version's reverse proxy misbehaves when dealing with servers that don't support keep-alive.
- The current git version's websocket implementation is buggy at best, and nonfunctional at worst.
- The current git version has some minor bugs that can cause clients to misbehave. This is an upstream issue, and will be fixed soon.

## Current Features
- Easy to read TOML configuration
- Flexible configuration parsing
- Regex-based redirects
- Compressed regex-based reverse proxy
- Websocket reverse proxying
- HTTP basic authentication
- Extremely fast file serving
- Brotli file compression
- Systemd/systemfd socket listening
- On-the-fly config reloading
- HSTS support
- SNI and OCSP response stapling
- High performance HTTP/2 and TLS 1.3
- Multiple logging formats
- Material design server-generated pages

## Possible Features (probably won't be implemented soon, but a possibility in the future)
- Let's Encrypt integration (Difficult but practical to implement, possible in the future)
- Caching proxy (Currently very difficult to implement, unlikely to be implemented in the near future)
- Advanced load balancer (May be implemented in the future)

## Unlikely features (will not be implemented soon or at all)
- QUIC support (The underlying HTTP library (actix-web) doesn't support it, and [only 1 browser supports it out of the box](https://en.wikipedia.org/wiki/QUIC#Adoption). Until it gets more adoption, I'm not going to put effort into adding it myself.)
- CGI/FastCGI support (There are no existing client libraries for Rust, and there's no real reason to implement it anyways. [HTTP/2 can do everything that FastCGI does](https://ef.gy/fastcgi-is-pointless), and KatWebX has an HTTP/2 capable reverse proxy built-in.)
- SPDY support ([SPDY is dying](https://caniuse.com/#feat=spdy), as it's being replaced by HTTP/2. KatWebX has full support for HTTP/2.)
- TLS 1.1 or older ([All recent browsers support TLS 1.2 or higher](https://caniuse.com/#feat=tls1-2), and these older TLS protocols are very insecure.)
- Support for more architectures (The underlying encryption library (Rustls) uses Ring for high-performance encryption, and Ring doesn't compile on many architectures. The only way to work around this would be to switch to a different encryption library, and change all TLS related code. There are currently no existing alternatives to Rustls that meet all of KatWebX's needs.)
- Documentation in other languages (I don't know any other languages, and I don't have the resources to hire a translator.)
