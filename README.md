## KatWebX
An extremely fast static web-server and reverse proxy for the modern web. More info is available on [KatWebX.kittyhacker101.tk](https://katwebx.kittyhacker101.tk/).

## Important Info
KatWebX is a work in progress, and you will likely encounter bugs. **KatWebX is not well tested, production use is not recommended!**  If you need something which will is well tested and can be used in production, check out [KatWeb](https://github.com/kittyhacker101/KatWeb) instead.

Interested in the project? You can help fund KatWebX's development by donating to the Bitcoin address `1KyggZGHF4BfHoHEXxoGzDmLmcGLaHN2x2`.

## Release Schedule
Approximate dates for the release of KatWebX (and discontinuing of KatWeb) are listed below.
 - December 16, 2018 - KatWebX's first beta release.
 - January 12, 2019 - KatWebX's first pre-release. During the time from pre-release to release, no new features will be added, and the configuration format will not be changed.
 - Febuary 3, 2019 - KatWebX's first release.
 - Febuary 17, 2019 - A tool is released to automatically migrate configuration from KatWeb to KatWebX.
 - March 2, 2019 - All KatWeb users will be told to upgrade to KatWebX.
 - June 13, 2019 - KatWeb is given EOL status, and is discontinued. For users who still rely on KatWeb, per-person upgrade support and additional patches to KatWeb will be available on request until December 16, 2019.

## Current Features
- Flexible config parsing
- Regex-based redirects
- Compressed regex-based reverse proxy
- HTTP basic authentication
- Fast file serving
- Brotli file compression
- HSTS support
- SNI and OCSP reponse stapling
- High peformance HTTP/2 and TLS 1.3
- Multiple logging types
- Material design server-generated pages

## Possible Features
- On-the-fly config reloading
- QUIC support
- TLS mutual auth
- Let's Encrypt integration
- Caching proxy
- Advanced load balancer
