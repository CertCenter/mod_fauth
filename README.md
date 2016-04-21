# Installation

**Download mod_fauth.c**

$ curl -O 'https://raw.githubusercontent.com/CertCenter/mod_fauth/master/mod_fauth.c'

**Build mod_fauth.so**

$ apxs -c -i mod_fauth.c -I/usr/include/openssl -lssl

**Activate the module**

1. Add **LoadModule fauth_module modules/mod_fauth.so** to your httpd.conf
2. Restart Apache (**service httpd restart**)

# Requirements

 - openssl-devel  (OpenSSL Client Library)
 - httpd-devel    (apxs)
 - gcc

# Supported CAs/Products

 - Thawte DV
 - GeoTrust DV
 - RapidSSL DV
 - GlobalSign DV
 - AlphaSSL DV
 - AlwaysOnSSL

# Detailed information

 - English: https://blog.certcenter.com/2016/04/mod-fauth-fileauth-without-files/
 - German: https://blog.certcenter.de/2016/04/fileauth-without-files/
