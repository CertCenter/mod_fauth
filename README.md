# Download mod_fauth.c
$ curl -O 'https://raw.githubusercontent.com/CertCenter/mod_fauth/master/mod_fauth.c'
# Build mod_fauth.so
$ apxs -c -i mod_fauth.c -I/usr/include/openssl -lssl
# Add "LoadModule fauth_module modules/mod_fauth.so" to your httpd.conf
$ {..}
# Restart httpd
$ service httpd restart

Requirements:

	- openssl-devel  (OpenSSL Client Library)
	- httpd-devel    (APXS)
	- gcc
