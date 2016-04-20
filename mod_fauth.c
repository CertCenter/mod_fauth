/*
**  mod_fauth.c
**
**  Copyright(c) 2016, CertCenter AG
**  https://www.certcenter.com
**  https://www.alwaysonssl.com
**
**  Permission is hereby granted, free of charge, to any person obtaining a copy
**  of this software and associated documentation files (the "Software"), to
**  deal in the Software without restriction, including without limitation the
**  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
**  sell copies of the Software, and to permit persons to whom the Software is
**  furnished to do so, subject to the following conditions:
**
**  The above copyright notice and this permission notice shall be included in
**  all copies or substantial portions of the Software.
**  
**  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
**  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
**  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
**  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
**  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
**  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
**  IN THE SOFTWARE.
*/


#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
#include <openssl/conf.h>
#endif
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>

// Get your DB_API_AUTH key from your Partner Success Manager.
#define DB_API_AUTH ""
#define DB_API_HOST "fauth-db.eu.certcenter.com"
#define DB_API_PORT "443"
#define DB_API_SERVER DB_API_HOST":"DB_API_PORT
#define SECURE_CIPHER_LIST "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"
#define DVAUTH_FILENAME_LENGTH 13
#define HASH_MAXLENGTH 32

const char* dbapi_lookup(const char *key) {
	long res = 1;
	SSL_CTX* ctx = NULL;
	BIO *web = NULL, *out = NULL;
	SSL *ssl = NULL;
	const SSL_METHOD* method;
	char *token, *tmpout, *buf;
	int hlen=0, len=0, maxlen=2048;
	(void)SSL_library_init();
	SSL_load_error_strings();
	OPENSSL_config(NULL);
	method = SSLv23_method(); if(method==NULL) return NULL;
	ctx = SSL_CTX_new(method); if(ctx==NULL) return NULL;
	SSL_CTX_set_verify_depth(ctx, 4);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_COMPRESSION);
	web = BIO_new_ssl_connect(ctx); if(web==NULL) return NULL;
	res = BIO_set_conn_hostname(web, DB_API_SERVER); if(res!=1) return NULL;
	BIO_get_ssl(web, &ssl); if(ssl==NULL) return NULL;
	res = SSL_set_cipher_list(ssl, SECURE_CIPHER_LIST); if(res!=1) return NULL;
	res = SSL_set_tlsext_host_name(ssl, DB_API_HOST); if(res!=1) return NULL;
	out = BIO_new_fp(stdout, BIO_NOCLOSE); if(NULL==out) return NULL;
	res = BIO_do_connect(web); if(res!=1) return NULL;
	res = BIO_do_handshake(web); if(res!=1) return NULL;
	len=(60+strlen(key)+strlen(DB_API_HOST)+strlen(DB_API_AUTH));
	char *request=malloc(sizeof(char)*(len+1));
	snprintf(request, len,
		"GET %s HTTP/1.1\nHost: %s\nx-api-key: %s\nConnection: close\n\n",
		key, DB_API_HOST, DB_API_AUTH);
	request[strlen(request)]=0;
	BIO_puts(web, request);
	BIO_puts(out, "\n");
	free(request);
	buf = (char*)malloc(sizeof(char)*(maxlen+1));
	do {
		char buff[1536] = {};
		len=BIO_read(web, buff, sizeof(buff));
		hlen+=len;
		if(hlen<maxlen&&len>0) strncat(buf,buff,len);
	} while (len>0 || BIO_should_retry(web));
	buf[strlen(buf)]=0;
	tmpout = (char*)malloc(sizeof(char)*(HASH_MAXLENGTH+1));
	token = strtok(buf, "\n");
	while (token) { snprintf(tmpout,HASH_MAXLENGTH,"%s",token); token = strtok(NULL, "\n");}
	tmpout[strlen(tmpout)]=0;
	free(buf);
	if(out) BIO_free(out);
	if(web != NULL) BIO_free_all(web);
	if(NULL != ctx) SSL_CTX_free(ctx);
	return tmpout;
}

static apr_status_t fauth_output_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {
	request_rec *r = f->r;
	conn_rec *c = r->connection;
	apr_bucket *pbktOut, *pbktIn;
	apr_bucket_brigade *pbbOut;
	int slu;
	char *uri, *buf, *hash;
	uri = strtok(r->the_request, " ");
	if(uri) uri = strtok(NULL, " ");
	if(!uri) return ap_pass_brigade(f->next,pbbIn);
	slu = strlen(uri);
	uri[slu]=0;
	if( !(r->status==HTTP_NOT_FOUND||r->status==HTTP_FORBIDDEN) ||
		r->method_number!=M_GET ||
		strlen(uri)!=DVAUTH_FILENAME_LENGTH ||
		(uri[slu-4]!='.' || uri[slu-3]!='h' || uri[slu-2]!='t' || uri[slu-1]!='m')
	) return ap_pass_brigade(f->next,pbbIn);
	hash=malloc(sizeof(char)*(HASH_MAXLENGTH+1));
	strncpy(hash,dbapi_lookup(uri),HASH_MAXLENGTH);
	hash[strlen(hash)]=0;
	if(strncmp(hash,"404 Not Found",13)==0||hash[0]=='{')
		return ap_pass_brigade(f->next,pbbIn);
	pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);
	for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
		pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
		pbktIn = APR_BUCKET_NEXT(pbktIn))
		APR_BUCKET_REMOVE(pbktIn);
	buf = apr_bucket_alloc(strlen(hash), c->bucket_alloc);
	strcpy(buf,hash);
	buf[strlen(buf)]=0;
	free(hash);
	pbktOut = apr_bucket_heap_create(buf, strlen(buf), apr_bucket_free, c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
	apr_brigade_cleanup(pbbIn);
	f->r->status=200;
	apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
	return ap_pass_brigade(f->next,pbbOut);
}

static void fauth_output_filter_hook(request_rec *r) {
	ap_add_output_filter("fauth_filter", NULL, r, r->connection);
}

static void fauth_register_hooks(apr_pool_t *p) {
	ap_hook_insert_filter(fauth_output_filter_hook, NULL, NULL, APR_HOOK_LAST);
	ap_hook_insert_error_filter(fauth_output_filter_hook, NULL, NULL, APR_HOOK_REALLY_LAST);
	ap_register_output_filter("fauth_filter", fauth_output_filter, NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA fauth_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	fauth_register_hooks
};
