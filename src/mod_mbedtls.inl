#if defined(USE_MBEDTLS)  // USE_MBEDTLS used with NO_SSL

#include <string.h>
#include "mbedtls/certs.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"

typedef mbedtls_ssl_context SSL;

typedef struct {
    mbedtls_ssl_config conf; /* SSL configuration */
    mbedtls_x509_crt cert; /* Certificate */
    mbedtls_ctr_drbg_context ctr; /* Counter random generator state */
    mbedtls_entropy_context entropy; /* Entropy context */
    mbedtls_pk_context pkey; /* Private key */
} SSL_CTX;

// public api
int mbed_sslctx_init(SSL_CTX *ctx, const char *crt);
void mbed_sslctx_uninit(SSL_CTX *ctx);
void mbed_ssl_close(mbedtls_ssl_context *ssl);
int mbed_ssl_accept(mbedtls_ssl_context **ssl, SSL_CTX *ssl_ctx, int *sock);
int mbed_ssl_read(mbedtls_ssl_context *ssl, unsigned char *buf, int len);
int mbed_ssl_write(mbedtls_ssl_context *ssl, const unsigned char *buf, int len);

static void mbed_debug(void *context, int level, const char *file, int line, const char *str);
static int mbed_ssl_handshake(mbedtls_ssl_context *ssl);

#if defined(__ZEPHYR__)
#include <drivers/entropy.h>

static const struct device *entropy_driver;
static const unsigned char drbg_seed[] = "civetweb+mbedtls";
static int ctr_drbg_entropy_func(void *ctx, unsigned char *buf, size_t len)
{
    return entropy_get_entropy(entropy_driver, (void *)buf, len);
}

extern const unsigned char server_key_der[];
extern const int sizeof_server_key_der;
extern const unsigned char server_cert_der[];
extern const int sizeof_server_cert_der;
#endif


int
mbed_sslctx_init(SSL_CTX *ctx, const char *crt)
{
    mbedtls_ssl_config *conf;
    int rc;

    if (ctx == NULL) {
        fprintf(stderr, "No ssl context provided\n");
        return -1;
    }

#if !defined(__ZEPHYR__)
    if  (crt == NULL) {
        fprintf(stderr, "No certificate provided\n");
        return -1;
    }
#endif

    fprintf(stdout, "Initializing MbedTLS SSL\n");

    mbedtls_ctr_drbg_init(&ctx->ctr);

    conf = &ctx->conf;

    //TODO: sockets_tls.c ma tohle vsechno pro kazde spojeni
    mbedtls_x509_crt_init(&ctx->cert);
    mbedtls_ssl_config_init(conf);
    mbedtls_pk_init(&ctx->pkey);

    // set debug level
#if defined(CONFIG_MBEDTLS_DEBUG)
    mbedtls_debug_set_threshold(2);
    mbedtls_ssl_conf_dbg(conf, mbed_debug, stdout);
#endif


#if !defined(__ZEPHYR__)
    mbedtls_entropy_init(&ctx->entropy);
    if ((rc = mbedtls_ctr_drbg_seed(&ctx->ctr,
                                    mbedtls_entropy_func,
                                    &ctx->entropy,
                                    (unsigned char *)"CivetWeb",
                                    strlen("CivetWeb")))
        != 0) {
        fprintf(stderr, "Cannot seed rng\n");
        return -1;
    }
#else
    entropy_driver = device_get_binding(DT_CHOSEN_ZEPHYR_ENTROPY_LABEL);
    if (!entropy_driver) {
	    fprintf(stdout, "No entropy driver.\n");
	    mbedtls_ctr_drbg_free(&ctx->ctr);
	    return -1;
    }

    if ((rc = mbedtls_ctr_drbg_seed(&ctx->ctr,
                                    ctr_drbg_entropy_func,
                                    NULL,
                                    drbg_seed,
                                    sizeof(drbg_seed)))
        != 0) {
        fprintf(stdout, "Cannot seed rng\n");
        mbedtls_ctr_drbg_free(&ctx->ctr);
        return -1;
    }
#endif
#if !defined(__ZEPHYR__)
    if (mbedtls_pk_parse_keyfile(&ctx->pkey, crt, NULL) != 0) {
        fprintf(stderr, "parse key file failed\n");
        return -1;
    }

    if (mbedtls_x509_crt_parse_file(&ctx->cert, crt) != 0) {
        fprintf(stderr, "parse crt file faied\n");
        return -1;
    }
#else
    if (mbedtls_pk_parse_key(&ctx->pkey, server_key_der, sizeof_server_key_der, NULL, 0) != 0) {
        fprintf(stdout, "parse key failed\n");
        mbedtls_ctr_drbg_free(&ctx->ctr);
        return -1;
    }

    if (mbedtls_x509_crt_parse(&ctx->cert, server_cert_der, sizeof_server_cert_der) != 0) {
        fprintf(stdout, "parse crt file faied\n");
        mbedtls_ctr_drbg_free(&ctx->ctr);
        return -1;
    }
#endif

    if ((rc = mbedtls_ssl_config_defaults(conf,
                                            MBEDTLS_SSL_IS_SERVER,
                                            MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT))
        != 0) {
        fprintf(stderr, "Cannot set mbedtls defaults\n");
        return -1;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &ctx->ctr);

    // Set auth mode if peer cert should be verified
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(conf, NULL, NULL);

    // Configure server cert and key
    if ((rc = mbedtls_ssl_conf_own_cert(conf, &ctx->cert, &ctx->pkey))
        != 0) {
        fprintf(stderr, "Cannot define certificate and private key\n");
        mbedtls_ctr_drbg_free(&ctx->ctr);
        return -1;
    }
    return 0;
}

void 
mbed_sslctx_uninit(SSL_CTX *ctx)
{
    mbedtls_ctr_drbg_free(&ctx->ctr);
    mbedtls_pk_free(&ctx->pkey);
    mbedtls_x509_crt_free(&ctx->cert);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ssl_config_free(&ctx->conf);
}

int
mbed_ssl_accept(mbedtls_ssl_context **ssl, SSL_CTX *ssl_ctx, int *sock)
{
    *ssl = calloc(1, sizeof(**ssl));
    if (*ssl == NULL) {
        fprintf(stderr, "malloc ssl failed\n");
        return -1;
    }

    mbedtls_ssl_init(*ssl);
    mbedtls_ssl_setup(*ssl, &ssl_ctx->conf);
	mbedtls_ssl_set_bio(*ssl, sock, mbedtls_net_send, mbedtls_net_recv, NULL);
    if (mbed_ssl_handshake(*ssl) != 0) {
        fprintf(stderr, "handshake failed\n");
        return -1;
    }

	fprintf(stdout, "mbedtls mbed_ssl_accept state:%d\n", (*ssl)->state);

	return 0;
}

void
mbed_ssl_close(mbedtls_ssl_context *ssl)
{
	fprintf(stdout, "mbedtls close\n");
    mbedtls_ssl_close_notify(ssl);
    mbedtls_ssl_free(ssl);
    ssl = NULL;
}

static int
mbed_ssl_handshake(mbedtls_ssl_context *ssl)
{
    int rc;
    while ((rc = mbedtls_ssl_handshake(ssl)) != 0) {
		if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE && rc != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS)  {
            break;
        }
    }

    fprintf(stdout, "mbedtls handshake rc:%d state:%d\n", rc, ssl->state);
    return rc;
}

int
mbed_ssl_read(mbedtls_ssl_context *ssl, unsigned char *buf, int len)
{
    int rc = mbedtls_ssl_read(ssl, buf, len);
    //fprintf(stdout, "mbedtls: mbedtls_ssl_read %d\n", rc);
    return rc;
}

int
mbed_ssl_write(mbedtls_ssl_context *ssl, const unsigned char *buf, int len)
{
    int rc = mbedtls_ssl_write(ssl, buf, len);
    //fprintf(stdout, "mbedtls: mbedtls_ssl_write:%d\n", rc);
    return rc;
}

static void
mbed_debug(void *context, int level, const char *file, int line, const char *str)
{
    (void)level;
    mbedtls_fprintf((FILE *)context, "file:%s line:%d str:%s", file, line, str);
}

#if !defined(MBEDTLS_NET_C) && defined(__ZEPHYR__)
/* copy from net_sockets.c, original file do not work in zephyr */
static int net_would_block( const mbedtls_net_context *ctx )
{
    int err = errno;

    /*
     * Never return 'WOULD BLOCK' on a blocking socket
     */
    if( ( fcntl( ctx->fd, F_GETFL, 0 ) & O_NONBLOCK) != O_NONBLOCK )
    {
        errno = err;
        return( 0 );
    }

    switch( errno = err )
    {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return( 1 );
    }
    return( 0 );
}

int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
{
    int ret;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );

    ret = (int) read( fd, buf, len );

    if( ret < 0 )
    {
        if( net_would_block( ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_READ );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_READ );
#endif

        return( MBEDTLS_ERR_NET_RECV_FAILED );
    }

    return( ret );
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
    int ret;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );

    ret = (int) write( fd, buf, len );

    if( ret < 0 )
    {
        if( net_would_block( ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_WRITE );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_WRITE );
#endif

        return( MBEDTLS_ERR_NET_SEND_FAILED );
    }

    return( ret );
}
#endif

#endif /* USE_MBEDTLS */
