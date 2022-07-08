/*
 *  SSL client demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

//! Memfault note:
//!
//! This is a slight modification of the original file, which can be found here:
//! https://github.com/ARMmbed/mbedtls/blob/81d903f5aa9032d23cf02d52b701e76abc6c3ffe/programs/ssl/ssl_client1.c
//!
//! The changes can be seen by running this command:
//!
//! ❯ diff -duw third_party/mbedtls/programs/ssl/ssl_client1.c ssl_client.c
//!
//! The changes are:
//! 1. install the Memfault root cert instead of the mbedtls test certs
//! 2. instead of a GET request, format and send a POST request with a canned
//!    Memfault chunk payload
//! 3. terminate the connection once an HTTP response is received

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
// #include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||     \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) ||    \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) ||            \
    !defined(MBEDTLS_PEM_PARSE_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_X509_CRT_PARSE_C)
#error "MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or MBEDTLS_PEM_PARSE_C and/or MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C not defined.\n"
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include <string.h>

#define SERVER_PORT "443"
#define SERVER_NAME "chunks.memfault.com"

// format string for building the HTTP header
#define POST_REQUEST \
    "POST /api/v0/chunks/TESTSERIAL HTTP/1.1\r\n" \
    "Host:chunks.memfault.com\r\n" \
    "User-Agent: MemfaultSDK/0.4.2\r\n" \
    "Memfault-Project-Key:%s\r\n" \
    "Content-Type:application/octet-stream\r\n" \
    "Content-Length:%zu\r\n\r\n" \

// set the memfault PEM cert in this variable
#include "third_party/memfault-firmware-sdk/components/include/memfault/http/root_certs.h"
const char memfault_cert[] = MEMFAULT_ROOT_CERTS_DIGICERT_GLOBAL_ROOT_CA;

#if !defined(DEBUG_LEVEL)
#define DEBUG_LEVEL 1
#endif

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int main( void )
{
    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    // default cert from mbedtls example
    // #include "test/certs.h"
    //
    // ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
    //                       mbedtls_test_cas_pem_len );

    /*
    // The amazon cert for httpbin.org
    const char amazon_pem[] = \
        "-----BEGIN CERTIFICATE-----\r\n" \
        "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\r\n" \
        "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\r\n" \
        "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\r\n" \
        "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\r\n" \
        "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\r\n" \
        "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\r\n" \
        "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\r\n" \
        "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\r\n" \
        "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\r\n" \
        "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\r\n" \
        "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\r\n" \
        "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\r\n" \
        "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\r\n" \
        "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\r\n" \
        "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\r\n" \
        "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\r\n" \
        "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\r\n" \
        "rqXRfboQnoZsG4q5WTP468SQvvG5\r\n" \
        "-----END CERTIFICATE-----\r\n" \
        ;
    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) amazon_pem,
                          sizeof(amazon_pem) );
                          */

    // Memfault cert
    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) memfault_cert,
                          sizeof(memfault_cert) );

    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -ret );
        goto exit;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    mbedtls_printf( "  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT );
    fflush( stdout );

    if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    ret = mbedtls_net_set_nonblock( &server_fd );
    if (ret != 0) {
        mbedtls_printf("Failed to set socket to non-blocking\n");
        goto exit;
    }

    /*
     * 2. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_REQUIRED );
    // mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );

    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        char vrfy_buf[512];
#endif

        mbedtls_printf( " failed\n" );

#if !defined(MBEDTLS_X509_REMOVE_INFO)
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
#endif
    }
    else
        mbedtls_printf( " ok\n" );

    /*
     * 3. Write the POST request
     */
      const char *apikey = getenv("MEMFAULT_HTTPTEST_API_KEY");
  if (!apikey) {
      ret = 1;
    mbedtls_printf("ERROR: set MEMFAULT_HTTPTEST_API_KEY\n\n");
    goto exit;
  }

    // example chunk data
  const unsigned char chunk[] = {
    0x08, 0x02, 0xa7, 0x02, 0x01, 0x03, 0x01, 0x07, 0x6a, 0x54, 0x45, 0x53, 0x54, 0x53, 0x45,
    0x52, 0x49, 0x41, 0x4c, 0x0a, 0x6d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x73, 0x6f, 0x66, 0x74,
    0x77, 0x61, 0x72, 0x65, 0x09, 0x6a, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x2d, 0x74, 0x65, 0x73,
    0x74, 0x06, 0x6d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x68, 0x61, 0x72, 0x64, 0x77, 0x61, 0x72,
    0x65, 0x04, 0xa1, 0x01, 0xa1, 0x72, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x5f, 0x74, 0x65, 0x73,
    0x74, 0x5f, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x01, 0x31, 0xe4};

    // format the request
    unsigned char sendbuf[2048];
    len = sprintf( (char *)sendbuf, POST_REQUEST, apikey, sizeof(chunk) );

    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );

    mbedtls_printf("\nHeader: \n%s", sendbuf);

    // send the header
    while( ( ret = mbedtls_ssl_write( &ssl, sendbuf, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( "\n failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf( "\n %d header bytes written\n\n%s", len, (char *) buf );

    // send the payload
    while( ( ret = mbedtls_ssl_write( &ssl, chunk, sizeof(chunk) ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf( " %d payload bytes written\n\n%s", len, (char *) buf );

    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf( "  < Read from server:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;

        if( ret < 0 )
        {
            mbedtls_printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
            break;
        }

        if( ret == 0 )
        {
            mbedtls_printf( "\n\nEOF\n\n" );
            break;
        }

        len = ret;
        mbedtls_printf( " %d bytes read\n\n%s\n\n", len, (char *) buf );

        // the connection doesn't hang up until 30 seconds after the HTTP
        // request completes, so check for an HTTP response code
        if (strstr(buf, "HTTP/1.1 ")) {
            mbedtls_printf("  . Response received, exiting\n");
            break;
        }
    }
    while( 1 );

    mbedtls_ssl_close_notify( &ssl );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &server_fd );

    mbedtls_x509_crt_free( &cacert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_exit( exit_code );
}
