# Memfault/mbedtls

Fork of [ARMmbed/mbedtls](https://github.com/ARMmbed/mbedtls) for sharing
Memfault mbedtls examples.

## Examples

### `ssl_client1.c`

Simple example showing how to post a single chunk to chunks.memfault.com.

See the source here for the implementation:

[programs/ssl/ssl_client1.c](programs/ssl/ssl_client1.c)

To run the example, you'll need Make and a C compiler. On Ubuntu linux you might
install this package:

```bash
❯ sudo apt install build-essential
```

To compile and run the example program, run these commands from the root of the repository
(be sure to update submodules first!):

```bash
# build the test program
❯ make -C programs/ ssl/ssl_client1

# run the example. be sure to set your project key below!
❯ MEMFAULT_HTTPTEST_API_KEY=$MEMFAULT_PROJECT_KEY programs/ssl/ssl_client1
```

If it succeeds, you should see output like the following:

```plaintext
  < Read from server: 168 bytes read

HTTP/1.1 202 Accepted
Date: Thu, 10 Mar 2022 16:38:01 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 8
Connection: keep-alive
Vary: Origin

Accepted
```

To see the result, go to the project in app.memfault.com and check for an event
received for `TESTSERIAL` (look under Events Debug/Chunks Debug).
