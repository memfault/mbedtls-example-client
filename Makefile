# disable printing rule execution by default. run with --trace to see it.
.SILENT:

# make sure the grouped-targets feature is available
ifneq ($(filter grouped-target,$(.FEATURES)),grouped-target)
$(error "This version of Make doesn't support grouped-targets, please update!")
endif

all: ssl_client

MBEDTLS_DIR = third_party/mbedtls
MBEDTLS_LIBS := \
   libmbedtls.a \
   libmbedx509.a \
   libmbedcrypto.a \

MBEDTLS_LIBS := $(addprefix $(MBEDTLS_DIR)/library/, $(MBEDTLS_LIBS))

$(MBEDTLS_LIBS) &:
	@echo "Building $(MBEDTLS_LIBS) ..."
	DEBUG=1 $(MAKE) -C $(MBEDTLS_DIR) lib

CFLAGS += \
    -ggdb3 \

CFLAGS += \
    -I$(MBEDTLS_DIR)/include \
    -I$(MBEDTLS_DIR)/tests/include \

ssl_client: ssl_client.c $(MBEDTLS_LIBS)
	@echo "Building ssl_client ..."
	$(CC) $(CFLAGS) -o ssl_client $^