CC ?= cc
CFLAGS = -Wall -O2

all: test-openssl-aes-siv

%: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lcrypto -o $@ $<

clean:
	rm -f test-openssl-aes-siv
