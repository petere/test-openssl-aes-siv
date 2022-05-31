#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/evp.h>

unsigned char key[] = {
	0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

unsigned char ad[] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
};

unsigned char ciphertext[] = {
	0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c,
};

static void
test1(void)
{
	EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
	if (!cipher)
	{
		fprintf(stderr, "EVP_CIPHER_fetch: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		exit(1);
	}

	EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();

	if (!EVP_DecryptInit_ex(evp_cipher_ctx, cipher, NULL, NULL, NULL))
	{
		fprintf(stderr, "EVP_DecryptInit_ex: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		exit(1);
	}

	/* key */
	if (!EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL, key, NULL))
	{
		fprintf(stderr, "EVP_DecryptInit_ex#2: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		exit(1);
	}

	int decrlen;

	/* AD */
	if (!EVP_DecryptUpdate(evp_cipher_ctx, NULL, &decrlen, ad, sizeof(ad)))
	{
		fprintf(stderr, "EVP_DecryptUpdate[AD]: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		exit(1);
	}

	unsigned char outbuf[1024];
	if (!EVP_DecryptUpdate(evp_cipher_ctx, outbuf, &decrlen, ciphertext, sizeof(ciphertext)))
	{
		fprintf(stderr, "EVP_DecryptUpdate: %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
		exit(1);
	}

	int decrlen2;
	if (!EVP_DecryptFinal_ex(evp_cipher_ctx, outbuf + decrlen, &decrlen2))
	{
		fprintf(stderr, "EVP_DecryptFinal_ex: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		exit(1);
	}
	decrlen += decrlen2;

	printf("plaintext = ");
	for (int i = 0; i < decrlen; i++)
		printf("0x%02x", outbuf[i]);
	printf("\n");
}

int
main(void)
{
	test1();

	return 0;
}
