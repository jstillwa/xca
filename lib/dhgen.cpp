/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "func.h"
#include "dhgen.h"
#include "entropy.h"
#include "xfile.h"
#include "BioByteArray.h"

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

void DHgen::run()
{
	BioByteArray bio;

	try {
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
		Q_CHECK_PTR(ctx);

		EVP_PKEY_paramgen_init(ctx);
		EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, bits);
		EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, 2);

		EVP_PKEY *param_key = nullptr;
		EVP_PKEY_generate(ctx, &param_key);
		EVP_PKEY_CTX_free(ctx);
		openssl_error();
		PEM_write_bio_Parameters(bio, param_key);
		EVP_PKEY_free(param_key);
		openssl_error();
	} catch (errorEx &e) {
		err = e;
		return;
	}
	XFile file(fname);
	file.open_write();
	file.write(bio);
}
