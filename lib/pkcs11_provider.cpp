#include <QDebug>

#include "pkcs11.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

// Signature context for RSA operations
class sig_ctx
{
  public:
	pkcs11 *p11;
	CK_OBJECT_HANDLE obj;
	EVP_PKEY *pubkey;

	sig_ctx(pkcs11 *_p11, CK_OBJECT_HANDLE _obj, EVP_PKEY *_pubkey)
		: p11(_p11), obj(_obj), pubkey(_pubkey)
	{
		TRACE
		if (pubkey)
			EVP_PKEY_up_ref(pubkey);
	}

	~sig_ctx()
	{
		TRACE
		if (pubkey)
			EVP_PKEY_free(pubkey);
	}
};

static void *p11prov_rsasig_newctx(void *provctx, const char *properties)
{
	TRACE
	(void)properties;
	(void)provctx;
	// Context will be created when key is loaded
	return nullptr;
}

static void p11prov_rsasig_freectx(void *ctx)
{
	TRACE
	if (ctx)
		delete (sig_ctx *)ctx;
}

static int p11prov_rsasig_sign(void *ctx, unsigned char *sig, size_t *siglen,
								size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	TRACE
	sig_ctx *sctx = (sig_ctx *)ctx;
	if (!sctx || !sctx->p11)
		return 0;

	size_t key_size = EVP_PKEY_bits(sctx->pubkey) / 8;
	if (!sig) {
		// Caller wants to know signature size
		*siglen = key_size;
		return 1;
	}

	if (sigsize < key_size)
		return 0;

	// Use pkcs11::encrypt for signing
	int ret = sctx->p11->encrypt(tbslen, tbs, sig, sigsize, CKM_RSA_PKCS);
	if (ret < 0)
		return 0;

	*siglen = ret;
	return 1;
}

static int p11prov_rsasig_digest_sign_init(void *ctx, const char *mdname,
										   void *provkey, const OSSL_PARAM params[])
{
	TRACE
	(void)ctx;
	(void)mdname;
	(void)provkey;
	(void)params;
	// Not implementing digest operations yet
	return 0;
}

const OSSL_DISPATCH pkcs11_rsa_functions[] = {
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p11prov_rsasig_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))p11prov_rsasig_freectx },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))p11prov_rsasig_sign },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))p11prov_rsasig_digest_sign_init },
	{ 0, nullptr}
};

static const OSSL_ALGORITHM pkcs11_ciphers[] = {
	{ "RSA:rsaEncryption:1.2.840.113549.1.1.1", "",
	  pkcs11_rsa_functions, "Description" },
	{ NULL, NULL, NULL, NULL }
};

class provider_ctx
{
  public:
	const OSSL_CORE_HANDLE *core;
	const OSSL_DISPATCH *dispatch;
	pkcs11 *p11;
	CK_OBJECT_HANDLE obj;
	const OSSL_ALGORITHM *op_signature;

	provider_ctx(const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in)
		: core(core), dispatch(in), p11(nullptr), obj(CK_INVALID_HANDLE)
	{
		TRACE
		op_signature = pkcs11_ciphers;
	}

	~provider_ctx()
	{
		TRACE
	}

	void setKey(pkcs11 *_p11, CK_OBJECT_HANDLE _obj)
	{
		p11 = _p11;
		obj = _obj;
	}
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *pkcs11_prov_operation(void *ctx,
	int operation_id, int *no_cache)
{
	TRACE

	*no_cache = 0;
	switch (operation_id) {
		case OSSL_OP_SIGNATURE:
			return ((provider_ctx *)ctx)->op_signature;
	}
	return NULL;
}

/* The function that tears down this provider */
static void pkcs11_prov_teardown(void *ctx)
{
	TRACE
	delete (provider_ctx *)ctx;
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))pkcs11_prov_teardown },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pkcs11_prov_operation },
#if 0
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION_NAME, (void (*)(void))pkcs11_prov_op_name },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION_PROPERTIES,
	  (void (*)(void))pkcs11_prov_op_properties },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY, (void (*)(void))pkcs11_prov_property },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_NAME, (void (*)(void))pkcs11_prov_prop_name },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_DESCRIPTION,
	  (void (*)(void))pkcs11_prov_prop_description },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_TYPE,
	  (void (*)(void))pkcs11_prov_prop_value_type },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_CONSTRAINTS,
	  (void (*)(void))pkcs11_prov_prop_value_constraints },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_DESCRIPTIONS,
	  (void (*)(void))pkcs11_prov_prop_value_descriptions },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_CONSTRAINTS,
	  (void (*)(void))pkcs11_prov_prop_value_constraints },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_DESCRIPTIONS,
	  (void (*)(void))pkcs11_prov_prop_value_descriptions },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_CONSTRAINTS,
	  (void (*)(void))pkcs11_prov_prop_value_constraints },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_DESCRIPTIONS,
	  (void (*)(void))pkcs11_prov_prop_value_descriptions },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_CONSTRAINTS,
	  (void (*)(void))pkcs11_prov_prop_value_constraints },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_DESCRIPTIONS,
	  (void (*)(void))pkcs11_prov_prop_value_descriptions },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_CONSTRAINTS,
	  (void (*)(void))pkcs11_prov_prop_value_constraints },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_DESCRIPTIONS,
	  (void (*)(void))pkcs11_prov_prop_value_descriptions },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_CONSTRAINTS,
	  (void (*)(void))pkcs11_prov_prop_value_constraints },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_DESCRIPTIONS,
	  (void (*)(void))pkcs11_prov_prop_value_descriptions },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_CONSTRAINTS,
	  (void (*)(void))pkcs11_prov_prop_value_constraints },
	{ OSSL_FUNC_PROVIDER_QUERY_PROPERTY_VALUE_DESCRIPTIONS,
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
	  (void (*)(void))vigenere_prov_get_reason_strings },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS,
	  (void (*)(void))vigenere_prov_get_params },
	{ 0, NULL }
#endif

};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
	const OSSL_DISPATCH *in,
	const OSSL_DISPATCH **out,
	void **p11ctx)
{
	TRACE
	*p11ctx = new provider_ctx(core, in);
	*out = provider_functions;
	TRACE
	return 1;
}

// Helper function to create a signature context with pkcs11
extern "C" void *pkcs11_create_sig_ctx(void *provctx, pkcs11 *p11,
									   CK_OBJECT_HANDLE obj, EVP_PKEY *pubkey)
{
	TRACE
	(void)provctx;
	return new sig_ctx(p11, obj, pubkey);
}

# if 0
#if not defined OPENSSL_NO_EC and defined EVP_PKEY_ED25519
// Shared between libressl and openssl
static int eng_idx = -1;
static int eng_finish(ENGINE *e)
{
	pkcs11 *p11 = (pkcs11 *)ENGINE_get_ex_data(e, eng_idx);
	delete p11;
	ENGINE_set_ex_data(e, eng_idx, NULL);
	return 1;
}

static int eng_pmeth_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
	void *p = EVP_PKEY_CTX_get_app_data((EVP_PKEY_CTX *)src);
	EVP_PKEY_CTX_set_app_data(dst,  p);
	return 1;
}
#endif

static int rsa_privdata_free(RSA *rsa)
{
	pkcs11 *priv = (pkcs11*)RSA_get_app_data(rsa);
	delete priv;
	return 0;
}

static int rsa_encrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA * rsa, int padding)
{
	pkcs11 *priv = (pkcs11*)RSA_get_app_data(rsa);
	const BIGNUM *n = NULL;

	if (padding != RSA_PKCS1_PADDING) {
		return -1;
	}
	RSA_get0_key(rsa, &n, NULL, NULL);
	return priv->encrypt(flen, from, to, BN_num_bytes(n), CKM_RSA_PKCS);
}

static int rsa_decrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA * rsa, int padding)
{
	pkcs11 *priv = (pkcs11*)RSA_get_app_data(rsa);

	if (padding != RSA_PKCS1_PADDING) {
		return -1;
	}
	return priv->decrypt(flen, from, to, flen, CKM_RSA_PKCS);
}

static int dsa_privdata_free(DSA *dsa)
{
	pkcs11 *p11 = (pkcs11*)DSA_get_ex_data(dsa, 0);
	delete p11;
	return 0;
}

static DSA_SIG *dsa_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
	int len, rs_len;
	unsigned char rs_buf[128];
	pkcs11 *p11 = (pkcs11*)DSA_get_ex_data(dsa, 0);
	DSA_SIG *dsa_sig = DSA_SIG_new();
	BIGNUM *r, *s;

	// siglen is unsigned and can't cope with -1 as return value
	len = p11->encrypt(dlen, dgst, rs_buf, sizeof rs_buf, CKM_DSA);
	if (len & 0x01) // Must be even
		goto out;

	rs_len = len / 2;
	r = BN_bin2bn(rs_buf, rs_len, NULL);
	s = BN_bin2bn(rs_buf + rs_len, rs_len, NULL);
	DSA_SIG_set0(dsa_sig, r, s);
	if (r && s)
		return dsa_sig;
out:
	DSA_SIG_free(dsa_sig);
	ign_openssl_error();
	return NULL;
}

#ifndef OPENSSL_NO_EC

static void ec_privdata_free(EC_KEY *ec)
{
	pkcs11 *p11 = (pkcs11*)EC_KEY_get_ex_data(ec, 0);
	delete p11;
}

static int ec_sign_setup(EC_KEY *ec, BN_CTX *ctx, BIGNUM **kinvp, BIGNUM **rp)
{
	(void) ec;
	(void) ctx;
	(void) kinvp;
	(void) rp;
	return 1;
}

static ECDSA_SIG *ec_do_sign(const unsigned char *dgst, int dgst_len,
			 const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *ec)
{
	int len, rs_len;
	unsigned char rs_buf[512];
	ECDSA_SIG *ec_sig = ECDSA_SIG_new();
	pkcs11 *p11 = (pkcs11 *) EC_KEY_get_ex_data(ec, 0);
	BIGNUM *r, *s;

	(void) in_kinv;
	(void) in_r;

	// siglen is unsigned and can' cope with -1 as return value
	len = p11->encrypt(dgst_len, dgst, rs_buf, sizeof rs_buf, CKM_ECDSA);
	if (len & 0x01) // Must be even
		goto out;
	/* The buffer contains r and s concatenated
	 * Both of equal size
	 * pkcs-11v2-20.pdf chapter 12.13.1, page 232
	 */
	rs_len = len / 2;
	r = BN_bin2bn(rs_buf, rs_len, NULL);
	s = BN_bin2bn(rs_buf + rs_len, rs_len, NULL);
	ECDSA_SIG_set0(ec_sig, r, s);
	if (r && s)
		return ec_sig;

out:
	ECDSA_SIG_free(ec_sig);
	ign_openssl_error();
	return NULL;
}

static int ec_sign(int type, const unsigned char *dgst, int dlen,
			   unsigned char *sig, unsigned int *siglen,
			   const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec)
{
	ECDSA_SIG *ec_sig;
	int ret = 0;
	int len;

	(void) type;
	ec_sig = ec_do_sign(dgst, dlen, kinv, r, ec);
	if (!ec_sig)
		return 0;

	len = i2d_ECDSA_SIG(ec_sig, &sig);
	if (len <= 0)
		goto out;
	*siglen = len;
	ret = 1;
out:
	ECDSA_SIG_free(ec_sig);
	ign_openssl_error();
	return ret;
}

static EC_KEY_METHOD *setup_ec_key_meth()
{
	EC_KEY_METHOD *ec_key_meth;
	int (*ec_init_proc)(EC_KEY *key);
	void (*ec_finish_proc)(EC_KEY *key);
	int (*ec_copy_proc)(EC_KEY *dest, const EC_KEY *src);
	int (*ec_set_group_proc)(EC_KEY *key, const EC_GROUP *grp);
	int (*ec_set_private_proc)(EC_KEY *key, const BIGNUM *priv_key);
	int (*ec_set_public_proc)(EC_KEY *key, const EC_POINT *pub_key);

	ec_key_meth = EC_KEY_METHOD_new(EC_KEY_get_default_method());
	EC_KEY_METHOD_set_sign(ec_key_meth, ec_sign, ec_sign_setup, ec_do_sign);
	EC_KEY_METHOD_get_init(ec_key_meth, &ec_init_proc, &ec_finish_proc,
				&ec_copy_proc, &ec_set_group_proc,
				&ec_set_private_proc, &ec_set_public_proc);
	EC_KEY_METHOD_set_init(ec_key_meth, ec_init_proc, ec_privdata_free,
				ec_copy_proc, ec_set_group_proc,
				ec_set_private_proc, ec_set_public_proc);
	return ec_key_meth;
}
#ifdef EVP_PKEY_ED25519

static EVP_PKEY_METHOD *p11_eddsa_method;

static int eddsa_eng_meths(ENGINE *e, EVP_PKEY_METHOD **m, const int **nids, int nid)
{
	static const int my_nids[] = {EVP_PKEY_ED25519 };
	(void)e;
	if (m) {
		switch (nid) {
		case EVP_PKEY_ED25519:
			*m = p11_eddsa_method;
			return 1;
		return 0;
		}
	}
	if (nids) {
		*nids = my_nids;
		return ARRAY_SIZE(my_nids);
	}
	return -1;

}

static int eng_pmeth_sign_eddsa(EVP_MD_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen)
{
	int len, ret = -1;
	unsigned char rs_buf[64];
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx));
	pkcs11 *p11 = (pkcs11 *)ENGINE_get_ex_data(EVP_PKEY_get0_engine(pkey), eng_idx);
	*siglen = EVP_PKEY_size(pkey);
	if (sig == NULL) {
		// caller needs only size
		ret = 1;
		goto out;
	}

	// siglen is unsigned and can' cope with -1 as return value
	len = p11->encrypt(tbslen, tbs, rs_buf, sizeof rs_buf, CKM_EDDSA);
	if ((len & 0x01) || (*siglen != (size_t)len)) // Must be even
		goto out;
	memcpy(sig, rs_buf, len);
	*siglen = len;
	ret = 1;
 out:
	ign_openssl_error();
	return ret;
}

static int eng_pmeth_ctrl_eddsa(EVP_PKEY_CTX *, int type, int p1, void *p2)
{
	(void)p1;
	switch (type) {
	case EVP_PKEY_CTRL_MD:
		if (p2 == NULL || (const EVP_MD *)p2 == EVP_md_null())
			return 1;
		ECerr(EC_F_PKEY_ECD_CTRL, EC_R_INVALID_DIGEST_TYPE);
		return 0;
	}
	qWarning() << "EC Don't call me" << type;
	return -2;
}
#endif
#endif

EVP_PKEY *pkcs11::getPrivateKey(EVP_PKEY *pub, CK_OBJECT_HANDLE obj)
{
	static RSA_METHOD *rsa_meth = NULL;
	static DSA_METHOD *dsa_meth = NULL;
#ifndef OPENSSL_NO_EC
	static EC_KEY_METHOD *ec_key_meth = NULL;
	EC_KEY *ec;
#ifdef EVP_PKEY_ED25519
	static ENGINE *e = NULL;

	if (!e) {
		e = ENGINE_new();
		Q_CHECK_PTR(e);

		ENGINE_set_pkey_meths(e, eddsa_eng_meths);
		ENGINE_set_finish_function(e, eng_finish);
		if (eng_idx == -1)
			eng_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
		ENGINE_set_ex_data(e, eng_idx, NULL);
		// Why is engine attached to pubkey? I'm commenting it, as I do
		// not want it to be attached to RSA/DSA/EC
		//CRYPTO_add(&pub->references, 1, CRYPTO_LOCK_EVP_PKEY);
		//pub->engine = e;

		if (!p11_eddsa_method) {
			p11_eddsa_method = EVP_PKEY_meth_new(EVP_PKEY_ED25519,
					EVP_PKEY_FLAG_SIGCTX_CUSTOM);
			EVP_PKEY_meth_set_digestsign(p11_eddsa_method,
					eng_pmeth_sign_eddsa);
			EVP_PKEY_meth_set_ctrl(p11_eddsa_method,
					eng_pmeth_ctrl_eddsa, NULL);
			EVP_PKEY_meth_set_copy(p11_eddsa_method, eng_pmeth_copy);
		}
	}
#endif
#endif
	RSA *rsa;
	DSA *dsa;
	EVP_PKEY *evp = NULL;
	int keytype;

	p11slot.isValid();

	keytype = EVP_PKEY_id(pub);

	switch (EVP_PKEY_type(keytype)) {
	case EVP_PKEY_RSA:
		rsa = RSAPublicKey_dup(EVP_PKEY_get0_RSA(pub));
		openssl_error();
		if (!rsa_meth) {
			rsa_meth = RSA_meth_dup(RSA_get_default_method());
			RSA_meth_set_priv_enc(rsa_meth, rsa_encrypt);
			RSA_meth_set_priv_dec(rsa_meth, rsa_decrypt);
			RSA_meth_set_finish(rsa_meth, rsa_privdata_free);
		}
		p11obj = obj;
		RSA_set_method(rsa, rsa_meth);
		RSA_set_app_data(rsa, this);
		evp = EVP_PKEY_new();
		openssl_error();
		EVP_PKEY_assign_RSA(evp, rsa);
		break;
	case EVP_PKEY_DSA:
		dsa = DSAparams_dup(EVP_PKEY_get0_DSA(pub));
		openssl_error();
		if (!dsa_meth) {
			dsa_meth = DSA_meth_dup(DSA_get_default_method());
			DSA_meth_set_sign(dsa_meth, dsa_sign);
			DSA_meth_set_finish(dsa_meth, dsa_privdata_free);
		}
		p11obj = obj;
		DSA_set_method(dsa, dsa_meth);
		DSA_set_ex_data(dsa, 0, this);
		evp = EVP_PKEY_new();
		openssl_error();
		EVP_PKEY_assign_DSA(evp, dsa);
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		ec = EC_KEY_dup(EVP_PKEY_get0_EC_KEY(pub));
		openssl_error();
		if (!ec_key_meth) {
			ec_key_meth = setup_ec_key_meth();
		}
		p11obj = obj;
		EC_KEY_set_method(ec, ec_key_meth);
		EC_KEY_set_ex_data(ec, 0, this);
		evp = EVP_PKEY_new();
		openssl_error();
		EVP_PKEY_assign_EC_KEY(evp, ec);
		break;
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519:
		size_t len;
		if (ENGINE_get_ex_data(e, eng_idx))
			qWarning() << "We forgot to free the previous Card key.";
		ENGINE_set_ex_data(e, eng_idx, this);
		p11obj = obj;
		EVP_PKEY_get_raw_public_key(pub, NULL, &len);
		unsigned char *pubkey = (unsigned char *)OPENSSL_malloc(len);
		Q_CHECK_PTR(pubkey);
		EVP_PKEY_get_raw_public_key(pub, pubkey, &len);
		evp = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, e, pubkey, len);
		openssl_error();
		OPENSSL_free(pubkey);
		//EVP_PKEY_set1_engine(evp, e);
		break;
#endif
#endif
	}
	return evp;
}
#endif
