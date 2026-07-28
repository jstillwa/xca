/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QJsonDocument>

#include "pki_evp.h"
#include "pass_info.h"
#include "func.h"
#include "entropy.h"
#include "BioByteArray.h"
#include "XcaProgress.h"

#include "PwDialogCore.h"
#include "XcaWarningCore.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>

Passwd pki_evp::passwd;

QString pki_evp::passHash = QString();

void pki_evp::init()
{
	ownPass = ptCommon;
	pkiType = asym_key;
}

void pki_evp::setOwnPass(enum passType x)
{
	EVP_PKEY *pk=NULL, *pk_back = key;
	enum passType oldOwnPass = ownPass;

	if (ownPass == x || isPubKey())
		return;

	try {
		pk = decryptKey();
		if (pk == NULL)
			return;

		key = pk;
		ownPass = x;
		encryptKey();
	}
	catch (errorEx &err) {
		if (pk)
			EVP_PKEY_free(pk);
		key = pk_back;
		ownPass = oldOwnPass;
		throw(err);
	}
}

bool pki_evp::sqlUpdatePrivateKey()
{
	if (encKey.size() <= 0)
		return false;
	Transaction;
	if (!TransBegin())
		return false;
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE private_keys SET private=?, ownPass=? "
		"WHERE item=?");
	q.bindValue(0, encKey_b64());
	q.bindValue(1, ownPass);
	q.bindValue(2, sqlItemId);
	AffectedItems(sqlItemId);
	q.exec();

	encKey.fill(0);
	encKey.clear();

	if (!q.lastError().isValid() && q.numRowsAffected() == 1) {
		TransCommit();
		return true;
	}
	return false;
}

void pki_evp::generate(const keyjob &task)
{
	Entropy::seed_rng();
	XcaProgress progress;

	EVP_PKEY *param_key = nullptr;

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(task.ktype.type, NULL);
	Q_CHECK_PTR(ctx);
	EVP_PKEY_CTX_set_app_data(ctx, &progress);

	switch (task.ktype.type) {
	case EVP_PKEY_RSA:
		EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, task.size);
		break;
	case EVP_PKEY_DSA:
		EVP_PKEY_paramgen_init(ctx);
		EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, task.size);
		EVP_PKEY_generate(ctx, &param_key);

		EVP_PKEY_CTX_free(ctx);
		ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		EVP_PKEY_paramgen_init(ctx);
		EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, task.ec_nid);
		EVP_PKEY_generate(ctx, &param_key);
		EVP_PKEY_CTX_free(ctx);
		ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
		break;
	case EVP_PKEY_ED25519:
		// ED25519 and ED448 need no extra treatment
		break;
	default:
		throw errorEx(tr("Unknown Keytype %1").arg(task.ktype.type));
#endif
	}
	EVP_PKEY *pkey = nullptr;
	EVP_PKEY_keygen_init(ctx);
	EVP_PKEY_keygen(ctx, &pkey);
	EVP_PKEY_CTX_free(ctx);
	isPub = false;
	pkiSource = generated;
	if (param_key)
		EVP_PKEY_free(param_key);
	if (key)
		EVP_PKEY_free(key);
	key = pkey;
	pki_openssl_error();
	encryptKey();
}

pki_evp::pki_evp(const pki_evp *pk)
	:pki_key(pk)
{
	init();
	pki_openssl_error();
	ownPass = pk->ownPass;
	isPub = pk->isPub;
	encKey = pk->getEncKey();
}

pki_evp::pki_evp(const QString &n, int type)
	:pki_key(n)
{
	init();
	EVP_PKEY_set_type(key, type);
	pki_openssl_error();
}

static bool EVP_PKEY_isPrivKey(EVP_PKEY *key)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	Q_CHECK_PTR(ctx);
	bool priv = EVP_PKEY_private_check(ctx) > 0;
	EVP_PKEY_CTX_free(ctx);
	ign_openssl_error();
	return priv;
}

pki_evp::pki_evp(EVP_PKEY *pkey)
	:pki_key()
{
	init();
	set_EVP_PKEY(pkey);
}

bool pki_evp::openssl_pw_error() const
{
	unsigned long e = ERR_peek_error();

	switch (ERR_PACK(ERR_GET_LIB(e), 0, ERR_GET_REASON(e))) {
	case ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_PASSWORD_READ):
	case ERR_PACK(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_PROV, 0, PROV_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_PKCS12, 0, PKCS12_R_PKCS12_CIPHERFINAL_ERROR):
		pki_ign_openssl_error();
		return true;
	}
	return false;
}

void pki_evp::fromPEMbyteArray(const QByteArray &ba, const QString &name)
{
	EVP_PKEY *pkey;
	pass_info p(XCA_TITLE,
		tr("Please enter the password to decrypt the private key %1.")
			.arg(name));
	pkey = load_ssh_ed25519_privatekey(ba, p);
	pki_ign_openssl_error();

	while (!pkey) {
		pkey = PEM_read_bio_PrivateKey(BioByteArray(ba).ro(), NULL,
						PwDialogCore::pwCallback, &p);
		if (p.getResult() != pw_ok)
			throw p.getResult();
		if (openssl_pw_error())
			XCA_PASSWD_ERROR();
		if (pki_ign_openssl_error())
			break;
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = PEM_read_bio_PUBKEY(BioByteArray(ba).ro(), NULL, NULL,0);
	}
	pki_openssl_error();
	set_EVP_PKEY(pkey, name);
}

void pki_evp::set_EVP_PKEY(EVP_PKEY *pkey, QString name)
{
	if (!pkey)
		return;
	if (!verify(pkey)) {
		pki_ign_openssl_error();
		EVP_PKEY_free(pkey);
		throw errorEx(tr("The key from file '%1' is incomplete or inconsistent.").arg(name));
	}
	if (key)
		EVP_PKEY_free(key);
	key = pkey;
	isPub = !EVP_PKEY_isPrivKey(key);
	if (!isPub)
		bogusEncryptKey();

	autoIntName(name);
	setFilename(name);
	pki_openssl_error();
}

EVP_PKEY *pki_evp::load_ssh_ed25519_privatekey(const QByteArray &ba,
						const pass_info &p)
{
	EVP_PKEY *pkey = NULL;
	unsigned char *pdata;
	long plen;
	QByteArray chunk, enc_algo, kdfname, kdf, pub, priv;

	(void)p; // Will be used later for decryption
	if (!PEM_bytes_read_bio(&pdata, &plen, NULL, PEM_STRING_OPENSSH_KEY,
				BioByteArray(ba).ro(), NULL, NULL))
		return NULL;

	QByteArray content((const char*)pdata, plen);
	OPENSSL_free(pdata);

	if (!content.startsWith("openssh-key-v1") ||
	     // also check trailing \0
	     content.constData()[sizeof "openssh-key-v1" -1])
		return NULL;

	content.remove(0, sizeof "openssh-key-v1");
	// encryption: "none", "aes256-ctr"
	enc_algo = ssh_key_next_chunk(&content);
	// KDFName "bcrypt"
	kdfname = ssh_key_next_chunk(&content);
	kdf = ssh_key_next_chunk(&content);

	if (enc_algo != "none" || kdfname != "none") {
		throw(errorEx(tr("Encrypted SSH ED25519 keys not supported, yet")));
	}
	// check bytes 00 00 00 01
	const char *d = content.constData();
	if (d[0] || d[1] || d[2] || d[3] != 1)
		return NULL;
	content.remove(0, 4);
	// Handle first occurrence of the public key
	pub = ssh_key_next_chunk(&content);
	ssh_key_check_chunk(&pub, "ssh-ed25519");
	pub = ssh_key_next_chunk(&pub);
	if (pub.size() != ED25519_KEYLEN)
		return NULL;

	// Followed by the private key
	priv = ssh_key_next_chunk(&content);
	// Drop 64bit random nonce
	priv.remove(0, 8);

	ssh_key_check_chunk(&priv, "ssh-ed25519");
	// The first pubkey must match the second occurrence
	// in front of the private one
	if (pub != ssh_key_next_chunk(&priv))
		return NULL;
	priv = ssh_key_next_chunk(&priv);
	// The private key is concatenated by the public key in one chunk
	if (priv.size() != 2 * ED25519_KEYLEN)
		return NULL;
	// The last ED25519_KEYLEN bytes must match the public key
	if (pub != priv.mid(ED25519_KEYLEN))
		return NULL;
	// The first ED25519_KEYLEN octets are the private key
#ifndef OPENSSL_NO_EC
#ifdef EVP_PKEY_ED25519
	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
		(const unsigned char *)priv.constData(), ED25519_KEYLEN);
#endif
#endif
	pki_openssl_error();
	return pkey;
}

void pki_evp::fload(const QString &fname)
{
	pass_info p(XCA_TITLE, tr("Please enter the password to decrypt the private key from file:\n%1").
		arg(compressFilename(fname)));
	pem_password_cb *cb = PwDialogCore::pwCallback;

	pki_ign_openssl_error();
	XFile file(fname);
	file.open_read();
	QByteArray ba = file.readAll();
	EVP_PKEY *pkey;

	do {
		pkey = PEM_read_bio_PrivateKey(BioByteArray(ba).ro(),
						NULL, cb, &p);
		if (p.getResult() != pw_ok)
			throw p.getResult();
		if (openssl_pw_error())
			XCA_PASSWD_ERROR();
		if (pki_ign_openssl_error())
			break;
	} while (!pkey);

	if (!pkey) {
		pki_ign_openssl_error();
		pkey = d2i_PrivateKey_bio(BioByteArray(ba).ro(), NULL);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = d2i_PKCS8PrivateKey_bio(BioByteArray(ba).ro(),
						NULL, cb, &p);
	}
	if (!pkey) {
		PKCS8_PRIV_KEY_INFO *p8inf;
		pki_ign_openssl_error();
		p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(BioByteArray(ba).ro(),
							NULL);
		if (p8inf) {
			pkey = EVP_PKCS82PKEY(p8inf);
			PKCS8_PRIV_KEY_INFO_free(p8inf);
		}
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = b2i_PVK_bio(BioByteArray(ba).ro(), cb, &p);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = load_ssh_ed25519_privatekey(ba, p);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = PEM_read_bio_PUBKEY(BioByteArray(ba).ro(), NULL, cb, &p);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = d2i_PUBKEY_bio(BioByteArray(ba).ro(), NULL);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = load_ssh2_key(ba);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		pkey = b2i_PublicKey_bio(BioByteArray(ba).ro());
	}
	if (pki_ign_openssl_error() || !pkey) {
		if (pkey)
			EVP_PKEY_free(pkey);
		throw errorEx(tr("Unable to load the private key in file %1. Tried PEM and DER private, public, PKCS#8 key types and SSH2 format.").arg(fname));
	}
	set_EVP_PKEY(pkey, fname);
}

bool pki_evp::validateDatabasePassword(const Passwd &passwd)
{
	return !passHash.isEmpty() &&
			(sha512passwT(passwd, passHash) == passHash ||
			 sha512passwd(passwd, passHash) == passHash);
}

EVP_PKEY *pki_evp::tryDecryptKey() const
{
	Passwd ownPassBuf;
	int ret;

	if (isPubKey()) {
		QByteArray ba = i2d_bytearray(I2D_VOID(i2d_PUBKEY), key);
		return (EVP_PKEY*)d2i_bytearray(D2I_VOID(d2i_PUBKEY), ba);
	}
	/* This key has its own password */
	if (ownPass == ptPrivate) {
		pass_info pi(XCA_TITLE, tr("Please enter the password to decrypt the private key: '%1'").arg(getIntName()));
		ret = PwDialogCore::execute(&pi, &ownPassBuf, false);
		if (ret != 1)
			throw errorEx(tr("Password input aborted"),
					getClassName());
	} else if (ownPass == ptBogus) { // BOGUS pass
		ownPassBuf = "Bogus";
	} else {
		ownPassBuf = passwd;
		while (!validateDatabasePassword(ownPassBuf)) {
			pass_info p(XCA_TITLE, tr("Please enter the database password for decrypting the key '%1'").arg(getIntName()));
			ret = PwDialogCore::execute(&p, &ownPassBuf,
							passHash.isEmpty());
			if (ret != 1)
				throw errorEx(tr("Password input aborted"),
						getClassName());
		}
	}
	QByteArray myencKey = getEncKey();
	qDebug() << "myencKey.size()"<<myencKey.size();
	if (myencKey.size() == 0)
		throw errorEx(tr("Private key has 0 size"));

	EVP_PKEY *priv = NULL;
	X509_SIG *p8 = d2i_PKCS8_bio(BioByteArray(myencKey).ro(), NULL);
	if (p8) {
		PKCS8_PRIV_KEY_INFO *p8inf = PKCS8_decrypt(p8,
				ownPassBuf.constData(), ownPassBuf.size());
		if (p8inf) {
			priv = EVP_PKCS82PKEY(p8inf);
			PKCS8_PRIV_KEY_INFO_free(p8inf);
		}
		X509_SIG_free(p8);
		if (!p8inf) {
			pki_ign_openssl_error();
			throw errorEx(tr("Decryption of private key '%1' failed")
							.arg(getIntName()));
		}
	} else {
		pki_ign_openssl_error();
		priv = legacyDecryptKey(myencKey, ownPassBuf);
	}
	pki_openssl_error();
	return priv;
}

EVP_PKEY *pki_evp::legacyDecryptKey(QByteArray &myencKey,
				    Passwd &ownPassBuf) const
{
	unsigned char *p;
	const unsigned char *p1;
	int outl, decsize;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char ckey[EVP_MAX_KEY_LENGTH];

	qDebug() << "legacyDecrypt" << this << myencKey.size();
	EVP_PKEY *tmpkey;
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	p = (unsigned char *)OPENSSL_malloc(myencKey.size());
	Q_CHECK_PTR(p);
	p1 = p;
	memset(iv, 0, EVP_MAX_IV_LENGTH);

	memcpy(iv, myencKey.constData(), 8); /* recover the iv */
	/* generate the key */
	EVP_BytesToKey(cipher, EVP_sha1(), iv,
		ownPassBuf.constUchar(), ownPassBuf.size(), 1, ckey, NULL);
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, cipher, ckey, iv);
	EVP_DecryptUpdate(ctx, p , &outl,
		(const unsigned char*)myencKey.constData() +8,
		myencKey.size() -8);
	decsize = outl;
	EVP_DecryptFinal_ex(ctx, p + decsize , &outl);

	EVP_CIPHER_CTX_cleanup(ctx);
	decsize += outl;
	tmpkey = d2i_PrivateKey(getKeyType(), NULL, &p1, decsize);
	OPENSSL_cleanse(p, myencKey.size());
	OPENSSL_free(p);
	EVP_CIPHER_CTX_free(ctx);
	pki_openssl_error();
	myencKey.fill(0);
	return tmpkey;
}

// Returns true if it was converted or already a PKCS#8 structure
bool pki_evp::updateLegacyEncryption()
{
	try {
		QByteArray myencKey = getEncKey();
		qDebug() << "myencKey:" << myencKey.size();
		X509_SIG *p8 = d2i_PKCS8_bio(BioByteArray(myencKey).ro(), NULL);
		X509_SIG_free(p8);
		if (p8) {
			qDebug() << "Key" << this << "already in PKCS#8 format";
			return true;
		}
		if (getOwnPass() == ptPrivate) {
			// Keys with individual password cannot be converted automatically
			return false;
		}
		pki_ign_openssl_error();

		EVP_PKEY *newkey = legacyDecryptKey(myencKey, passwd);
		ign_openssl_error();
		if (newkey) {
			set_evp_key(newkey);
			encryptKey();
			bool success = sqlUpdatePrivateKey();
			qDebug() << "Updated encryption scheme of" << this << success;
			return success;
		}
		qDebug() << "updating encryption scheme of" << this << "failed" << myencKey.size();

	} catch (...) {
		qDebug() << "CATCH: updating encryption scheme of" << this << "failed";
	}
	pki_ign_openssl_error();
	return false;
}

EVP_PKEY *pki_evp::decryptKey() const
{
	EVP_PKEY *priv = nullptr;
	for (int i = 0; !priv; i++) {
		priv = tryDecryptKey();
		if (i > 200)
			// break the loop after 200 tries
			throw errorEx(tr("Internal error decrypting the private key"));
	}
	return priv;
}

EVP_PKEY *pki_evp::priv2pub(EVP_PKEY* key)
{
	int keylen;
	unsigned char *p, *p1;
	EVP_PKEY *pubkey;

	keylen = i2d_PUBKEY(key, NULL);
	p1 = p = (unsigned char *)OPENSSL_malloc(keylen);
	Q_CHECK_PTR(p);

	/* convert rsa/dsa/ec to Pubkey */
	keylen = i2d_PUBKEY(key, &p);
	pki_openssl_error();
	p = p1;
	pubkey = d2i_PUBKEY(NULL, (const unsigned char**)&p, keylen);
	OPENSSL_free(p1);
	pki_openssl_error();
	return pubkey;
}

void pki_evp::encryptKey(const char *password)
{
	Passwd ownPassBuf;

	pki_openssl_error();
	/* This key has its own, private password */
	if (ownPass == ptPrivate) {
		int ret;
		pass_info p(XCA_TITLE, tr("Please enter the password to protect the private key: '%1'").
			arg(getIntName()));
		ret = PwDialogCore::execute(&p, &ownPassBuf, true);
		if (ret != 1)
			throw errorEx("Password input aborted", getClassName());
		pki_openssl_error();
	} else if (ownPass == ptBogus) { // BOGUS password
		ownPassBuf = "Bogus";
		pki_openssl_error();
	} else {
		if (password) {
			/* use the password parameter
			 * if this is a common password */
			ownPassBuf = password;
			pki_openssl_error();
		} else {
			int ret = 0;
			ownPassBuf = passwd;
			pass_info p(XCA_TITLE, tr("Please enter the database password for encrypting the key"));
			while (!validateDatabasePassword(ownPassBuf)) {
				ret = PwDialogCore::execute(&p, &ownPassBuf,
							passHash.isEmpty());
				if (ret != 1)
					throw errorEx("Password input aborted",
							getClassName());
			}
		}
	}

	/* Convert private key to DER(PKCS8-aes) */
	BioByteArray bba;
	i2d_PKCS8PrivateKey_bio(bba, key, EVP_aes_256_cbc(),
		ownPassBuf.data(), ownPassBuf.size(), NULL, 0);
	pki_openssl_error();
	encKey = bba;

	/* Replace private key by public key and
	   have the encrypted private in "encKey"
	 */
	EVP_PKEY *pkey1 = priv2pub(key);
	Q_CHECK_PTR(pkey1);
	EVP_PKEY_free(key);
	key = pkey1;
	pki_openssl_error();
}

void pki_evp::set_evp_key(EVP_PKEY *pkey)
{
	if (key)
		EVP_PKEY_free(key);
	key = pkey;
}

void pki_evp::bogusEncryptKey()
{
	ownPass = ptBogus;
	isPub = false;
	encryptKey();
}

pki_evp::~pki_evp()
{
	encKey.fill(0);
}

QSqlError pki_evp::insertSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_key::insertSqlData();
	if (e.isValid())
		return e;
	if (isPubKey())
		return QSqlError();

	SQL_PREPARE(q, "INSERT INTO private_keys (item, ownPass, private) "
		  "VALUES (?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, ownPass);
	q.bindValue(2, encKey_b64());
	q.exec();
	encKey.fill(0);
	encKey.clear();
	return q.lastError();
}

void pki_evp::restoreSql(const QSqlRecord &rec)
{
	pki_key::restoreSql(rec);
	isPub = rec.isNull(VIEW_private_ownpass);
	if (!isPub)
		ownPass =(enum passType)rec.value(VIEW_private_ownpass).toInt();
}

QByteArray pki_evp::getEncKey() const
{
	XSqlQuery q;
	QSqlError e;
	QByteArray ba;

	if (encKey.size() > 0 || !sqlItemId.isValid())
		return encKey;

	SQL_PREPARE(q, "SELECT private FROM private_keys WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid() || !q.first())
		return QByteArray();
	return QByteArray::fromBase64(q.value(0).toByteArray().trimmed());
}

QSqlError pki_evp::deleteSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_key::deleteSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM private_keys WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	return q.lastError();
}

#ifndef LIBRESSL_VERSION_NUMBER
int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x,
                                         const EVP_CIPHER *enc,
                                         unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u)
{
	QString pem = keytype::byPKEY(x).traditionalPemName();

	return PEM_ASN1_write_bio((i2d_of_void *)i2d_PrivateKey,
			pem.toLatin1(), bp, (char*)x, enc, kstr, klen, cb, u);
}
#endif

bool pki_evp::pem(BioByteArray &b, const pki_export *xport)
{
	EVP_PKEY *pkey;

	if (xport->match_all(F_PEM | F_PRIVATE)) {
		pkey = decryptKey();
		PEM_write_bio_PrivateKey_traditional(b, pkey, nullptr,
						nullptr, 0, nullptr, nullptr);
		EVP_PKEY_free(pkey);
	} else if (xport->match_all(F_PKCS8 | F_PRIVATE)) {
		const EVP_CIPHER *algo = xport->match_all(F_CRYPT) ?
			EVP_aes_256_cbc() : NULL;
		pkey = decryptKey();
        PEM_write_bio_PrivateKey(b, pkey, algo,
					 passwd.constUchar(), passwd.size(),
					 NULL, NULL);
		EVP_PKEY_free(pkey);
	} else
		return pki_key::pem(b, xport);

	return true;
}

void pki_evp::fillJWK(QJsonObject &json, const pki_export *xport) const
{
	pki_key::fillJWK(json, xport);
	if (!xport->match_all(F_PRIVATE))
		return;

	EVP_PKEY *pkey = decryptKey();

	switch (getKeyType()) {
	case EVP_PKEY_RSA:
		json["p"] = base64UrlEncodeParam(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1);
		json["q"] = base64UrlEncodeParam(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2);
		json["d"] = base64UrlEncodeParam(pkey, OSSL_PKEY_PARAM_RSA_D);
		json["dp"] = base64UrlEncodeParam(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1);
		json["dq"] = base64UrlEncodeParam(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2);
		json["qi"] = base64UrlEncodeParam(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		int bits = EVP_PKEY_bits(pkey);
		json["d"] = base64UrlEncodeParam(pkey, OSSL_PKEY_PARAM_PRIV_KEY, bits);
		break;
#endif
	}
	EVP_PKEY_free(pkey);
};

void pki_evp::writePKCS8(XFile &file, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem) const
{
	pass_info p(XCA_TITLE,
		tr("Please enter the password to protect the PKCS#8 key '%1' in file:\n%2")
			.arg(getIntName()).arg(nativeSeparator(file.fileName())));
	EVP_PKEY *pkey = decryptKey();
	if (!pkey) {
		pki_openssl_error();
		return;
	}
	BioByteArray b;
	if (pem) {
		b += PEM_comment();
		PEM_write_bio_PKCS8PrivateKey(b, pkey, enc, NULL, 0, cb, &p);
	} else {
		i2d_PKCS8PrivateKey_bio(b, pkey, enc, NULL, 0, cb, &p);
	}
	EVP_PKEY_free(pkey);
	file.write(b);
}

void pki_evp::writePVKprivate(XFile &file) const
{
	EVP_PKEY *pkey = decryptKey();
	if (!pkey) {
		pki_openssl_error();
		return;
	}
	/* In case of success! the error
	 *   PEMerr(PEM_F_I2B_PVK_BIO, PEM_R_BIO_WRITE_FAILURE)
	 * is set. Workaround this behavior */
	BioByteArray b;
	if (i2b_PVK_bio(b, pkey, 0, nullptr, nullptr) == -1) {
		pki_openssl_error();
		PEMerr(PEM_F_I2B_PVK_BIO, PEM_R_BIO_WRITE_FAILURE);
		pki_openssl_error();
	}
	ign_openssl_error();
	EVP_PKEY_free(pkey);
	file.write(b);
}

static int mycb(char *buf, int size, int, void *)
{
	strncpy(buf, pki_evp::passwd, size);
	return strlen(pki_evp::passwd);
}

void pki_evp::writeDefault(const QString &dirname) const
{
	XFile file(get_dump_filename(dirname, ".pem"));
	file.open_key();
	writeKey(file, pki_evp::passwd.isEmpty() ? NULL : EVP_aes_256_cbc(),
			mycb, true);
}

void pki_evp::writeKey(XFile &file, const EVP_CIPHER *enc,
			pem_password_cb *cb, bool pem) const
{
	pass_info p(XCA_TITLE,
		tr("Please enter the password to protect the private key '%1' in file:\n%2")
			.arg(getIntName()).arg(nativeSeparator(file.fileName())));

	if (isPubKey()) {
		writePublic(file, pem);
		return;
	}
	EVP_PKEY *pkey = key ? decryptKey() : NULL;
	if (!pkey) {
		pki_openssl_error();
		return;
	}
	BioByteArray b;
	if (pem) {
		b += PEM_comment();
		PEM_write_bio_PrivateKey_traditional(b, pkey, enc,
						NULL, 0, cb, &p);
	} else {
		i2d_PrivateKey_bio(b, pkey);
	}
	EVP_PKEY_free(pkey);
	pki_openssl_error();
	file.write(b);
}

void pki_evp::write_SSH2_ed25519_private(BIO *b, const EVP_PKEY *pkey) const
{
#ifndef OPENSSL_NO_EC
	static const char data0001[] = { 0, 0, 0, 1};
	// padding required to bring private key up to required block size for encryption
	// elected to just add fixed padding as the size of the binary data should not change due to the fixed keysizes
	static const char padding[] = { 1, 2, 3, 4, 5 };
	char buf_nonce[4];
	QByteArray data, priv, pubfull;

	pubfull = SSH2publicQByteArray(true);
	RAND_bytes((unsigned char*)buf_nonce, sizeof buf_nonce);
	priv.append(buf_nonce, sizeof buf_nonce);
	priv.append(buf_nonce, sizeof buf_nonce);
	priv += pubfull;
	ssh_key_QBA2data(ed25519PrivKey(pkey) + ed25519PubKey(), &priv);
	ssh_key_QBA2data("", &priv); // comment (blank)
	priv.append(padding, sizeof padding);

	data = "openssh-key-v1";
	data.append('\0');
	ssh_key_QBA2data("none", &data); // enc-alg
	ssh_key_QBA2data("none", &data); // KDF name
	ssh_key_QBA2data("", &data); // KDF data
	data.append(data0001, sizeof data0001);
	ssh_key_QBA2data(pubfull, &data);
	ssh_key_QBA2data(priv, &data);

	PEM_write_bio(b, PEM_STRING_OPENSSH_KEY, (char*)"",
		(unsigned char*)(data.data()), data.size());
	pki_openssl_error();
#else
	(void)b;
	(void)pkey;
#endif
}
void pki_evp::writeSSH2private(XFile &file) const
{
	EVP_PKEY *pkey = decryptKey();
	if (!pkey) {
		pki_openssl_error();
		return;
	}
#ifdef EVP_PKEY_ED25519
	if (getKeyType() == EVP_PKEY_ED25519) {
		BioByteArray b;
		write_SSH2_ed25519_private(b, pkey);
		file.write(b);
	} else
#endif
		writeKey(file, nullptr, nullptr, true);

	EVP_PKEY_free(pkey);
}

bool pki_evp::verify(EVP_PKEY *pkey) const
{
	if (!EVP_PKEY_isPrivKey(pkey))
		return pki_key::verify(pkey);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	Q_CHECK_PTR(ctx);
	int verify = EVP_PKEY_check(ctx);
	EVP_PKEY_CTX_free(ctx);
	if (verify == -2) {
		// Operation not supported assume true
		pki_ign_openssl_error();
	}
	pki_openssl_error();
	return verify;
}

QVariant pki_evp::getIcon(const dbheader *hd) const
{
	if (hd->id != HD_internal_name)
		return QVariant();

	return QVariant(QPixmap(isPubKey() ? ":pubkeyIco" : ":keyIco"));
}

QString pki_evp::md5passwd(QByteArray pass)
{
	return formatHash(Digest(pass, EVP_md5()));
}

QString pki_evp::_sha512passwd(QByteArray pass, QString salt,
				int size, int repeat)
{
	if (salt.length() < size)
		return QString();

	salt = salt.left(size);
	pass = salt.toLatin1() + pass;

	while (repeat--)
		pass = Digest(pass, EVP_sha512());

	return salt + formatHash(pass, "");
}

QString pki_evp::sha512passwd(QByteArray pass, QString salt)
{
	return _sha512passwd(pass, salt, 5, 1);
}

QString pki_evp::sha512passwT(QByteArray pass, QString salt)
{
	return _sha512passwd(pass, salt, 17, 8000);
}
