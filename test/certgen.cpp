/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2025 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QTemporaryFile>
#include <QTemporaryDir>
#include <openssl/pem.h>

#include "lib/pki_multi.h"
#include "lib/pki_x509.h"
#include "lib/db_x509.h"
#include "lib/cli_sign.h"
#include "lib/settings.h"
#include "lib/BioByteArray.h"

#include "main.h"

static QString jobFile(QTemporaryFile &f, const QByteArray &json)
{
	if (!f.open())
		throw errorEx("Failed to create temporary job file");
	f.write(json);
	f.close();
	return f.fileName();
}

static int extCount(pki_x509 *cert, int nid)
{
	int n = 0;
	extList el = cert->getV3ext();
	for (const x509v3ext &e : el)
		n += e.nid() == nid;
	return n;
}

void test_main::certgen()
{
	try {

	ign_openssl_error();
	openDB();
	Settings["suppress_messages"] = true;
	pki_multi *pem = new pki_multi();
	pem->fromPEMbyteArray(pemdata["Root CA"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Root CA Key"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Endentity Key"].toUtf8(), QString());
	Database.insert(pem);

	pki_x509 *root = dynamic_cast<pki_x509*>(
		Database.model<db_x509>()->getByName("Root CA"));
	QVERIFY(root);
	QString keyId;
	foreach(pki_key *k, Store.getAll<pki_key>()) {
		if (k != root->getRefKey())
			keyId = k->getSqlItemId().toString();
	}
	QVERIFY(!keyId.isEmpty());

	/* Issue: every extension exactly once, chain verifies */
	QTemporaryFile f1;
	pki_x509 *cert = cli_certgen(jobFile(f1, QString(R"({
		"issuer": "Root CA", "key": "%1", "name": "srv",
		"subject": { "CN": "*.example.net", "O": "Test" },
		"days": 30,
		"extensions": {
			"basicConstraints": "critical, CA:FALSE",
			"subjectKeyIdentifier": "hash",
			"authorityKeyIdentifier": "keyid,issuer",
			"keyUsage": "critical, digitalSignature, keyEncipherment",
			"extendedKeyUsage": "serverAuth",
			"subjectAltName": "DNS:*.example.net"
		}})").arg(keyId).toUtf8()));
	QVERIFY(cert);
	QVERIFY(cert->getSqlItemId().toULongLong() > 0);
	QVERIFY(cert->verify_only(root));
	QCOMPARE(cert->getSigner(), root);
	QVERIFY(!cert->isCA());
	QCOMPARE(cert->getSubject().getEntryByNid(NID_commonName),
		QString("*.example.net"));
	QCOMPARE(cert->getNotBefore().daysTo(cert->getNotAfter()), qint64(30));
	for (int nid : { NID_basic_constraints, NID_subject_key_identifier,
			NID_authority_key_identifier, NID_key_usage,
			NID_ext_key_usage, NID_subject_alt_name })
		QCOMPARE(extCount(cert, nid), 1);

	/* Renew: new serial, same subject and extensions, 90 days */
	QTemporaryFile f2;
	pki_x509 *renewed = cli_certgen(jobFile(f2, QString(
		R"({ "renew": "%1", "days": 90 })")
		.arg(cert->getSqlItemId().toString()).toUtf8()));
	QVERIFY(renewed);
	QVERIFY(renewed->verify_only(root));
	QVERIFY(renewed->getSerial() != cert->getSerial());
	QCOMPARE(renewed->getSubject(), cert->getSubject());
	QCOMPARE(renewed->getV3ext().count(), cert->getV3ext().count());
	QCOMPARE(renewed->getNotBefore().daysTo(renewed->getNotAfter()), qint64(90));

	/* Issue with a generated key and write a deployable bundle */
	QTemporaryDir dir;
	QVERIFY(dir.isValid());
	QTemporaryFile f3;
	pki_x509 *gen = cli_certgen(jobFile(f3, QString(R"({
		"issuer": "Root CA", "key": { "generate": "EC:prime256v1" },
		"name": "gen", "subject": { "CN": "gen.example.net" },
		"days": 7,
		"extensions": { "subjectAltName": "DNS:copycn" },
		"output": { "cert": "%1/c.pem", "chain": "%1/ch.pem",
			"key": "%1/k.pem" } })").arg(dir.path()).toUtf8()));
	QVERIFY(gen);
	QVERIFY(gen->verify_only(root));
	pki_key *gkey = gen->getRefKey();
	QVERIFY(gkey && !gkey->isPubKey());
	QCOMPARE(gkey->getIntName(), QString("gen"));
	QCOMPARE(gen->getV3ext().count(), 1);
	QVERIFY(gen->getV3ext()[0].getValue().contains("DNS:gen.example.net"));

	QFile chain(dir.path() + "/ch.pem");
	QVERIFY(chain.open(QIODevice::ReadOnly));
	QCOMPARE(chain.readAll().count("BEGIN CERTIFICATE"), 2);
	QFile keyf(dir.path() + "/k.pem");
	QVERIFY(keyf.open(QIODevice::ReadOnly));
	QByteArray kpem = keyf.readAll();
	QVERIFY(kpem.startsWith("-----BEGIN PRIVATE KEY-----"));
	EVP_PKEY *pk = PEM_read_bio_PrivateKey(BioByteArray(kpem).ro(),
						NULL, NULL, NULL);
	QVERIFY(pk);
	QCOMPARE(X509_check_private_key(gen->getCert(), pk), 1);
	EVP_PKEY_free(pk);
#if !defined(Q_OS_WIN32)
	QCOMPARE(keyf.permissions() & (QFile::ReadGroup | QFile::ReadOther),
		QFile::Permissions());
#endif

	/* Console mode leaves the database password unvalidated and offers
	 * --password to the first prompt only. A job that decrypts several
	 * keys must still succeed, and a wrong password must fail loudly. */
	Passwd dbpass = pki_evp::passwd;
	QTemporaryFile f4;
	QString job4 = jobFile(f4, QString(R"({
		"issuer": "Root CA", "key": { "generate": "EC:prime256v1" },
		"subject": { "CN": "console.example.net" }, "days": 1,
		"output": { "key": "%1/k2.pem" } })").arg(dir.path()).toUtf8());

	pki_evp::passwd = Passwd();
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("wrong", pw_ok),
	});
	int n = Store.getAll<pki_x509>().size();
	QVERIFY_EXCEPTION_THROWN(cli_certgen(job4), errorEx);
	QCOMPARE(Store.getAll<pki_x509>().size(), n);

	pki_evp::passwd = Passwd();
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect(dbpass.constData(), pw_ok),
	});
	QVERIFY(cli_certgen(job4));
	QCOMPARE(pwdialog->expect_idx, 1);
	QVERIFY(QFile::exists(dir.path() + "/k2.pem"));

	/* Invalid jobs are refused before anything is stored */
	int before = Store.getAll<pki_x509>().size();
	for (QByteArray bad : {
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "typo": 1 })"),
		QByteArray(R"({ "issuer": "nope", "key": "1", "days": 1 })"),
		QByteArray(R"({ "issuer": "Root CA", "days": 1,
			"subject": { "CN": "x" } })"),
		QByteArray(R"({ "renew": "999999" })"),
		QByteArray(R"({ "issuer": "Root CA", "days": 1,
			"key": { "generate": "RSA:512" }, "subject": { "CN": "x" } })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1,
			"subject": { "CN": "x" },
			"extensions": { "keyUsage": "digitalSignatur" } })"),
	}) {
		QTemporaryFile fb;
		QVERIFY_EXCEPTION_THROWN(cli_certgen(jobFile(fb, bad)), errorEx);
	}
	QCOMPARE(Store.getAll<pki_x509>().size(), before);

	} catch (errorEx &e) {
		QVERIFY2(false, CCHAR(e.getString()));
	}
}
