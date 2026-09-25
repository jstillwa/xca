/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2025 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QTemporaryFile>
#include <QTemporaryDir>
#include <QProcess>
#include <QCoreApplication>
#include <openssl/pem.h>

#include "lib/pki_multi.h"
#include "lib/pki_x509.h"
#include "lib/db_x509.h"
#include "lib/db_x509req.h"
#include "lib/pki_x509req.h"
#include "lib/cli_sign.h"
#include "lib/secure_file.h"
#include "lib/sql.h"
#include "lib/PwDialogCore.h"
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
	/* Entry order follows explicit_dn like the GUI, not the JSON */
	QCOMPARE(cert->getSubject().oneLine(XN_FLAG_RFC2253),
		QString("CN=*.example.net,O=Test"));
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
	QVERIFY2(is_owner_only_file(dir.path() + "/k.pem"),
		"key file is readable beyond its owner");

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

	/* A CSR must carry a valid signature before the CA signs it */
	pki_key *subjectKey = Store.lookupPki<pki_key>(QVariant(keyId.toULongLong()));
	QVERIFY(subjectKey);
	x509name reqName;
	reqName.addEntryByNid(NID_commonName, "csr.example.net");
	pki_x509req *good = new pki_x509req("good-csr");
	good->createReq(subjectKey, reqName, digest::getDefault(), extList());
	QVERIFY(good->verify());
	good = dynamic_cast<pki_x509req*>(Database.model<db_x509req>()->insert(good));
	QVERIFY(good);

	pki_x509req *tampered = new pki_x509req("tampered-csr");
	tampered->createReq(subjectKey, reqName, digest::getDefault(), extList());
	x509name forged;
	forged.addEntryByNid(NID_commonName, "forged.example.net");
	tampered->setSubject(forged);        /* changes signed content */
	QVERIFY(!tampered->verify());
	tampered = dynamic_cast<pki_x509req*>(Database.model<db_x509req>()->insert(tampered));
	QVERIFY(tampered);

	QTemporaryFile f5, f6;
	QVERIFY(cli_certgen(jobFile(f5, QString(R"({ "issuer": "Root CA",
		"csr": "%1", "days": 1 })").arg(good->getSqlItemId().toString()).toUtf8())));
	int nCsr = Store.getAll<pki_x509>().size();
	QVERIFY_EXCEPTION_THROWN(cli_certgen(jobFile(f6, QString(R"({ "issuer": "Root CA",
		"csr": "%1", "days": 1 })").arg(tampered->getSqlItemId().toString()).toUtf8())), errorEx);
	QCOMPARE(Store.getAll<pki_x509>().size(), nCsr);

	/* Renewal keeps the exact validity length, including sub-day
	 * intervals, and keeps an undefined expiry undefined. */
	{
		QTemporaryFile fa, fb2, fc;
		pki_x509 *shortCert = cli_certgen(jobFile(fa, QString(R"({
			"issuer": "Root CA", "key": "%1", "subject": { "CN": "short" },
			"not_before": "2031-03-01T10:00:00Z",
			"not_after": "2031-03-01T16:30:00Z" })").arg(keyId).toUtf8()));
		QVERIFY(shortCert);
		pki_x509 *r1 = cli_certgen(jobFile(fb2, QString(R"({ "renew": "%1",
			"not_before": "2031-06-01T23:00:00Z" })")
			.arg(shortCert->getSqlItemId().toString()).toUtf8()));
		QVERIFY(r1);
		QCOMPARE(r1->getNotBefore().secsTo(r1->getNotAfter()),
			qint64(6 * 3600 + 1800));

		pki_x509 *noExpiry = new pki_x509(shortCert);
		a1time undef;
		undef.setUndefined();
		noExpiry->setNotAfter(undef);
		noExpiry->setSerial(Database.model<db_x509>()->getUniqueSerial(root));
		noExpiry->sign(root->getRefKey(), digest::getDefault());
		noExpiry = dynamic_cast<pki_x509*>(Database.model<db_x509>()->insert(noExpiry));
		QVERIFY(noExpiry);
		pki_x509 *r2 = cli_certgen(jobFile(fc, QString(R"({ "renew": "%1" })")
			.arg(noExpiry->getSqlItemId().toString()).toUtf8()));
		QVERIFY(r2);
		QVERIFY(r2->getNotAfter().isUndefined());
	}

	/* A failed job leaves no trace: no certificate, no generated key,
	 * no output file, and the database stays consistent with Store. */
	QTemporaryFile f7;
	int keysBefore = Store.getAll<pki_key>().size();
	int certsBefore = Store.getAll<pki_x509>().size();
	QString unwritable = dir.path() + "/no-such-dir/k.pem";
	for (QByteArray failing : {
		/* fails after key generation, before signing */
		QByteArray(R"({ "issuer": "Root CA", "key": { "generate": "EC:prime256v1" },
			"template": "no such template", "subject": { "CN": "t1" }, "days": 1 })"),
		/* fails on an invalid extension after key generation */
		QByteArray(R"({ "issuer": "Root CA", "key": { "generate": "EC:prime256v1" },
			"subject": { "CN": "t2" }, "days": 1,
			"extensions": { "keyUsage": "digitalSignatur" } })"),
		/* fails writing output after the certificate is signed */
		QString(R"({ "issuer": "Root CA", "key": { "generate": "EC:prime256v1" },
			"subject": { "CN": "t3" }, "days": 1,
			"output": { "cert": "%1/t3.pem", "key": "%2" } })")
			.arg(dir.path(), unwritable).toUtf8(),
	}) {
		QVERIFY_EXCEPTION_THROWN(cli_certgen(jobFile(f7, failing)), errorEx);
		QCOMPARE(Store.getAll<pki_key>().size(), keysBefore);
		QCOMPARE(Store.getAll<pki_x509>().size(), certsBefore);
	}
	QVERIFY(!QFile::exists(dir.path() + "/t3.pem"));
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT COUNT(*) FROM items WHERE del=0 AND name IN ('t1','t2','t3')");
	q.exec();
	QVERIFY(q.first());
	QCOMPARE(q.value(0).toInt(), 0);

	/* A renewal whose output fails is not stored either */
	QTemporaryFile f8;
	QVERIFY_EXCEPTION_THROWN(cli_certgen(jobFile(f8, QString(R"({ "renew": "%1",
		"days": 1, "output": { "cert": "%2" } })")
		.arg(cert->getSqlItemId().toString(), unwritable).toUtf8())), errorEx);
	QCOMPARE(Store.getAll<pki_x509>().size(), certsBefore);

	/* --certgen together with --import must not hand the stored
	 * certificate back to the import path, which deletes it as a
	 * duplicate while the item store still owns it. Run the real binary:
	 * the double free shows up at process exit. */
	{
		QString xca = QCoreApplication::applicationDirPath() + "/xca";
#if defined(Q_OS_WIN32)
		xca += ".exe";
#endif
		QTemporaryDir cdir;
		QString db = cdir.path() + "/cli.xdb";
		QVERIFY(QFile::copy("testdb.xdb", db));
		QTemporaryFile f9;
		QString job9 = jobFile(f9, QString(R"({ "renew": "%1", "days": 1 })")
				.arg(cert->getSqlItemId().toString()).toUtf8());
		QProcess p;
		QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
		env.insert("XCA_NO_GUI", "1");
		env.insert("XCA_TEST_PW", QString::fromLatin1(dbpass));
		p.setProcessEnvironment(env);
		p.start(xca, { "--database=" + db, "--password=env:XCA_TEST_PW",
			"--certgen=" + job9, "--import" });
		QVERIFY2(p.waitForFinished(60000), "xca --certgen --import did not exit");
		QCOMPARE(p.exitStatus(), QProcess::NormalExit);
		QCOMPARE(p.exitCode(), 0);
	}

	/* A password prompt that aborts by throwing (the Windows console
	 * path throws pw_exit) must reach the caller as errorEx, which the
	 * command line turns into a failure exit status, whether it happens
	 * at the database-password check or when a key is decrypted. */
	{
		struct ThrowingDialog : public PwDialogUI_i {
			enum open_result execute(pass_info *, Passwd *, bool, bool)
			{
				throw pw_exit;
			}
		};
		QTemporaryFile fp1, fp2;
		QString j1 = jobFile(fp1, QString(R"({ "renew": "%1", "days": 1 })")
				.arg(cert->getSqlItemId().toString()).toUtf8());
		QString j2 = jobFile(fp2, QString(R"({ "renew": "%1", "days": 1,
			"output": { "key": "%2/pw.pem" } })")
				.arg(cert->getSqlItemId().toString(), dir.path()).toUtf8());
		Passwd saved = pki_evp::passwd;
		PwDialogCore::setGui(new ThrowingDialog());
		int n0 = Store.getAll<pki_x509>().size();
		for (const QString &j : { j1, j2 }) {
			pki_evp::passwd = Passwd();
			bool gotErrorEx = false;
			try {
				cli_certgen(j);
			} catch (errorEx &) {
				gotErrorEx = true;
			} catch (...) {
			}
			QVERIFY2(gotErrorEx, "password abort escaped as a non-errorEx exception");
		}
		QCOMPARE(Store.getAll<pki_x509>().size(), n0);
		pki_evp::passwd = saved;
		pwdialog = new PwDialogMock();
		PwDialogCore::setGui(pwdialog);
	}

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
		/* wrongly typed values are refused, not coerced */
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1,
			"subject": { "CN": "x" }, "extensions": { "extendedKeyUsage": false } })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1,
			"subject": { "CN": "x", "O": 3 } })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": "30",
			"subject": { "CN": "x" } })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 0,
			"subject": { "CN": "x" } })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1.5,
			"subject": { "CN": "x" } })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1,
			"subject": "CN=x" })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1,
			"subject": { "CN": "x" }, "copy_csr_extensions": "false" })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "subject": { "CN": "x" },
			"not_before": "2030-01-02T00:00:00Z", "not_after": "2030-01-01T00:00:00Z" })"),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1,
			"subject": { "CN": "x" }, "output": "out.pem" })"),
		/* keys that do not apply to the job type are refused */
		QString(R"({ "renew": "%1", "hash": "SHA512" })")
			.arg(cert->getSqlItemId().toString()).toUtf8(),
		QString(R"({ "renew": "%1", "subject": { "CN": "y" } })")
			.arg(cert->getSqlItemId().toString()).toUtf8(),
		QByteArray(R"({ "issuer": "Root CA", "key": "1", "days": 1,
			"subject": { "CN": "x" }, "keep_serial": true })"),
	}) {
		QTemporaryFile fb;
		QVERIFY_EXCEPTION_THROWN(cli_certgen(jobFile(fb, bad)), errorEx);
	}
	QCOMPARE(Store.getAll<pki_x509>().size(), before);

	} catch (errorEx &e) {
		QVERIFY2(false, CCHAR(e.getString()));
	}
}
