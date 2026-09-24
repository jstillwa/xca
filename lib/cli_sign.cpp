/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2025 Christian Hohnstaedt.
 *
 * All rights reserved.
 *
 * Non-interactive certificate issuance and renewal for "--certgen".
 * Mirrors db_x509::newCert() and db_x509::certRenewal(), which are
 * bound to the NewX509 / CertExtend dialogs.
 */

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "cli_sign.h"
#include "exception.h"
#include "func.h"
#include "settings.h"
#include "BioByteArray.h"
#include "database_model.h"
#include "db_x509.h"
#include "db_x509req.h"
#include "db_key.h"
#include "db_temp.h"
#include "pki_x509.h"
#include "pki_x509req.h"
#include "pki_temp.h"
#include "pki_key.h"
#include "x509rev.h"
#include "xfile.h"
#include "pki_evp.h"

static const QSet<QString> job_keys = {
	"renew", "keep_serial", "issuer", "key", "csr", "template",
	"name", "subject", "not_before", "not_after", "days", "hash",
	"extensions", "copy_csr_extensions", "output",
};

static const QSet<QString> output_keys = { "cert", "chain", "key" };

static const QSet<QString> ext_keys = {
	"basicConstraints", "keyUsage", "extendedKeyUsage",
	"subjectAltName", "issuerAltName", "nameConstraints",
	"crlDistributionPoints", "authorityInfoAccess", "nsComment",
	"subjectKeyIdentifier", "authorityKeyIdentifier", "advanced",
};

static void rejectUnknown(const QJsonObject &o, const QSet<QString> &allowed,
			const QString &where)
{
	foreach(QString k, o.keys()) {
		if (!allowed.contains(k))
			throw errorEx(QObject::tr("Unknown key '%1' in %2")
					.arg(k).arg(where));
	}
}

/* Look up an item by database id or by exact internal name.
 * Ambiguous names are an error: renewing or signing the wrong
 * certificate is worse than asking for the id. */
template <class T> static T *lookup(const QString &ref, const char *what)
{
	QList<T*> hits;
	foreach(T *pki, Store.getAll<T>()) {
		if (pki->getSqlItemId().toString() == ref)
			return pki;
		if (pki->getIntName() == ref)
			hits << pki;
	}
	if (hits.isEmpty())
		throw errorEx(QObject::tr("%1 '%2' not found").arg(what).arg(ref));
	if (hits.size() > 1) {
		QStringList ids;
		foreach(T *pki, hits)
			ids << pki->getSqlItemId().toString();
		throw errorEx(QObject::tr("%1 name '%2' is ambiguous, use one "
			"of the ids: %3").arg(what).arg(ref).arg(ids.join(", ")));
	}
	return hits[0];
}

/* Accept ids as JSON numbers or strings */
static QString ref(const QJsonObject &job, const char *key)
{
	return job[key].toVariant().toString();
}

static a1time parseTime(const QJsonValue &v, const char *key)
{
	a1time t;
	QDateTime dt = QDateTime::fromString(v.toString(), Qt::ISODate);
	if (!dt.isValid())
		throw errorEx(QObject::tr("Invalid ISO-8601 date in '%1': %2")
				.arg(key).arg(v.toString()));
	t = a1time(dt.toUTC());
	return t;
}

static pki_x509 *resolveIssuer(const QString &ref)
{
	if (ref.isEmpty())
		throw errorEx(QObject::tr("Missing 'issuer'"));
	pki_x509 *issuer = lookup<pki_x509>(ref, "Issuer");
	if (!issuer->canSign())
		throw errorEx(QObject::tr("Issuer '%1' is not a CA with a "
			"private key").arg(issuer->getIntName()));
	return issuer;
}

static void checkSignKey(pki_key *key)
{
	if (!key || key->isPubKey())
		throw errorEx(QObject::tr("The issuer has no private key"));
}

static pki_x509 *renew(const QJsonObject &job, db_x509 *certs)
{
	pki_x509 *old = lookup<pki_x509>(ref(job, "renew"), "Certificate");
	pki_x509 *signer = old->getSigner();
	if (!signer || signer == old)
		throw errorEx(QObject::tr("Certificate '%1' has no known issuer "
			"in the database").arg(old->getIntName()));
	pki_key *signkey = signer->getRefKey();
	checkSignKey(signkey);

	a1time notBefore = job.contains("not_before") ?
		parseTime(job["not_before"], "not_before") : a1time(a1time::now());
	a1time notAfter;
	if (job.contains("not_after")) {
		notAfter = parseTime(job["not_after"], "not_after");
	} else {
		qint64 days = job.contains("days") ? job["days"].toInt() :
			old->getNotBefore().daysTo(old->getNotAfter());
		notAfter = a1time(notBefore.addDays(days));
	}

	pki_x509 *cert = new pki_x509(old);
	try {
		cert->pkiSource = renewed;
		cert->setRevoked(x509rev());
		cert->setSerial(job["keep_serial"].toBool() ?
			old->getSerial() : certs->getUniqueSerial(signer));
		cert->setNotBefore(notBefore);
		cert->setNotAfter(notAfter);
		cert->sign(signkey, old->getDigest());
	} catch (...) {
		delete cert;
		throw;
	}
	return cert;
}

/* Collected extension config strings in the order NewX509::getAllExt()
 * applies them. Empty strings mean "omit". */
struct extConf {
	QString bc, ski, aki, ku, eku, nameCons, san, ian, crlDist, aia;
	QString ocsp, nsCertType, nsComment, advanced;
};

static QString kuFromBits(int bits, bool critical)
{
	static const char *names[] = {
		"digitalSignature", "nonRepudiation", "keyEncipherment",
		"dataEncipherment", "keyAgreement", "keyCertSign",
		"cRLSign", "encipherOnly", "decipherOnly"
	};
	QStringList l;
	for (int i = 0; i < 9; i++)
		if (bits & (1 << i))
			l << names[i];
	if (critical && !l.isEmpty())
		l.prepend("critical");
	return l.join(", ");
}

static QString nsCertTypeFromBits(int bits)
{
	static const char *names[] = {
		"client", "server", "email", "objsign",
		"sslCA", "emailCA", "objCA"
	};
	QStringList l;
	for (int i = 0; i < 7; i++)
		if (bits & (1 << i))
			l << names[i];
	return l.join(", ");
}

static void fromTemplate(extConf &c, pki_temp *t)
{
	QStringList bc;
	int ca = t->getSettingInt("ca");
	if (ca > 0) {
		if (t->getSettingInt("bcCritical"))
			bc << "critical";
		bc << (ca == 1 ? "CA:TRUE" : "CA:FALSE");
		if (ca == 1 && !t->getSetting("basicPath").isEmpty())
			bc << "pathlen:" + t->getSetting("basicPath");
	}
	c.bc = bc.join(", ");
	c.ski = t->getSettingInt("subKey") ? "hash" : "";
	c.aki = t->getSettingInt("authKey") ? "keyid,issuer" : "";
	c.ku = kuFromBits(t->getSettingInt("keyUse"),
				t->getSettingInt("kuCritical"));
	c.eku = t->getSetting("eKeyUse");
	if (t->getSettingInt("ekuCritical") && !c.eku.isEmpty())
		c.eku = "critical, " + c.eku;
	c.nameCons = t->getSetting("nameCons");
	c.san = t->getSetting("subAltName");
	c.ian = t->getSetting("issAltName");
	c.crlDist = t->getSetting("crlDist");
	c.aia = t->getSetting("authInfAcc");
	c.ocsp = t->getSettingInt("OCSPstaple") ? "status_request" : "";
	c.nsCertType = nsCertTypeFromBits(t->getSettingInt("nsCertType"));
	c.nsComment = t->getSetting("nsComment");
	c.advanced = t->getSetting("adv_ext");
}

static void fromJson(extConf &c, const QJsonObject &e)
{
	rejectUnknown(e, ext_keys, "'extensions'");
	struct { const char *key; QString *dst; } map[] = {
		{ "basicConstraints", &c.bc },
		{ "subjectKeyIdentifier", &c.ski },
		{ "authorityKeyIdentifier", &c.aki },
		{ "keyUsage", &c.ku },
		{ "extendedKeyUsage", &c.eku },
		{ "nameConstraints", &c.nameCons },
		{ "subjectAltName", &c.san },
		{ "issuerAltName", &c.ian },
		{ "crlDistributionPoints", &c.crlDist },
		{ "authorityInfoAccess", &c.aia },
		{ "nsComment", &c.nsComment },
		{ "advanced", &c.advanced },
	};
	for (auto &m : map) {
		if (e.contains(m.key))
			*m.dst = e[m.key].toString();
	}
}

/* Same mechanism as NewX509::getAdvanced(): an OpenSSL config
 * "[default]" section applied to ctx->subject_cert. */
static void applyAdvanced(const QString &conf_str, X509V3_CTX *ctx)
{
	if (conf_str.trimmed().isEmpty())
		return;
	long err_line = 0;
	CONF *conf = NCONF_new(NULL);
	if (NCONF_load_bio(conf, BioByteArray(conf_str.toLatin1()).ro(),
				&err_line) != 1) {
		NCONF_free(conf);
		throw errorEx(QObject::tr("Advanced extensions: config error "
			"on line %1").arg(err_line));
	}
	X509V3_set_nconf(ctx, conf);
	int ok = X509V3_EXT_add_nconf(conf, ctx, (char *)"default",
					ctx->subject_cert);
	X509V3_set_nconf(ctx, NULL);
	NCONF_free(conf);
	if (!ok)
		openssl_error();
}

/* x509v3ext::create() adds the extension to ctx->subject_cert
 * directly, so nothing here calls pki_x509::addV3ext().
 * create() also swallows OpenSSL errors; a malformed value must not
 * silently produce a certificate without that extension. */
static void addExt(int nid, const QString &val, X509V3_CTX *ctx,
			bool ia5 = false)
{
	if (val.isEmpty())
		return;
	x509v3ext e;
	if (ia5)
		e.create_ia5(nid, val, ctx);
	else
		e.create(nid, val, ctx);
	if (!e.isValid())
		throw errorEx(QObject::tr("Invalid %1: '%2'")
				.arg(OBJ_nid2ln(nid)).arg(val));
}

static void applyExtensions(const extConf &c, X509V3_CTX *ctx)
{
	addExt(NID_basic_constraints, c.bc, ctx);
	addExt(NID_subject_key_identifier, c.ski, ctx);
	addExt(NID_authority_key_identifier, c.aki, ctx);
	addExt(NID_key_usage, c.ku, ctx);
	addExt(NID_ext_key_usage, c.eku, ctx);
	addExt(NID_name_constraints, c.nameCons, ctx);
	addExt(NID_subject_alt_name, c.san, ctx);
	addExt(NID_issuer_alt_name, c.ian, ctx);
	addExt(NID_crl_distribution_points, c.crlDist, ctx);
	addExt(NID_info_access, c.aia, ctx);
	addExt(NID_tlsfeature, c.ocsp, ctx);
	applyAdvanced(c.advanced, ctx);
	if (!Settings["disable_netscape"]) {
		addExt(NID_netscape_cert_type, c.nsCertType, ctx);
		addExt(NID_netscape_comment, c.nsComment, ctx, true);
	}
}

static a1time templateNotAfter(const a1time &nb, pki_temp *t)
{
	int n = t->getSettingInt("validN");
	QDateTime dt = nb;
	switch (t->getSettingInt("validM")) {
	case 0: dt = dt.addDays(n); break;
	case 1: dt = dt.addMonths(n); break;
	default: dt = dt.addYears(n); break;
	}
	if (t->getSettingInt("validMidn"))
		dt = dt.addDays(-1);
	return a1time(dt);
}

/* "key": { "generate": "RSA:4096" } creates the subject key in the
 * database, named after the job, as the "New key" dialog would. */
static pki_key *generateKey(const QJsonObject &k, const QJsonObject &job)
{
	rejectUnknown(k, { "generate", "name" }, "'key'");
	keyjob task(k["generate"].toString());
	if (!task.isValid() || (!task.isEC() && !task.isED25519() &&
				(task.size < 2048 || task.size > 8192)))
		throw errorEx(QObject::tr("Invalid key type '%1', expected e.g. "
			"RSA:4096, EC:prime256v1 or ED25519")
			.arg(k["generate"].toString()));
	QString name = k["name"].toString();
	if (name.isEmpty())
		name = job["name"].toString();
	if (name.isEmpty())
		name = job["subject"].toObject()["CN"].toString();
	pki_evp *key = new pki_evp(name);
	try {
		key->generate(task);
		key->pkiSource = generated;
		if (key->getIntName().isEmpty())
			key->autoIntName(name);
	} catch (...) {
		delete key;
		throw;
	}
	pki_key *stored = dynamic_cast<pki_key *>(
		Database.model<db_key>()->insert(key));
	if (!stored)
		throw errorEx(QObject::tr("Generated key was not stored"));
	return stored;
}

static pki_x509 *issue(const QJsonObject &job, db_x509 *certs,
			pki_x509req **reqOut)
{
	pki_x509 *issuer = resolveIssuer(ref(job, "issuer"));
	pki_key *signkey = issuer->getRefKey();
	checkSignKey(signkey);

	pki_x509req *req = NULL;
	pki_key *subjKey = NULL, *tempKey = NULL;
	if (job.contains("csr") == job.contains("key"))
		throw errorEx(QObject::tr("Give exactly one of 'key' or 'csr'"));
	if (job.contains("csr")) {
		req = lookup<pki_x509req>(ref(job, "csr"), "Request");
		subjKey = req->getRefKey();
		if (!subjKey)
			subjKey = tempKey = req->getPubKey();
	} else if (job["key"].isObject()) {
		subjKey = generateKey(job["key"].toObject(), job);
	} else {
		subjKey = lookup<pki_key>(ref(job, "key"), "Key");
	}

	pki_temp *temp = job.contains("template") ?
		lookup<pki_temp>(ref(job, "template"), "Template") : NULL;

	pki_x509 *cert = new pki_x509();
	try {
		/* Subject: template, then CSR, then explicit JSON entries */
		x509name subj = req ? req->getSubject() :
				(temp ? temp->getSubject() : x509name());
		QJsonObject js = job["subject"].toObject();
		if (!js.isEmpty()) {
			x509name merged;
			foreach(QString k, js.keys()) {
				int nid = OBJ_txt2nid(CCHAR(k));
				if (nid == NID_undef)
					throw errorEx(QObject::tr("Unknown subject "
						"field '%1'").arg(k));
				subj.popEntryByNid(nid);
				merged.addEntryByNid(nid, js[k].toString());
			}
			for (int i = 0; i < merged.entryCount(); i++)
				subj.addEntryByNid(merged.nid(i), merged.getEntry(i));
		}
		if (subj.entryCount() == 0)
			throw errorEx(QObject::tr("Empty subject"));

		QString name = job["name"].toString();
		if (name.isEmpty())
			name = req ? req->getIntName() : subj.getMostPopular();
		cert->setIntName(name);
		cert->setSubject(subj);
		cert->setPubKey(subjKey);
		cert->setIssuer(issuer->getSubject());
		cert->setSerial(certs->getUniqueSerial(issuer));
		cert->pkiSource = generated;

		a1time nb = job.contains("not_before") ?
			parseTime(job["not_before"], "not_before") :
			a1time(a1time::now());
		a1time na;
		if (job.contains("not_after"))
			na = parseTime(job["not_after"], "not_after");
		else if (job.contains("days"))
			na = a1time(nb.addDays(job["days"].toInt()));
		else if (temp)
			na = templateNotAfter(nb, temp);
		else
			throw errorEx(QObject::tr("Give 'days', 'not_after' "
					"or a 'template'"));
		cert->setNotBefore(nb);
		cert->setNotAfter(na);

		extConf conf;
		if (temp)
			fromTemplate(conf, temp);
		fromJson(conf, job["extensions"].toObject());

		X509V3_CTX ctx;
		X509V3_set_ctx(&ctx, issuer->getCert(), cert->getCert(),
				req ? req->getReq() : NULL, NULL, 0);
		X509V3_set_ctx_nodb(&ctx);
		applyExtensions(conf, &ctx);

		if (req && job["copy_csr_extensions"].toBool(true)) {
			extList el = req->getV3ext();
			for (int i = 0; i < el.count(); i++)
				cert->addV3ext(el[i], true);
		}

		digest md = job.contains("hash") ?
			digest(job["hash"].toString()) : digest::getDefault();
		if (!md.MD())
			throw errorEx(QObject::tr("Unknown hash '%1'")
					.arg(job["hash"].toString()));
		cert->sign(signkey, md);
	} catch (...) {
		delete cert;
		delete tempKey;
		throw;
	}
	delete tempKey;
	*reqOut = req;
	return cert;
}

static void writeFile(const QString &path, const QByteArray &data,
			bool secret)
{
	XFile f(path);
	if (!(secret ? f.open_key() : f.open_write()))
		throw errorEx(QObject::tr("Cannot write '%1'").arg(path));
	f.write(data);
	f.close();
}

/* "output": { "cert": ..., "chain": ..., "key": ... }
 * chain holds the certificate followed by its issuers up to the root.
 * key is written unencrypted with owner-only permissions, because
 * its consumers (web servers, Kubernetes TLS secrets) need it plain. */
static void writeOutput(const QJsonObject &o, pki_x509 *cert)
{
	rejectUnknown(o, output_keys, "'output'");
	if (o.contains("cert")) {
		BioByteArray b;
		PEM_write_bio_X509(b, cert->getCert());
		writeFile(o["cert"].toString(), b, false);
	}
	if (o.contains("chain")) {
		BioByteArray b;
		pki_x509 *c = cert, *prev = nullptr;
		while (c && c != prev) {
			PEM_write_bio_X509(b, c->getCert());
			prev = c;
			c = c->getSigner();
		}
		writeFile(o["chain"].toString(), b, false);
	}
	if (o.contains("key")) {
		pki_evp *key = dynamic_cast<pki_evp *>(cert->getRefKey());
		if (!key || key->isPubKey())
			throw errorEx(QObject::tr("No private key for '%1' in "
				"the database").arg(cert->getIntName()));
		EVP_PKEY *pkey = key->decryptKey();
		BioByteArray b;
		PEM_write_bio_PrivateKey(b, pkey, NULL, NULL, 0, NULL, NULL);
		EVP_PKEY_free(pkey);
		writeFile(o["key"].toString(), b, true);
	}
	openssl_error();
}

pki_x509 *cli_certgen(const QString &jsonfile)
{
	QFile file(jsonfile);
	if (!file.open(QIODevice::ReadOnly))
		throw errorEx(QObject::tr("Failed to open '%1'").arg(jsonfile));

	QJsonParseError jerr;
	QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &jerr);
	if (jerr.error != QJsonParseError::NoError || !doc.isObject())
		throw errorEx(QObject::tr("Invalid JSON in '%1': %2")
				.arg(jsonfile).arg(jerr.errorString()));
	QJsonObject job = doc.object();
	rejectUnknown(job, job_keys, jsonfile);

	db_x509 *certs = Database.model<db_x509>();
	pki_x509req *req = NULL;
	pki_x509 *cert = job.contains("renew") ?
		renew(job, certs) : issue(job, certs, &req);

	cert = dynamic_cast<pki_x509 *>(certs->insert(cert));
	if (!cert)
		throw errorEx(QObject::tr("Certificate was not stored"));
	certs->createSuccess(cert);
	certs->markRequestSigned(req, cert);
	if (job.contains("output"))
		writeOutput(job["output"].toObject(), cert);
	return cert;
}
