/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs11_lib.h"
#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"
#include "db_base.h"
#include "func.h"
#include "pass_info.h"
#include "Passwd.h"
#include "entropy.h"

#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <QThread>

#include "PwDialogCore.h"
#include "XcaWarningCore.h"

#pragma message ("split PwDialog into console and GUI")
#include "ui_SelectToken.h"
#include <QPushButton>

void waitcursor(int start, int line)
{
	qDebug() << "Waitcursor" << (start ? "start" : "end") << line;
	ign_openssl_error();
	if (!IS_GUI_APP)
		return;
	if (start)
		QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	else
		QApplication::restoreOverrideCursor();
}

pkcs11_lib_list pkcs11::libraries;
int pkcs11::pctr;

pkcs11::pkcs11()
{
	session = CK_INVALID_HANDLE;
	p11obj = CK_INVALID_HANDLE;
	qDebug() << "PKCS11 Counter"<< ++pctr;
}

pkcs11::~pkcs11()
{
	try { closeSession(p11slot); } catch ( ... ) { }
	qDebug() << "PKCS11 Counter"<< --pctr;
}

void pkcs11::closeSession(const slotid &slot)
{
	if (session != CK_INVALID_HANDLE && slot.p11()) {
		CK_RV rv;
		CALL_P11_C(p11slot.lib, C_CloseSession, session);
		if (rv != CKR_OK)
			pk11error(slot, "C_CloseSession", rv);
	}
	session = CK_INVALID_HANDLE;
}

void pkcs11::startSession(const slotid &slot, bool rw)
{
	CK_RV rv;
	unsigned long flags = CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0);

	closeSession(slot);

	CALL_P11_C(slot.lib, C_OpenSession,
			slot.id, flags, NULL, NULL, &session);
	if (rv != CKR_OK)
		pk11error(slot, "C_OpenSession", rv);
	p11slot = slot;
}

void pkcs11::getRandom()
{
	CK_BYTE buf[64];
	CK_ULONG len = sizeof buf;
	CK_RV rv;

	if (Entropy::get(buf, len)) {
		CALL_P11_C(p11slot.lib, C_SeedRandom, session, buf, len);
	}
	CALL_P11_C(p11slot.lib, C_GenerateRandom, session, buf, len);
	if (rv == CKR_OK)
		Entropy::add_buf(buf, len);
	else
		qDebug("C_GenerateRandom: %s", pk11errorString(rv));
}

QList<CK_MECHANISM_TYPE> pkcs11::mechanismList(const slotid &slot)
{
	CK_RV rv;
	CK_MECHANISM_TYPE *m;
	QList<CK_MECHANISM_TYPE> ml;
	unsigned long count;

	CALL_P11_C(slot.lib, C_GetMechanismList, slot.id, NULL, &count);
	if (count != 0) {
		m = (CK_MECHANISM_TYPE *)malloc(count *sizeof(*m));
		Q_CHECK_PTR(m);

		CALL_P11_C(slot.lib, C_GetMechanismList, slot.id, m, &count);
		if (rv != CKR_OK) {
			free(m);
			pk11error(slot, "C_GetMechanismList", rv);
		}
		for (unsigned i=0; i<count; i++) {
			ml << m[i];
		}
		free(m);
	}
	return ml;
}

void pkcs11::mechanismInfo(const slotid &slot, CK_MECHANISM_TYPE m,
						CK_MECHANISM_INFO *info)
{
	CK_RV rv;
	CALL_P11_C(slot.lib, C_GetMechanismInfo, slot.id, m, info);
	if (rv != CKR_OK) {
		pk11error(slot, "C_GetMechanismInfo", rv);
	}
}

void pkcs11::logout()
{
	CK_RV rv;
	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_Logout, session);
	if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN)
		pk11error("C_Logout", rv);
}

bool pkcs11::needsLogin(bool so)
{
	CK_SESSION_INFO sinfo;
	CK_RV rv;

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_GetSessionInfo, session, &sinfo);
	if (rv != CKR_OK)
		pk11error("C_GetSessionInfo", rv);

	switch (sinfo.state) {
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RW_PUBLIC_SESSION:
		return true;
	case CKS_RW_SO_FUNCTIONS:
		if (so) {
			return false;
		} else {
			logout();
			return true;
		}
	case CKS_RO_USER_FUNCTIONS:
	case CKS_RW_USER_FUNCTIONS:
		if (!so) {
			return false;
		} else {
			logout();
			return true;
		}
	}
	return true;
}

void pkcs11::login(unsigned char *pin, unsigned long pinlen, bool so)
{
	unsigned long user = so ? CKU_SO : CKU_USER;
	CK_RV rv;

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_Login, session, user, pin, pinlen);
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
		pk11error("C_Login", rv);
}

class pinPadLoginThread: public QThread
{
	bool so;
	pkcs11 *p11;
    public:
	errorEx err;
	pinPadLoginThread(pkcs11 *_p11, bool _so) : QThread()
	{
		so = _so;
		p11 = _p11;
	}
	void run()
	{
		try {
			p11->login(NULL, 0, so);
		} catch (errorEx &e) {
			err = e;
		}
	}
};

static QDialog *newPinPadBox()
{
	QDialog *box = new QDialog(NULL, Qt::WindowStaysOnTopHint);
	box->setWindowTitle(XCA_TITLE);
	QHBoxLayout *h = new QHBoxLayout(box);
	QLabel *l = new QLabel();
	l->setPixmap(QPixmap(":scardImg"));
	l->setMaximumSize(QSize(95, 40));
	l->setScaledContents(true);
	h->addWidget(l);
	l = new QLabel(QObject::tr("Please enter the PIN on the PinPad"));
	h->addWidget(l);
	return box;
}

bool pkcs11::tokenLoginForModification()
{
	 tkInfo ti = tokenInfo();
	 return !tokenLogin(ti.label(), ti.need_SO_for_object_mod()).isNull();
}

QString pkcs11::tokenLogin(const QString &name, bool so, bool force)
{
	Passwd pin;
	bool need_login;

	QString text = so ?
		QObject::tr("Please enter the SO PIN (PUK) of the token %1"):
		QObject::tr("Please enter the PIN of the token %1");

	pass_info p(XCA_TITLE, text.arg(name));
	p.setPin();
	need_login = needsLogin(so);
	if (force || need_login) {
		if (!need_login)
			logout();
		if (tokenInfo().protAuthPath()) {
			pin = ""; // Indicate success
			QDialog *pinpadbox = newPinPadBox();
			pinpadbox->show();
			pinPadLoginThread ppt(this, so);
			ppt.start();
			while(!ppt.wait(20)) {
				qApp->processEvents();
				pinpadbox->raise();
			}
			delete pinpadbox;
			if (!ppt.err.isEmpty())
				throw errorEx(ppt.err);
		} else {
			if (PwDialogCore::execute(&p, &pin, false) != 1)
				return QString();
			login(pin.constUchar(), pin.size(), so);
		}
	} else {
		return QString("");
	}
	return QString(pin);
}

bool pkcs11::selectToken(slotid *slot, QWidget *w)
{
	slotidList p11_slots = getSlotList();

	QStringList slotnames;
	QList<int> slotsWithToken;

	for (int i = 0; i < p11_slots.count(); i++) {
		try {
			tkInfo info;
			CK_RV rv = tokenInfo(p11_slots[i], &info);
			if (rv == CKR_TOKEN_NOT_PRESENT)
				continue;
			slotsWithToken.append(i);
			slotnames << QString("%1 (#%2)").
				arg(info.label()).arg(info.serial());
		} catch (errorEx &e) {
			XCA_WARN(QString("Error: %1").arg(e.getString()));
		}
	}
	switch (slotnames.count()) {
	case 0:
		XCA_WARN(QObject::tr("No Security token found"));
		return false;
	case 1:
		*slot = p11_slots[slotsWithToken[0]];
		return true;
	}
	Ui::SelectToken ui;
	QDialog *select_slot = new QDialog(w);
	ui.setupUi(select_slot);
	ui.image->setPixmap(QPixmap(":scardImg"));
	ui.tokenBox->addItems(slotnames);
	ui.buttonBox->button(QDialogButtonBox::Ok)->setText(QObject::tr("Select"));
	select_slot->setWindowTitle(XCA_TITLE);
	if (select_slot->exec() == 0) {
		delete select_slot;
		return false;
	}
	int selected = ui.tokenBox->currentIndex();
	*slot = p11_slots[slotsWithToken[selected]];
	delete select_slot;
	return true;
}

void pkcs11::setPin(unsigned char *oldPin, unsigned long oldPinLen,
	    unsigned char *pin, unsigned long pinLen)
{
	CK_RV rv;
	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_SetPIN, session,
			oldPin, oldPinLen, pin, pinLen);
	if (rv != CKR_OK)
		pk11error("C_SetPIN", rv);
}

static QString newSoPinTxt = QObject::tr(
		"Please enter the new SO PIN (PUK) for the token: '%1'");
static QString newPinTxt = QObject::tr(
		"Please enter the new PIN for the token: '%1'");

void pkcs11::changePin(const slotid &slot, bool so)
{
	Passwd newPin, pinp;
	QString pin;

	startSession(slot, true);
	tkInfo ti = tokenInfo();

	if (ti.protAuthPath()) {
		setPin(NULL, 0, NULL, 0);
		return;
	}

	pin = tokenLogin(ti.label(), so, true);
	if (pin.isNull())
		return;

	QString msg = so ? newSoPinTxt : newPinTxt;
	pass_info p(XCA_TITLE, msg.arg(ti.label()) + "\n" + ti.pinInfo());
	p.setPin();

	if (PwDialogCore::execute(&p, &newPin, true) == 1) {
		pinp = pin.toLatin1();
		setPin(pinp.constUchar(), pinp.size(),
			newPin.constUchar(), newPin.size());
	}
	logout();
}

void pkcs11::initPin(const slotid &slot)
{
	Passwd newPin, pinp;
	int ret = 1;

	startSession(slot, true);
	tkInfo ti = tokenInfo();

	if (tokenLogin(ti.label(), true, false).isNull())
		return;

	pass_info p(XCA_TITLE, newPinTxt.arg(ti.label()) + "\n" + ti.pinInfo());
	p.setPin();

	if (!ti.protAuthPath()) {
		ret = PwDialogCore::execute(&p, &newPin, true);
		pinp = newPin;
	}
	p11slot.isValid();
	if (ret == 1) {
		CK_RV rv;
		CALL_P11_C(p11slot.lib, C_InitPIN, session,
				pinp.constUchar(), pinp.size());
		if (rv != CKR_OK)
			pk11error("C_InitPIN", rv);
	}
	logout();
}

void pkcs11::initToken(const slotid &slot, unsigned char *pin, int pinlen,
		QString label)
{
	CK_RV rv;
	unsigned char clabel[32];
	QByteArray ba = label.toUtf8().left(32);
	memset(clabel, ' ', 32);
	memcpy(clabel, ba.constData(), ba.size());

	CALL_P11_C(slot.lib, C_InitToken, slot.id, pin, pinlen, clabel);
	if (rv != CKR_OK)
		pk11error(slot, "C_InitToken", rv);
}

tkInfo pkcs11::tokenInfo(const slotid &slot) const
{
	tkInfo ti;
	CK_RV rv = tokenInfo(slot, &ti);

	if (rv != CKR_OK) {
		pk11error(slot, "C_GetTokenInfo", rv);
	}
	return ti;
}

CK_RV pkcs11::tokenInfo(const slotid &slot, tkInfo *tkinfo) const
{
	CK_TOKEN_INFO token_info;
	CK_RV rv;

	CALL_P11_C(slot.lib, C_GetTokenInfo, slot.id, &token_info);
	if (rv == CKR_OK)
		tkinfo->set(&token_info);
	return rv;
}

void pkcs11::loadAttribute(pk11_attribute &attribute, CK_OBJECT_HANDLE object)
{
	p11slot.isValid();
	attribute.load(p11slot, session, object);
}

void pkcs11::storeAttribute(pk11_attribute &attribute, CK_OBJECT_HANDLE object)
{
	p11slot.isValid();
	attribute.store(p11slot, session, object);
}

CK_OBJECT_HANDLE pkcs11::createObject(pk11_attlist &attrs)
{
	CK_RV rv;
	CK_OBJECT_HANDLE obj;

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_CreateObject, session,
			attrs.getAttributes(), attrs.length(), &obj);
	if (rv != CKR_OK) {
		pk11error("C_CreateObject", rv);
	}
	return obj;
}

int pkcs11::deleteObjects(QList<CK_OBJECT_HANDLE> objects)
{
	CK_RV rv;

	p11slot.isValid();
	for (int i=0; i< objects.count(); i++) {
		CALL_P11_C(p11slot.lib, C_DestroyObject, session, objects[i]);
		if (rv != CKR_OK) {
			pk11error("C_DestroyObject", rv);
		}
	}
	return objects.count();
}

#define ID_LEN 8
pk11_attr_data pkcs11::findUniqueID(unsigned long oclass) const
{
	pk11_attr_data id(CKA_ID);
	pk11_attr_ulong class_att(CKA_CLASS, oclass);

	while (1) {
		unsigned char buf[ID_LEN];
		pk11_attlist atts(class_att);
		RAND_bytes(buf, ID_LEN);
		id.setValue(buf, ID_LEN);
		atts << id;
		if (objectList(atts).count() == 0)
			break;
	}
	return id;
}

pk11_attr_data pkcs11::generateKey(QString name, unsigned long mech,
				unsigned long bits, int nid, const pk11_attr_data &id)
{
#ifdef OPENSSL_NO_EC
	(void)nid;
#endif
	tkInfo ti = tokenInfo();
	CK_RV rv;
	CK_OBJECT_HANDLE pubkey, privkey, dsa_param_obj;
	pk11_attlist priv_atts, pub_atts, dsa_param;
	CK_MECHANISM mechanism = {mech, NULL_PTR, 0};
	pk11_attr_data label(CKA_LABEL, name.toUtf8());

	pub_atts << label << id <<
		pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY) <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, false) <<
		pk11_attr_bool(CKA_ENCRYPT, true) <<
		pk11_attr_bool(CKA_VERIFY, true) <<
		pk11_attr_bool(CKA_WRAP, true);

	priv_atts << label << id <<
		pk11_attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY) <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, true) <<
		pk11_attr_bool(CKA_SENSITIVE, true) <<
		pk11_attr_bool(CKA_DECRYPT, true) <<
		pk11_attr_bool(CKA_SIGN, true) <<
		pk11_attr_bool(CKA_UNWRAP, true);

	switch (mech) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		pub_atts <<
		pk11_attr_ulong(CKA_MODULUS_BITS, bits) <<
		pk11_attr_data(CKA_PUBLIC_EXPONENT, 0x10001);
		break;
	case CKM_DSA_KEY_PAIR_GEN: {
		//DSA: Spec Page 191 (175) C_GenerateKey
		CK_MECHANISM mechanism = {CKM_DSA_PARAMETER_GEN, NULL_PTR, 0};

		dsa_param << label <<
			pk11_attr_ulong(CKA_CLASS, CKO_DOMAIN_PARAMETERS) <<
			pk11_attr_ulong(CKA_KEY_TYPE, CKK_DSA) <<
			pk11_attr_bool(CKA_TOKEN, !ti.set_token_attr_false_dsa_param()) <<
			pk11_attr_bool(CKA_PRIVATE, false) <<
			pk11_attr_ulong(CKA_PRIME_BITS, bits);
		p11slot.isValid();
		CALL_P11_C(p11slot.lib, C_GenerateKey, session, &mechanism,
			dsa_param.getAttributes(), dsa_param.length(),
			&dsa_param_obj);
		if (rv != CKR_OK)
			pk11error("C_GenerateKey(DSA_PARAMETER)", rv);

		pk11_attr_data p(CKA_PRIME), q(CKA_SUBPRIME), g(CKA_BASE);
		loadAttribute(p, dsa_param_obj);
		loadAttribute(q, dsa_param_obj);
		loadAttribute(g, dsa_param_obj);

		pub_atts << p << q << g;
		break;
	}
#ifndef OPENSSL_NO_EC
	case CKM_EC_KEY_PAIR_GEN: {
		CK_MECHANISM_INFO info;
		mechanismInfo(p11slot, CKM_EC_KEY_PAIR_GEN, &info);

		EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);

		EC_GROUP_set_asn1_flag(group,
			((info.flags & CKF_EC_NAMEDCURVE) || ti.force_keygen_named_curve()) ?
				OPENSSL_EC_NAMED_CURVE : 0);

		priv_atts << pk11_attr_bool(CKA_DERIVE, false);
		pub_atts << pk11_attr_data(CKA_EC_PARAMS,
			i2d_bytearray(I2D_VOID(i2d_ECPKParameters), group));
		EC_GROUP_free(group);
		break;
	}
#endif
	default:
		throw errorEx(("Unsupported Key generation mechanism"));
	}
	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_GenerateKeyPair, session, &mechanism,
		pub_atts.getAttributes(), pub_atts.length(),
		priv_atts.getAttributes(), priv_atts.length(),
		&pubkey, &privkey);
	if (rv != CKR_OK) {
		pk11error("C_GenerateKeyPair", rv);
	}
	return id;
}

QList<CK_OBJECT_HANDLE> pkcs11::objectList(pk11_attlist &atts) const
{
	CK_RV rv;
	CK_OBJECT_HANDLE objects[256];
	QList<CK_OBJECT_HANDLE> list;
	unsigned long len, i, att_num;
	CK_ATTRIBUTE *attribute;

	att_num = atts.get(&attribute);

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_FindObjectsInit, session, attribute, att_num);

	if (rv != CKR_OK)
		pk11error("C_FindObjectsInit", rv);

	do {
		CALL_P11_C(p11slot.lib, C_FindObjects, session,
				objects, 256, &len);
		if (rv != CKR_OK)
			pk11error("C_FindObjects", rv);
		for (i=0; i<len; i++)
			list += objects[i];
	} while (len);

	CALL_P11_C(p11slot.lib, C_FindObjectsFinal, session);
	if (rv != CKR_OK)
		pk11error("C_FindObjectsFinal", rv);

	return list;
}

int pkcs11::decrypt(int flen, const unsigned char *from,
			unsigned char *to, int tolen, unsigned long m)
{
	CK_MECHANISM mech;
	CK_ULONG size = tolen;
	CK_RV rv;

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = m;

	CALL_P11_C(p11slot.lib, C_DecryptInit, session, &mech, p11obj);
	if (rv == CKR_OK)
		CALL_P11_C(p11slot.lib, C_Decrypt, session,
			(CK_BYTE *)from, flen, to, &size);

	if (rv != CKR_OK) {
		qDebug() << "Error: C_Decrypt(init):"
			 << pk11errorString(rv);
		return -1;
	}
	return size;
}

int pkcs11::encrypt(int flen, const unsigned char *from,
	unsigned char *to, int tolen, unsigned long m)
{
	CK_MECHANISM mech;
	CK_ULONG size = tolen;
	CK_RV rv;

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = m;

	CALL_P11_C(p11slot.lib, C_SignInit, session, &mech, p11obj);
	if (rv == CKR_OK)
		CALL_P11_C(p11slot.lib, C_Sign, session,
				(CK_BYTE *)from, flen, to, &size);

	if (rv != CKR_OK) {
		qDebug() << "Error: C_Sign(init):"
			 << pk11errorString(rv);
		return -1;
	}
	return size;
}

#include <openssl/provider.h>
#include <openssl/core_names.h>

// Forward declaration from pkcs11_provider.cpp
extern "C" void *pkcs11_create_sig_ctx(void *provctx, pkcs11 *p11, 
                                       CK_OBJECT_HANDLE obj, EVP_PKEY *pubkey);

EVP_PKEY *pkcs11::getPrivateKey(EVP_PKEY *pub, CK_OBJECT_HANDLE obj)
{
	p11slot.isValid();
	p11obj = obj;
	
	int keytype = EVP_PKEY_id(pub);
	
	// For now, we create a wrapper that will use the old ENGINE-style approach
	// A full provider-based implementation would require more extensive changes
	// to how OpenSSL 3.0 handles custom keys
	
	switch (EVP_PKEY_type(keytype)) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_DSA:
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519:
#endif
#endif
		// Return a reference to the public key
		// The actual signing will be handled by the sig_ctx in the provider
		// when operations are performed
		EVP_PKEY_up_ref(pub);
		return pub;
	}
	
	return nullptr;
}
