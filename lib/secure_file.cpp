/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2025 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QAtomicInt>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include "secure_file.h"
#include "exception.h"

/* windows.h is kept out of every header: its macros (X509_NAME and
 * others) collide with OpenSSL declarations. */
#if defined(Q_OS_WIN32)
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#else
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#endif

static errorEx fileError(const QString &what, const QString &path)
{
	return errorEx(QObject::tr("%1 '%2'").arg(what).arg(path));
}

/* Unique within the process and across processes: pid plus a counter.
 * The file is created exclusively, so a leftover or planted file with the
 * same name makes the write fail instead of being reused. */
static QString tempName(const QString &dest)
{
	static QAtomicInt counter;
	return QString("%1.%2.%3.tmp").arg(dest)
		.arg(QCoreApplication::applicationPid())
		.arg(counter.fetchAndAddRelaxed(1));
}

#if defined(Q_OS_WIN32)

static std::wstring native(const QString &path)
{
	return QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath())
		.toStdWString();
}

staged_file::staged_file(const QString &path, const QByteArray &data,
			bool secret)
	: dest(path), tmp(tempName(path)), owner_only(secret)
{
	/* D:P = protected DACL (no inheritance); one ACE granting full
	 * access to OWNER RIGHTS (OW), which resolves to the file's owner. */
	PSECURITY_DESCRIPTOR sd = NULL;
	if (owner_only && !ConvertStringSecurityDescriptorToSecurityDescriptorW(
			L"D:P(A;;FA;;;OW)", SDDL_REVISION_1, &sd, NULL))
		throw fileError(QObject::tr("Cannot build an owner-only ACL for"),
				path);
	SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };

	HANDLE h = CreateFileW(native(tmp).c_str(), GENERIC_WRITE, 0,
				owner_only ? &sa : NULL, CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL, NULL);
	if (sd)
		LocalFree(sd);
	if (h == INVALID_HANDLE_VALUE)
		throw fileError(QObject::tr("Cannot create"), path);

	DWORD written = 0;
	bool ok = WriteFile(h, data.constData(), (DWORD)data.size(),
				&written, NULL) && written == (DWORD)data.size() &&
			FlushFileBuffers(h);
	CloseHandle(h);
	if (!ok) {
		DeleteFileW(native(tmp).c_str());
		throw fileError(QObject::tr("Short write to"), path);
	}
}

staged_file::~staged_file()
{
	if (!done)
		DeleteFileW(native(tmp).c_str());
}

void staged_file::commit()
{
	if (!MoveFileExW(native(tmp).c_str(), native(dest).c_str(),
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		throw fileError(QObject::tr("Cannot replace"), dest);
	done = true;
	if (owner_only && !is_owner_only_file(dest))
		throw fileError(QObject::tr("Owner-only ACL did not apply to"), dest);
}

/* An access-allowed ACE is owner-only when it names the file's owner or
 * the OWNER RIGHTS SID (S-1-3-4), which the system resolves to whoever
 * owns the file. */
static bool ownerSid(PSID sid, PSID owner)
{
	BYTE buf[SECURITY_MAX_SID_SIZE];
	DWORD len = sizeof(buf);
	if (EqualSid(sid, owner))
		return true;
	return CreateWellKnownSid(WinCreatorOwnerRightsSid, NULL, buf, &len) &&
		EqualSid(sid, (PSID)buf);
}

bool is_owner_only_file(const QString &path)
{
	PSID owner = NULL;
	PACL dacl = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	if (GetNamedSecurityInfoW(native(path).c_str(), SE_FILE_OBJECT,
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			&owner, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS)
		return false;
	SECURITY_DESCRIPTOR_CONTROL ctl = 0;
	DWORD rev = 0;
	/* A NULL DACL grants everyone full access. */
	bool ok = dacl && GetSecurityDescriptorControl(sd, &ctl, &rev) &&
		(ctl & SE_DACL_PROTECTED);
	for (DWORD i = 0; ok && i < dacl->AceCount; i++) {
		ACE_HEADER *h;
		if (!GetAce(dacl, i, (LPVOID *)&h))
			ok = false;
		else if (h->AceType == ACCESS_ALLOWED_ACE_TYPE)
			ok = ownerSid(&((ACCESS_ALLOWED_ACE *)h)->SidStart, owner);
		else if (h->AceType != ACCESS_DENIED_ACE_TYPE)
			ok = false;       /* unknown or object ACE: refuse */
	}
	LocalFree(sd);
	return ok;
}

#else

staged_file::staged_file(const QString &path, const QByteArray &data,
			bool secret)
	: dest(path), tmp(tempName(path)), owner_only(secret)
{
	/* The mode is set at creation: an owner-only file is never readable
	 * by others, not even while empty. Other files get 0666 & ~umask. */
	QByteArray t = QFile::encodeName(tmp);
	int fd = ::open(t.constData(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
			owner_only ? 0600 : 0666);
	if (fd < 0)
		throw fileError(QObject::tr("Cannot create"), path);
	const char *p = data.constData();
	qint64 left = data.size();
	while (left > 0) {
		ssize_t n = ::write(fd, p, left);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		p += n;
		left -= n;
	}
	bool ok = left == 0 && ::fsync(fd) == 0;
	if (::close(fd) != 0)
		ok = false;
	if (!ok) {
		::unlink(t.constData());
		throw fileError(QObject::tr("Short write to"), path);
	}
}

staged_file::~staged_file()
{
	if (!done)
		::unlink(QFile::encodeName(tmp).constData());
}

void staged_file::commit()
{
	if (::rename(QFile::encodeName(tmp).constData(),
			QFile::encodeName(dest).constData()) != 0)
		throw fileError(QObject::tr("Cannot replace"), dest);
	done = true;
	if (owner_only && !is_owner_only_file(dest))
		throw fileError(QObject::tr("Owner-only permissions did not apply to"),
				dest);
}

bool is_owner_only_file(const QString &path)
{
	QFile::Permissions p = QFile::permissions(path);
	return p != QFile::Permissions() &&
		!(p & (QFile::ReadGroup | QFile::WriteGroup | QFile::ExeGroup |
		       QFile::ReadOther | QFile::WriteOther | QFile::ExeOther));
}

#endif

void write_owner_only_file(const QString &path, const QByteArray &data)
{
	staged_file f(path, data, true);
	f.commit();
}

void write_file_atomic(const QString &path, const QByteArray &data)
{
	staged_file f(path, data, false);
	f.commit();
}
