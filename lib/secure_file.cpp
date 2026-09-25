/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2025 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>

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
#include <sys/stat.h>
#endif

static errorEx fileError(const QString &what, const QString &path)
{
	return errorEx(QObject::tr("%1 '%2'").arg(what).arg(path));
}

void write_file_atomic(const QString &path, const QByteArray &data)
{
	QSaveFile f(path);
	if (!f.open(QIODevice::WriteOnly))
		throw fileError(QObject::tr("Cannot write"), path);
	if (f.write(data) != data.size()) {
		f.cancelWriting();
		throw fileError(QObject::tr("Short write to"), path);
	}
	if (!f.commit())
		throw fileError(QObject::tr("Cannot replace"), path);
}

#if defined(Q_OS_WIN32)

static std::wstring native(const QString &path)
{
	return QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath())
		.toStdWString();
}

/* Security descriptor for a new file: owner = current user, DACL
 * protected against inheritance, one ACE granting the owner full
 * control. "OW" is the SDDL owner-rights SID, which resolves to the
 * creating user. */
static PSECURITY_DESCRIPTOR ownerOnlyDescriptor()
{
	PSECURITY_DESCRIPTOR sd = NULL;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
			L"D:P(A;;FA;;;OW)", SDDL_REVISION_1, &sd, NULL))
		return NULL;
	return sd;
}

void write_owner_only_file(const QString &path, const QByteArray &data)
{
	std::wstring dest = native(path);
	/* Unique temporary name in the destination directory: CREATE_NEW
	 * refuses an existing name, so a leftover or planted file cannot be
	 * reused, and rename stays on the same volume. */
	std::wstring tmp = dest + L"." +
		std::to_wstring(GetCurrentProcessId()) + L"." +
		std::to_wstring(GetTickCount64()) + L".tmp";

	PSECURITY_DESCRIPTOR sd = ownerOnlyDescriptor();
	if (!sd)
		throw fileError(QObject::tr("Cannot build an owner-only ACL for"), path);
	SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };

	HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, &sa,
				CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	LocalFree(sd);
	if (h == INVALID_HANDLE_VALUE)
		throw fileError(QObject::tr("Cannot create"), path);

	DWORD written = 0;
	bool ok = WriteFile(h, data.constData(), (DWORD)data.size(),
				&written, NULL) && written == (DWORD)data.size() &&
			FlushFileBuffers(h);
	CloseHandle(h);
	if (!ok) {
		DeleteFileW(tmp.c_str());
		throw fileError(QObject::tr("Short write to"), path);
	}
	/* Rename keeps the temporary file's own protected DACL; an existing
	 * destination with looser permissions is replaced, not reused. */
	if (!MoveFileExW(tmp.c_str(), dest.c_str(),
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		DeleteFileW(tmp.c_str());
		throw fileError(QObject::tr("Cannot replace"), path);
	}
	if (!is_owner_only_file(path))
		throw fileError(QObject::tr("Owner-only ACL did not apply to"), path);
}

/* An access-allowed ACE is owner-only when it names the file's owner
 * or the OWNER RIGHTS SID (S-1-3-4, SDDL "OW"), which the system
 * resolves to whoever owns the file. */
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
	std::wstring w = native(path);
	if (GetNamedSecurityInfoW(w.c_str(), SE_FILE_OBJECT,
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

void write_owner_only_file(const QString &path, const QByteArray &data)
{
	/* QSaveFile creates its temporary file with the process umask;
	 * restrict it before any byte is written. */
	QSaveFile f(path);
	if (!f.open(QIODevice::WriteOnly))
		throw fileError(QObject::tr("Cannot write"), path);
	if (!f.setPermissions(QFile::ReadOwner | QFile::WriteOwner)) {
		f.cancelWriting();
		throw fileError(QObject::tr("Cannot restrict permissions of"), path);
	}
	if (f.write(data) != data.size()) {
		f.cancelWriting();
		throw fileError(QObject::tr("Short write to"), path);
	}
	if (!f.commit())
		throw fileError(QObject::tr("Cannot replace"), path);
	if (!is_owner_only_file(path))
		throw fileError(QObject::tr("Owner-only permissions did not apply to"), path);
}

bool is_owner_only_file(const QString &path)
{
	QFile::Permissions p = QFile::permissions(path);
	return p != QFile::Permissions() &&
		!(p & (QFile::ReadGroup | QFile::WriteGroup | QFile::ExeGroup |
		       QFile::ReadOther | QFile::WriteOther | QFile::ExeOther));
}

#endif
