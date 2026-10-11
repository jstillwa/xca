/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2025 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __SECURE_FILE_H
#define __SECURE_FILE_H

#include <QByteArray>
#include <QString>

/* A file written in two steps. The constructor writes the data to a new,
 * uniquely named temporary file beside the destination and throws errorEx
 * on any short write. commit() renames it over the destination. A staged
 * file that is never committed is deleted by the destructor, so a caller
 * can prepare several outputs and publish them only after everything
 * else has succeeded.
 *
 * With owner_only, the temporary file is created readable by the current
 * user only (mode 0600; on Windows a protected DACL granting OWNER RIGHTS
 * only, so ACEs inherited from the folder never apply). The empty file
 * is checked before writing, and commit() checks the staged permissions
 * again before replacing and verifies the published file. The open file
 * handle remains available to restore its permissions if that last check
 * fails. Renaming replaces an existing destination instead of reusing its
 * permissions. */
class staged_file
{
  public:
	staged_file(const QString &path, const QByteArray &data, bool owner_only);
	~staged_file();
	void commit();
	staged_file(const staged_file &) = delete;
	staged_file &operator=(const staged_file &) = delete;

  private:
	QString dest{}, tmp{};
	bool owner_only{}, done{};
#if defined(Q_OS_WIN32)
	void *file_handle{};
#else
	int file_descriptor{-1};
#endif
};

/* Stage and commit in one call. */
void write_owner_only_file(const QString &path, const QByteArray &data);
void write_file_atomic(const QString &path, const QByteArray &data);

/* True when path is readable by its owner only: on Windows, a protected
 * DACL whose access-allowed entries all name the owner or OWNER RIGHTS;
 * elsewhere, no group or other permission bits. */
bool is_owner_only_file(const QString &path);

#endif
