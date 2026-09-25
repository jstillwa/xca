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

/* Write data to path so that only the current user can read it, and
 * throw errorEx when that cannot be guaranteed. The file is written to a
 * temporary name beside path and renamed over it, so a failed write
 * leaves an existing file untouched. On Windows the new file gets a
 * protected DACL that grants access to its owner only; inherited ACEs
 * from the directory never apply. */
void write_owner_only_file(const QString &path, const QByteArray &data);

/* Write data to path atomically (temporary file plus rename), with
 * default permissions. Throws errorEx on any short write. */
void write_file_atomic(const QString &path, const QByteArray &data);

/* True when path is readable by its owner only: on Windows, a protected
 * DACL whose access-allowed entries all name the owner; elsewhere, no
 * group or other permission bits. */
bool is_owner_only_file(const QString &path);

#endif
