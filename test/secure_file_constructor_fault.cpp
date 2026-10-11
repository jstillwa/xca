/* Synthetic fault injection against the linked production staged_file.
 * GNU ld wraps only this test executable's Win32 imports; no hooks are
 * installed in xca or in the rest of the test suite. */
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTest>

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <cstring>

#include "lib/exception.h"
#include "lib/secure_file.h"

namespace {
const char marker[] = "synthetic-non-secret-constructor-fault";
enum class Failure { shortWrite, flush };
struct Injection {
	bool active = false;
	Failure failure = Failure::shortWrite;
	QString dir;
	QString dest;
	HANDLE handle = nullptr;
	bool wroteBytes = false;
	bool changedAcl = false;
	bool handleRepairWorked = false;
} injection;

bool setDacl(HANDLE handle, const wchar_t *sddl)
{
	PSECURITY_DESCRIPTOR sd = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
			sddl, SDDL_REVISION_1, &sd, nullptr))
		return false;
	BOOL present = FALSE, defaulted = FALSE;
	PACL dacl = nullptr;
	bool ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) &&
		present && dacl &&
		SetSecurityInfo(handle, SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
			nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
	LocalFree(sd);
	return ok;
}

void corruptAfterWrite(HANDLE handle)
{
	/* Prove WRITE_DAC on the still-open production handle can repair the
	 * same inode, then leave it permissive for the failure cleanup path. */
	const QStringList files = QDir(injection.dir).entryList(
		{ "synthetic.key.*.tmp" }, QDir::Files);
	if (files.size() != 1)
		return;
	const QString tmp = QDir(injection.dir).filePath(files.first());
	injection.changedAcl = setDacl(handle, L"D:P(A;;FA;;;WD)") &&
		!is_owner_only_file(tmp);
	if (!injection.changedAcl)
		return;
	injection.handleRepairWorked = setDacl(handle, L"D:P(A;;FA;;;OW)") &&
		is_owner_only_file(tmp);
	if (injection.handleRepairWorked)
		injection.changedAcl = setDacl(handle, L"D:P(A;;FA;;;WD)") &&
		!is_owner_only_file(tmp);
}
} // namespace

/* The production object imports __imp_WriteFile etc. through libxcalib.a;
 * wrapping the import pointer, not the API function, intercepts that call. */
extern "C" {
extern decltype(&WriteFile) __real___imp_WriteFile;
extern decltype(&FlushFileBuffers) __real___imp_FlushFileBuffers;
extern decltype(&DeleteFileW) __real___imp_DeleteFileW;

decltype(&WriteFile) __wrap___imp_WriteFile =
	[](HANDLE h, LPCVOID bytes, DWORD length, LPDWORD written, LPOVERLAPPED ov) -> BOOL {
		if (!injection.active || length != sizeof(marker) - 1 ||
			std::memcmp(bytes, marker, sizeof(marker) - 1) != 0)
			return __real___imp_WriteFile(h, bytes, length, written, ov);
		injection.handle = h;
		DWORD requested = injection.failure == Failure::shortWrite ? length / 2 : length;
		BOOL ok = __real___imp_WriteFile(h, bytes, requested, written, ov);
		injection.wroteBytes = ok && *written == requested && requested > 0;
		if (injection.wroteBytes && injection.failure == Failure::shortWrite)
			corruptAfterWrite(h);
		return ok;
	};

decltype(&FlushFileBuffers) __wrap___imp_FlushFileBuffers =
	[](HANDLE h) -> BOOL {
		if (!injection.active || injection.failure != Failure::flush ||
			h != injection.handle)
			return __real___imp_FlushFileBuffers(h);
		corruptAfterWrite(h);
		SetLastError(ERROR_WRITE_FAULT);
		return FALSE;
	};

decltype(&DeleteFileW) __wrap___imp_DeleteFileW =
	[](LPCWSTR path) -> BOOL {
		QString name = QDir::fromNativeSeparators(QString::fromWCharArray(path));
		if (injection.active && name.startsWith(injection.dest + '.') &&
			name.endsWith(".tmp")) {
			SetLastError(ERROR_ACCESS_DENIED);
			return FALSE;
		}
		return __real___imp_DeleteFileW(path);
	};
} // extern "C"

class SecureFileConstructorFault : public QObject
{
	Q_OBJECT
private slots:
	void failure_data()
	{
		QTest::addColumn<bool>("flushFailure");
		QTest::newRow("short-WriteFile") << false;
		QTest::newRow("failed-FlushFileBuffers") << true;
	}
	void failure()
	{
		QFETCH(bool, flushFailure);
		QTemporaryDir dir;
		QVERIFY(dir.isValid());
		const QString dest = dir.filePath("synthetic.key");

		/* Positive control: the same production path works without injection. */
		write_owner_only_file(dest, marker);
		QVERIFY(is_owner_only_file(dest));
		QVERIFY(QFile::remove(dest));

		injection = {};
		injection.active = true;
		injection.failure = flushFailure ? Failure::flush : Failure::shortWrite;
		injection.dir = dir.path();
		injection.dest = dest;
		bool threw = false;
		try {
			staged_file file(dest, marker, true);
		} catch (const errorEx &) {
			threw = true;
		}
		injection.active = false;
		QVERIFY2(injection.wroteBytes, "fault did not follow a real nonempty WriteFile");
		QVERIFY2(injection.changedAcl, "fault did not leave a permissive ACL before cleanup");
		QVERIFY2(injection.handleRepairWorked,
			"test control: owner-only ACL could not be restored on the open handle");
		QVERIFY2(threw, "constructor did not reject the injected I/O failure");
		QVERIFY2(!QFile::exists(dest), "constructor failure published a destination");
		const QStringList files = QDir(dir.path()).entryList(
			{ "synthetic.key.*.tmp" }, QDir::Files);
		for (const QString &file : files) {
			QFile staged(dir.filePath(file));
			QVERIFY(staged.open(QIODevice::ReadOnly));
			QVERIFY2(staged.readAll().startsWith("synthetic"),
				"fault left a temp file, but not the written synthetic bytes");
			QVERIFY2(is_owner_only_file(dir.filePath(file)),
				"constructor failure left synthetic key bytes with an insecure ACL");
		}
	}
};

QTEST_GUILESS_MAIN(SecureFileConstructorFault)
#include "secure_file_constructor_fault.moc"
