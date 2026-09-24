/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2025 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CLI_SIGN_H
#define __CLI_SIGN_H

#include <QString>

class pki_x509;

/* Issue or renew a certificate from a JSON job file and store it
 * in the open database. Throws errorEx on failure. */
pki_x509 *cli_certgen(const QString &jsonfile);

#endif
