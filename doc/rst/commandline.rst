
Commandline
===========

XCA can be used without GUI to analyze PKI items and to generate CRLs and
keys. In this case no X-Server connection is required (Linux)

Arguments
---------

.. include:: arguments.rst

Issuing certificates
--------------------

``--certgen=<json-file>`` issues or renews a certificate without the GUI.
The job file is a JSON object. Unknown keys are rejected.
Items are referenced by their database id (see ``--list-items``) or by
their internal name. An ambiguous name is an error. The command refuses
conditions that the "New certificate" dialog warns about, including missing
mandatory subject fields, insecure hashes, validity outside the issuer's
period and certificates without extensions. Correct the job before retrying;
there is no interactive "Continue rollout" choice.

Issue a new certificate:

.. code-block:: json

  {
    "issuer": "Company AWS Root",
    "key": "*.example.net",
    "template": "TLS_server San Diego",
    "subject": { "CN": "*.example.net" },
    "days": 365,
    "extensions": { "subjectAltName": "DNS:*.example.net" }
  }

issuer
  CA certificate with a private key that signs the new certificate.
key / csr
  Exactly one. ``key`` names a key from the database, or is an object
  ``{ "generate": "RSA:4096" }`` that creates a new key (``RSA:<bits>``,
  ``EC:<curve>`` or ``ED25519``) named like the certificate. ``csr`` signs
  a certificate request; its subject is used and its extensions are copied
  unless ``copy_csr_extensions`` is ``false``.
template
  Optional. Subject, extensions and validity are taken from it, as in the
  "New certificate" dialog.
subject
  Distinguished name entries by short or long name. They replace the same
  entries from the template or request.
name
  Internal name. Defaults to the request name or the most descriptive subject field.
not_before / not_after
  ISO-8601 dates. ``not_before`` defaults to now.
days
  Validity in days, used when ``not_after`` is absent.
hash
  Signature digest, for example ``SHA256``. Defaults to the configured one.
extensions
  OpenSSL extension config values that replace template values:
  ``basicConstraints``, ``subjectKeyIdentifier``, ``authorityKeyIdentifier``,
  ``keyUsage``, ``extendedKeyUsage``, ``subjectAltName``, ``issuerAltName``,
  ``nameConstraints``, ``crlDistributionPoints``, ``authorityInfoAccess``,
  ``nsComment`` and ``advanced`` (an OpenSSL config ``[default]`` section).
  An empty string removes the extension.

Renew an existing certificate, as the "Renewal" dialog does:

.. code-block:: json

  { "renew": "75", "days": 365 }

The subject, key and extensions stay the same. A new serial is used unless
``keep_serial`` is ``true``. Without ``days`` or ``not_after`` the previous
validity period is reused.

The new certificate is stored in the database. Add ``--pem`` to print it.

Both job types accept an ``output`` object that writes files after the
certificate is stored:

cert
  The certificate in PEM format.
chain
  The certificate followed by its issuers up to the root.
key
  The private key, unencrypted PEM, readable by the owner only. On Windows
  the file gets its own access list that grants only its owner access and
  ignores permissions inherited from the folder. The job fails if that
  cannot be applied.

Each file is written to a temporary name and renamed into place, so a failed
staging write leaves an existing file unchanged. Output publication follows
the database commit. If publication fails, the error names the certificate
already stored; inspect it before retrying to avoid issuing a duplicate.
