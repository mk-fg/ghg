ghg
===

Simple GnuPG_ replacement for file encryption, based on python-libnacl_ crypto
primitives (`NaCl crypto_box`_), which doesn't require complex key/trust
management stuff and can use ssh ed25519 keys directly, as well as
base64-encoded key strings.

All key management happens by editing YAML (with ordered keys for maps) file in
either ``/etc/ghg.yaml`` or ``~/.ghg.yaml``.
Both files are read and merged together (if/when present), with matching keys
from latter overriding ones in the former.

ghg.yaml example::

  core:
    key: mykey # name of the default key to use

  ## pkid_cache can be generated using
  ##  --gen-pkid-cache for decryption speedup with many keys.
  # pkid_cache:

  keys:
    # Hashed to pkid's (if not cached) in the same order, when needed

    ssh-host: ssh-/etc/ssh/ssh_host_ed25519_key
    ssh-user: ssh-~/.ssh/id_ed25519

    mykey: raw64-v81IAezQzuzZQ0e9LQk2eaMRNzTAyxFRAfW-qSK-svQ=
    mykey-on-remote: pub64-mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs=

    ## Value format is: { ssh | raw64 | pub64 }-{spec}
    # mykey-a: raw64-gXNGcNgy22YxBTDb5wK0Cz8zpRNhjrs-aDLanbj22Fs=
    # mykey-b: ssh-~/.ssh/id_ed25519_mykey-b

Usage::

  % ghg -e secret-data.txt
  % ghg -d secret-data.txt.ghg
  ## Works same as gpg, replacing source files, but with .ghg suffix

  % ghg -e -r mykey-remote -r ssh-user secret-data.txt
  ## Resulting file will be decryptable with any of the specified keys

  % ghg -e -r pub64-mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs= secret-data.txt
  ## Public keys are allowed on the command-line, with same format as in config

  % ls -lah /bin/blender
  -rwxr-xr-x 1 root root 55M Nov  4 17:10 /bin/blender
  % ghg </bin/blender >blender.ghg
  ## Encrypting huge files should be fine (chunked), stdin/stdout work too
  ## If neither -e/-d are specified, direction is auto-detected from file magic

  % ghg -se secret-data.txt
  ## -s/--stable uses hmac-sha256 of the plaintext as nonce

  % ghg -p mykey
  pub64-mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs=
  ## Print pubkey (in "pub64-..." format) for specified secret key

  % ghg -g
  raw64-GfJUQ51_BwWtaqZknIX0Lh129hh_T3eDKzpx3RwV77c=
  ## Generate and print new secret key

  % ghg -h
  ...
  ## See output for all the other options

Same as with all crypto tools - use at your own risk, manage your trust
carefully and check/audit such stuff for at least basic sanity.

Uses PyYAML_ and python-libnacl_.

.. _GnuPG: https://www.gnupg.org/
.. _python-libnacl: https://libnacl.readthedocs.org/
.. _NaCl crypto_box: http://nacl.cr.yp.to/box.html
.. _PyYAML: http://pyyaml.org/
