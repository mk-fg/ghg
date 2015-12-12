ghg
===

Simple GnuPG_ (command-line "gpg" tool, FOSS PGP implementation) replacement for
file encryption, based on python-libnacl_ crypto primitives (`NaCl
crypto_box`_), which doesn't require complex key/trust management stuff and can
use ssh ed25519 keys directly, as well as base64-encoded key strings.

All key management happens by editing YAML_ (with ordered keys for maps) file in
either ``/etc/ghg.yaml`` or ``~/.ghg.yaml``.
Both files are read and merged together (if/when present), with matching keys
from latter overriding ones in the former.

Does not care about gpg-agent and any kind of secret key encryption, email
encryption and authentication (signatures), compression, "web of trust", signing
keys or having images embedded in them - only for file encryption, as mentioned.

Same as with all crypto tools - use at your own risk, manage your trust
carefully and check/audit such stuff for basic sanity, at least.

Is it Certified, Peer-Reviewed or blessed-by-EFF-and-Crypto-Jesus-himself? Hell no.


.. contents::
  :backlinks: none



Usage
-----

ghg.example.yaml::

  core:
    key: mykey # name of the default key to use

  ## pkid_cache can be generated using
  ##  --gen-pkid-cache for decryption speedup with many keys.
  # pkid_cache:

  keys:
    # Hashed to pkid's (if not cached) in the same order, when needed

    ssh-host: ssh-/etc/ssh/ssh_host_ed25519_key # only if accessible
    ssh-user: ssh-~/.ssh/id_ed25519

    mykey: raw64-v81IAezQzuzZQ0e9LQk2eaMRNzTAyxFRAfW-qSK-svQ=
    mykey-on-remote: pub64-mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs=

    backup: link-backup-hostX
    backup-hostX: pub64-DZqKsImH_Rizt38ariDw-jD-E9pXFbNQ38aoyKIIn2k=

    ## Value format is: { ssh | raw64 | pub64 | link }-{spec}
    # mykey-a: raw64-gXNGcNgy22YxBTDb5wK0Cz8zpRNhjrs-aDLanbj22Fs=
    # mykey-b: ssh-~/.ssh/id_ed25519_mykey-b
    # mykey-current: link-mykey-b

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

  % ghg -se -r backup secret-data.txt
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

Some knowledge of how assymetric crypto algos work is assumed on the part of the
user, to understand the basic concepts of "public" and "secret" keys, for example.



Installation
------------

Tool is written in python (2.7, not 3.X) and uses PyYAML_ and python-libnacl_.

On e.g. Arch, for system-wide install, do::

  # pacman -S --needed python2 python2-yaml python2-libnacl
  # install -m755 ghg /usr/local/bin/
  # install -m640 ghg.example.yaml /etc/ghg.yaml

Install for user with pip_::

  % pip install --user pyyaml libnacl
  % install -m755 ghg ~/bin/
  % install -m600 ghg.example.yaml ~/.ghg.yaml

Done!



Crypto details
--------------

Encryption process in pseudocode::

  file_plaintext = input_data
  stable = input_stable_option
  box_dst_pk_list, box_src_sk, box_src_pk = input_key

  enc_magic = '¯\_ʻghgʻ_/¯'
  enc_ver = '1'
  enc_block_size = 4 * 2**20

  if stable:
    nonce_32B = HMAC(
      key = enc_magic,
      msg = file_plaintext,
      digest = sha256 )
    nonce_16B = nonce_32B[:16]

  else:
    nonce_16B = read('/dev/urandom', 16)

  file_checksum = sha256(file_plaintext)

  for box_dst_pk in box_dst_pk_list:

    pkid_b64_8B = base64(blake2b(box_dst_pk)[:6])
    box_src_pk_b64 = base64(box_src_pk)
    nonce_16B_b64 = base64(nonce_16B)

    header = enc_magic || ' ' ||
      enc_ver || ' ' ||
      box_src_pk_b64 || ' ' ||
      nonce_16B_b64 || ' ' ||
      pkid_b64_8B || '\n'

    write(header)

    n = 0
    for chunk_plaintext in break_into_chunks(file_plaintext, enc_block_size):

      chunk_nonce = nonce_16B || uint64_BE(n)
      chunk_ciphertext = crypto_box(chunk_plaintext, chunk_nonce, box_dst_pk, box_src_sk)
      n += 1

      box_header = uint32_BE(length(chunk_ciphertext)) ||
        uint32_BE(length(chunk_plaintext))

      write(box_header)
      write(chunk_ciphertext)

    chunk_nonce = nonce_16B || uint64_BE(n)
    checksum_ciphertext = crypto_box(file_checksum, chunk_nonce, box_dst_pk, box_src_sk)

    box_header_last = uint32_BE(length(checksum_ciphertext)) || uint32_BE(0)

    write(box_header_last)
    write(checksum_ciphertext)

"crypto_box()" corresponds to `NaCl crypto_box`_ routine (with python-libnacl
wrapper), which is a combination of Salsa20 stream cipher and and Poly1305
authenticatior in one easy-to-use and secure package, implemented and maintained
by very smart and skilled people (djb being the main author).

Nonce is only derived from plaintext hash if --stable option is specified,
which should exclude possibility of reuse for different plaintexts,
yet provide deterministic output for the same file, otherwise is random.

"enc_ver" is encoded into "header" lines in case encryption algorithm might
change in the future.

Weird "enc_magic" unicode stuff in the "header" is an arbitrary magic string to
be able to easily and kinda-reliably tell if file is encrypted by the presence
of that.

When decrypting file using bunch of available (configured) keys, each "header"
line gets checked for "pkid" match to one of the keys, with non-matching
ciphertext blocks (encrypted for a unavailable key) skipped.

"file_checksum" is not strictly necessary with AEAD that crypto_box provides,
but added to make sure that code doesn't mess up merging chunks' plaintexts in
any way.

Unlike gpg, this tool explicitly doesn't do compression, which can be applied
before encryption manually (encypted data is pretty much incompressible), but do
keep in mind that it inevitably leaks information about plaintext, which is
especially bad if attacker has control over any part of it (see attacks against
compression in TLS for examples).



Links
-----

- `libsodium/issues/141 <https://github.com/jedisct1/libsodium/issues/141>`_

  Lots of great info and links on how to use e.g. crypto_box to encrypt a
  stream.

- `Adam Langley's "Encrypting Streams" blog post
  <https://www.imperialviolet.org/2014/06/27/streamingencryption.html>`_

  Mentions `draft-mcgrew-aero-01 <https://tools.ietf.org/html/draft-mcgrew-aero-01>`_
  as a particular example of a good format, though unnecessary complicated in
  this case.

- `kaepora/miniLock <https://github.com/kaepora/miniLock>`_

  Similar tool in JS with much more exposure to public scrutiny.



.. _GnuPG: https://www.gnupg.org/
.. _python-libnacl: https://libnacl.readthedocs.org/
.. _NaCl crypto_box: http://nacl.cr.yp.to/box.html
.. _YAML: https://en.wikipedia.org/wiki/YAML
.. _PyYAML: http://pyyaml.org/
.. _pip: https://pip.pypa.io/
