ghg
===

Simple command-line NaCl/libsodium file encryption tool.

Intended to be a replacement for GnuPG_ file encryption mode (as in command-line
"gpg" tool), based on modern libsodium_ crypto primitives like `NaCl crypto_box`_ and
secretstream_xchacha20poly1305, instead of an old/brittle/clunky ElGamal and AES-based stuff.

Allows for an easy and efficient one-way file/pipe encryption from private to public
keys, and having lists of these, using any matching local private key(s) for decryption.

Uses short base64-encoded ed25519 public/private key strings.

Doesn't require complex key/trust management stuff, which is more direct and manual here,
through options or editing very simple YAML-like text file in ``/etc/ghg.yamlx`` (or path
specified via ``-c/--conf`` option).

It does not have any kind of gpg-agent/ssh-agent like stuff for key passphrases,
not intended for email encryption or authentication (signatures), no compression,
"web of trust", signed keys or having images embedded in them - just easy-to-use
file encryption between public/private keys and some basic key agility, as mentioned.

Same as with all crypto tools - use at your own risk, manage your trust
carefully and check/audit such stuff for basic sanity, at least.

Is it Certified, Peer-Reviewed or blessed-by-EFF-and-Crypto-Jesus-himself? Hell no.

------------

This tool was originally implemented as a python2 script (started in `mk-fg/fgtk repo`_),
which used slightly different file format (which is still supported for decryption
with same keys), actual-YAML config (yuck), and had some extra options like stable encryption,
parsing/using SSH ed25519 keys, etc, which only ended up being an unnecessary complication
for my use-cases.
That old script should be accessible via e.g. `commit c010639 here`_ for whatever legacy purposes.

.. contents::
  :backlinks: none

This repository URLs:

- https://github.com/mk-fg/ghg
- https://codeberg.org/mk-fg/ghg
- https://fraggod.net/code/git/ghg



Usage
-----

With `ghg.example.yamlx <ghg.example.yamlx>`_ config like this::

  -keys: link.workstations
  -keys-dec: link.old-key-2015-12-13 link.old-backup

  workstations:
    link.desktop
    link.laptop
  desktop: sk64.v81IAezQzuzZQ0e9LQk2eaMRNzTAyxFRAfW-qSK-svQ
  laptop: pk64.mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs=

  backup:
    link.backup.storage-hosts
    link.backup.offline-keys
    sk64.M4GuROf3vNLZTAtHcgYPkO7gnC6sPFBSA67-CvV2Fc8=

  backup.storage-hosts: link.backup.hostX link.backup.hostY
  backup.hostX: pk64.DZqKsImH_Rizt38ariDw-jD-E9pXFbNQ38aoyKIIn2k
  backup.hostY: pk64.NUcN-SC6rnqLv37d7I3gYnvBZP_Obb5R8ESifuILhe0=

  backup.offline-keys:
    pk64.PddqJWLx1T-XWD_tnbjb-uWJNgp8muQFK_jHhflGOGo=
    pk64.QIRv0_7ke5H78A-xQTS4FEZKZ4IGeEfAYLoLeGug0B4
    pk64.Mm4H27O739v-pB6WiLCnFHZZcoFqdvyNgCwl3nuZemw=

  old-key-2015-12-13: sk64.gXNGcNgy22YxBTDb5wK0Cz8zpRNhjrs-aDLanbj22Fs=
  old-backup: sk64.VBjFzFE93GtWwUqA4s7s5s_bEy-GW054t9gHPuIevZA=

(`see config file in the repo`_ for comments describing format and all its features)

Here are some usage examples::

  % ghg -h
  ...
  ## Should describe how tool works and all supported options

  % ghg -e secret-data.txt
  % ghg -d secret-data.txt.ghg
  ## Works same as gpg, replacing source files, but with .ghg suffix
  ## -e/-d opts can be dropped - auto-detected from first bytes in a file

  % ghg -e -r some-key-on-remote -r offline-backup-key secret-data.txt
  ## Resulting file will be decryptable only with keys specified with -r

  % ghg -e -r pk64.mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs= secret-data.txt
  ## Public keys are allowed on the command-line, with same format as in config

  % ls -lah /bin/blender
  -rwxr-xr-x 1 root root 55M Nov  4 17:10 /bin/blender
  % ghg </bin/blender >blender.ghg
  ## Encrypting large files should be fine (chunked), stdin/stdout work too
  ## With neither -e/-d are specified, direction is auto-detected from file magic

  % ghg -p my-other-key
  pk64.itMXyr0tmn9HYz95YMPPLNmncE1bXQUnHK4qOco8bRQ
  ## Print pubkey(s) (in "pk64.*" format) for specified/configured private key

  % ghg -g
  sk64.GfJUQ51_BwWtaqZknIX0Lh129hh_T3eDKzpx3RwV77c=
  ## Generate and print new private key

  % ghg -x3 somefile.ghg 3<<< secret-argon2id-passphrase
  ## Decrypt file using a key derived from secret key + extra argon2id passphrase

  % ghg -x3 -k %4 somefile.ghg 3<<< secret-argon2id-passphrase 4<<< sk64.some-key
  ## Same as above, but provide decryption private key via a file descriptor as well

Some general knowledge about how asymetric crypto works is assumed on the part of the user,
such as understanding of basic concepts like public and private keys, for example.



Installation
------------

This is a small OCaml_ cli app with C bindings, which can be built using any
modern (4.13+) ocamlopt compiler and the usual make tool, with libsodium_ on the system::

  % make
  % ./ghg --help
  Usage: ./ghg [opts] [file ...]
  ...

That should produce ~1M binary, linked against libsodium (for actual crypto stuff),
which can then be installed and copied between systems normally.
OCaml compiler is only needed to build the tool, not to run it.

``test.sh`` script (or ``make test``) can be used for a quick sanity-check after code
tweaks, mostly adapted from an earlier script, with a bunch of leftover redundant tests.



Crypto details
--------------

Encryption process in pseudocode::

  file_plaintext = input_data
  stable = input_stable_option
  box_dst_pk_list, box_src_sk, box_src_pk = input_keys
  argon_string, argon_opts = argon_cli_opts

  enc_magic = '¯\_ʻghgʻ_/¯'
  enc_ver = '2'
  enc_header_cap = '-'
  enc_block_size = 16384
  argon_salt = 'ghg.argon2id13.1'

  if argon_string:
    box_src_sk = crypto_pwhash(
      box_src_sk || argon_string, argon_salt, argon_opts )
    box_src_pk = crypto_scalarmult_base(box_src_sk)

  sym_key = random(crypto_secretstream_xchacha20poly1305_KEYBYTES)

  header = enc_magic || ' ' || enc_ver || ' ' || enc_header_cap || '\n'
  write(header)

  for box_dst_pk in box_dst_pk_list:
    box_nonce = random(crypto_box_NONCEBYTES)
    key_slot_ct = crypto_box_easy(sym_key, box_nonce, box_src_sk, box_dst_pk)
    key_slot = urlsafe_base64(box_src_pk || box_nonce || key_slot_ct)
    write(key_slot || '\n')

  write('---\n')

  for chunk_plaintext in break_into_chunks(file_plaintext, enc_block_size):
    chunk_ciphertext = crypto_secretstream_xchacha20poly1305(chunk_plaintext, sym_key)
    write(chunk_ciphertext)

See libsodium_ docs for info on corresponding primitives there.

"enc_ver" is encoded into "header" lines in case encryption algorithm might
change in the future.

Weird "enc_magic" unicode stuff in the "header" is an arbitrary magic string to
be able to easily and kinda-reliably tell if file is encrypted by the presence
of that.

When decrypting file using bunch of available (configured) keys,
crypto_box_open_easy decryption is attempted for each "key_slot" line at the top
using all specified/configured private keys, until any of them works, or exiting
with failure otherwise.

crypto_secretstream_xchacha20poly1305 AEAD encryption should provide both
secrecy and integrity of the plaintext data, with no additional hmac's needed.

Optional Argon2id (1.3) key derivation is performed on the used secret key(s),
if argon options (fd to read passphrase from and difficulty/memory factors)
are specified on the command line, which effectively replaces secret key(s)
being used, with one(s) returned from crypto_pwhash().

Unlike gpg, this tool explicitly doesn't do compression, which can be applied
before encryption manually (encypted data is pretty much incompressible),
but do keep in mind that it inevitably leaks information about plaintext,
which is especially bad if attacker has control over any part of it
(see issues with compression in TLS for examples).



Links
-----

- `age <https://github.com/FiloSottile/age>`_

  More recent tool similar to an older python2 ghg script here, with a lot more
  features than current ghg.ml, but also a lot more unnecessary junk and dependencies.

  Considered migrating to it (or its `rage <https://github.com/str4d/rage>`_ rewrite) myself,
  but couldn't justify extra complexity that involves, and wanted backwards compability with
  the old format of the script here, but those shouldn't apply to new uses, so check it out.

- `minisign <https://jedisct1.github.io/minisign/>`_

  Tool for generating signatures for files/data instead of encryption.

- `Earlier python2 ghg script <https://github.com/mk-fg/ghg/blob/c010639/ghg>`_

  Should only be useful for some legacy purposes.



.. _GnuPG: https://www.gnupg.org/
.. _libsodium: https://libsodium.gitbook.io/
.. _NaCl crypto_box: http://nacl.cr.yp.to/box.html
.. _mk-fg/fgtk repo: https://github.com/mk-fg/fgtk
.. _commit c010639 here: https://github.com/mk-fg/ghg/blob/c010639/ghg
.. _ghg.example.yamlx: ghg.example.yamlx
.. _see config file in the repo: ghg.example.yamlx
.. _OCaml: https://ocaml.org/
