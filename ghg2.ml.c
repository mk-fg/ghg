// XXX: cleanup includes

#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/callback.h>

#include <sodium.h>


const int enc_bs = 16384; // note: changing requires protocol version bump
const int key_bs = crypto_secretstream_xchacha20poly1305_KEYBYTES;
const int b64_type = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
const int nonce_len = crypto_box_NONCEBYTES;
const int ct_len = key_bs + crypto_box_MACBYTES;

value nacl_init() {
	CAMLparam0();
	CAMLlocal1(v_consts);
	v_consts = caml_alloc_tuple(2);
	if (sodium_init()) caml_failwith("sodium_init failed");

	// Same lengths are used for all keys when parsing, so checked to be same here
	if ( key_bs != crypto_box_PUBLICKEYBYTES || key_bs != crypto_box_SECRETKEYBYTES)
		caml_failwith("unexpected libsodium key length values");

	Store_field(v_consts, 0, Val_int(key_bs));

	CAMLreturn(v_consts);
}

value nacl_b64_to_string(value v_b64, value v_len) {
	// Load base64-string to a string of specified (expected) length
	CAMLparam1(v_b64);
	unsigned char *b64 = String_val(v_b64);
	int bin_len = Int_val(v_len);
	unsigned char bin[bin_len];
	const char *b64_end; size_t bin_len_dec;
	if (sodium_base642bin( bin, bin_len,
			b64, caml_string_length(v_b64),
			NULL, &bin_len_dec, &b64_end, b64_type ))
		caml_failwith("sodium_base642bin failed");
	if (bin_len_dec != bin_len) caml_failwith("length mismatch");
	CAMLreturn(caml_alloc_initialized_string(bin_len, bin));
}

value nacl_string_to_b64(value v_bin) {
	// Return base64-string of a string
	CAMLparam1(v_bin);
	unsigned char *bin = String_val(v_bin);
	int bin_len = caml_string_length(v_bin);
	int b64_len = sodium_base64_encoded_len(bin_len, b64_type);
	unsigned char b64[b64_len];
	sodium_bin2base64(b64, b64_len, bin, bin_len, b64_type);
	CAMLreturn(caml_alloc_initialized_string(b64_len-1, b64));
}

value nacl_key_load(value v_key_b64) {
	// Load base64 key string into a sodium_malloc'ed nativeint pointer
	CAMLparam1(v_key_b64);
	char *err;
	size_t key_b64_len = caml_string_length(v_key_b64);
	unsigned char *key_b64 = String_val(v_key_b64);
	const char *key_b64_end; size_t key_len;
	unsigned char *key = sodium_malloc(key_bs);
	if (sodium_base642bin( key, key_bs,
			key_b64, key_b64_len, NULL, &key_len, &key_b64_end, b64_type ))
		{ err = "sodium_base642bin failed"; goto fail_with_err; }
	if (key_len != key_bs) { err = "key length mismatch"; goto fail_with_err; }
	CAMLreturn(caml_copy_nativeint((intptr_t) key));

	fail_with_err:
	sodium_free(key);
	caml_failwith(err);
}

value nacl_key_free(value v_key) {
	CAMLparam1(v_key);
	sodium_free((unsigned char *) Nativeint_val(v_key));
	CAMLreturn(Val_unit);
}

value nacl_key_sk_to_pk(value v_sk) {
	CAMLparam1(v_sk);
	unsigned char *key_sk = (unsigned char *) Nativeint_val(v_sk);
	unsigned char *key_pk = sodium_malloc(key_bs);
	if (crypto_scalarmult_base(key_pk, key_sk))
		{ sodium_free(key_pk); caml_failwith("crypto_scalarmult_base failed"); }
	CAMLreturn(caml_copy_nativeint((intptr_t) key_pk));
}

value nacl_key_b64(value v_key) {
	CAMLparam1(v_key);
	unsigned char *key = (unsigned char *) Nativeint_val(v_key);
	int key_b64_len = sodium_base64_encoded_len(key_bs, b64_type);
	unsigned char key_b64[key_b64_len];
	sodium_bin2base64(key_b64, key_b64_len, key, key_bs, b64_type);
	CAMLreturn(caml_alloc_initialized_string(key_b64_len-1, key_b64));
}

value nacl_key_hash(value v_key) {
	CAMLparam1(v_key);
	char *err;
	unsigned char *key = (unsigned char *) Nativeint_val(v_key);
	size_t hash_len = crypto_generichash_BYTES;
	unsigned char hash[hash_len];
	if (crypto_generichash(hash, hash_len, key, key_bs, NULL, 0))
		caml_failwith("crypto_generichash failed");
	hash_len = 6;
	int hash_b64_len = sodium_base64_encoded_len(hash_len, b64_type);
	unsigned char hash_b64[hash_b64_len];
	sodium_bin2base64(hash_b64, hash_b64_len, hash, hash_len, b64_type);
	CAMLreturn(caml_alloc_initialized_string(8, hash_b64));
}

value nacl_key_gen() {
	CAMLparam0();
	unsigned char *key = sodium_malloc(key_bs);
	crypto_secretstream_xchacha20poly1305_keygen(key);
	CAMLreturn(caml_copy_nativeint((intptr_t) key));
}

value nacl_key_encrypt(value v_sk, value v_pk, value v_key) {
	CAMLparam3(v_sk, v_pk, v_key);
	unsigned char *key_sk = (unsigned char *) Nativeint_val(v_sk);
	unsigned char *key_pk = (unsigned char *) Nativeint_val(v_pk);
	unsigned char *key = (unsigned char *) Nativeint_val(v_key);
	int nct_len = key_bs + nonce_len + ct_len;
	unsigned char nct[nct_len];
	memcpy(nct, key_pk, key_bs);
	randombytes_buf(nct + key_bs, nonce_len);

	if (crypto_box_easy( nct + key_bs + nonce_len,
			key, key_bs, nct + key_bs, key_pk, key_sk ))
		caml_failwith("crypto_box_easy failed");

	int ct_b64_len = sodium_base64_encoded_len(nct_len, b64_type);
	unsigned char ct_b64[ct_b64_len];
	sodium_bin2base64(ct_b64, ct_b64_len, nct, nct_len, b64_type);
	CAMLreturn(caml_alloc_initialized_string(ct_b64_len-1, ct_b64));
}

value nacl_key_decrypt(value v_sk, value v_ct_b64) {
	CAMLparam2(v_sk, v_ct_b64);
	unsigned char *key_sk = (unsigned char *) Nativeint_val(v_sk);
	unsigned char *ct_b64 = String_val(v_ct_b64);
	size_t ct_b64_len = caml_string_length(v_ct_b64);
	char *err;
	unsigned char *key = sodium_malloc(key_bs);
	const char *key_b64_end;
	size_t nct_len;
	unsigned char nct[key_bs + nonce_len + ct_len];

	if (sodium_base642bin( nct, key_bs + nonce_len + ct_len,
			ct_b64, ct_b64_len, NULL, &nct_len, &key_b64_end, b64_type ))
		{ err = "sodium_base642bin failed"; goto fail_with_err; }
	if (nct_len != key_bs + nonce_len + ct_len)
		{ err = "key length mismatch"; goto fail_with_err; }

	if (crypto_box_open_easy( key,
			nct + key_bs + nonce_len, ct_len, nct + key_bs, nct, key_sk ))
		{ err = "crypto_box_open_easy failed"; goto fail_with_err; }
	CAMLreturn(caml_copy_nativeint((intptr_t) key));

	fail_with_err:
	sodium_free(key);
	caml_failwith(err);
}

value nacl_encrypt(value v_key, value v_chunk0, value v_fd_src, value v_fd_dst) {
	CAMLparam4(v_key, v_chunk0, v_fd_src, v_fd_dst);
	char *err;
	unsigned char *key = (unsigned char *) Nativeint_val(v_key);
	int fd_src = -1, fd_dst = -1; FILE *fp_src, *fp_dst;

	unsigned char buff_in[enc_bs];
	unsigned char buff_out[enc_bs + crypto_secretstream_xchacha20poly1305_ABYTES];
	size_t hdr_len = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
	unsigned char hdr[hdr_len];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long out_len; size_t in_len; int eof; unsigned char tag;

	in_len = caml_string_length(v_chunk0);
	if (in_len >= enc_bs) { err = "enc bug - initial chunk too large"; goto fail_with_err; }
	if (in_len > 0) { memcpy(buff_in, String_val(v_chunk0), in_len); }

	fd_src = dup(Int_val(v_fd_src)); fd_dst = dup(Int_val(v_fd_dst));
	if (fd_src < 0 || fd_dst < 0) { err = "enc fd dup failed"; goto fail_with_err; }
	fp_src = fdopen(Int_val(v_fd_src), "rb"); fp_dst = fdopen(Int_val(v_fd_dst), "wb");
	if (!fp_src || !fp_dst) { err = "enc fdopen failed"; goto fail_with_err; }

	if (crypto_secretstream_xchacha20poly1305_init_push(&st, hdr, key))
		{ err = "enc init_push failed"; goto fail_with_err; }
	if (fwrite(hdr, 1, hdr_len, fp_dst) != hdr_len)
		{ err = "enc header write failed"; goto fail_with_err; }

	do {
		in_len += fread(buff_in + in_len, 1, sizeof buff_in - in_len, fp_src);
		eof = feof(fp_src);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		if (crypto_secretstream_xchacha20poly1305_push(
				&st, buff_out, &out_len, buff_in, in_len, NULL, 0, tag ))
			{ err = "enc push failed"; goto fail_with_err; }
		if (fwrite(buff_out, 1, (size_t) out_len, fp_dst) != out_len || ferror(fp_src))
			{ err = "enc i/o error"; goto fail_with_err; }
		in_len = 0;
	} while (!eof);

	int close_err;
	if ( (close_err = fflush(fp_dst))
			|| ((close_err |= fclose(fp_src)) & 0 || (fp_src = NULL)) || close_err
			|| ((close_err |= fclose(fp_dst)) & 0 || (fp_dst = NULL)) || close_err )
		{ err = "enc i/o flush/close error"; goto fail_with_err; }
	CAMLreturn(Val_unit);

	fail_with_err:
	if (fp_src) fclose(fp_src); else if (fd_src >= 0) close(fd_src);
	if (fp_dst) fclose(fp_dst); else if (fd_dst >= 0) close(fd_dst);
	caml_failwith(err);
}

value nacl_decrypt(value v_key, value v_fd_src, value v_fd_dst) {
	CAMLparam3(v_key, v_fd_src, v_fd_dst);
	char *err;
	unsigned char *key = (unsigned char *) Nativeint_val(v_key);
	int fd_src = -1, fd_dst = -1; FILE *fp_src, *fp_dst;

	unsigned char buff_in[enc_bs + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char buff_out[enc_bs];
	size_t hdr_len = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
	unsigned char hdr[hdr_len];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long out_len; size_t in_len; int eof; unsigned char tag;

	fd_src = dup(Int_val(v_fd_src)); fd_dst = dup(Int_val(v_fd_dst));
	if (fd_src < 0 || fd_dst < 0) { err = "dec fd dup failed"; goto fail_with_err; }
	fp_src = fdopen(Int_val(v_fd_src), "rb"); fp_dst = fdopen(Int_val(v_fd_dst), "wb");
	if (!fp_src || !fp_dst) { err = "dec fdopen failed"; goto fail_with_err; }

	if (fread(hdr, 1, hdr_len, fp_src) != hdr_len)
		{ err = "dec header read failed"; goto fail_with_err; }
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, hdr, key))
		{ err = "dec init_pull failed"; goto fail_with_err; }

	do {
		in_len = fread(buff_in, 1, sizeof buff_in, fp_src);
		eof = feof(fp_src);
		if (crypto_secretstream_xchacha20poly1305_pull(
				&st, buff_out, &out_len, &tag, buff_in, in_len, NULL, 0 ))
			{ err = "dec pull failed"; goto fail_with_err; }
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof)
			{ err = "dec incomplete stream"; goto fail_with_err; }
		if (fwrite(buff_out, 1, (size_t) out_len, fp_dst) != out_len || ferror(fp_src))
			{ err = "dec i/o error"; goto fail_with_err; }
	} while (!eof);

	int close_err;
	if ( (close_err = fflush(fp_dst))
			|| ((close_err |= fclose(fp_src)) & 0 && (fp_src = NULL)) || close_err
			|| ((close_err |= fclose(fp_dst)) & 0 && (fp_dst = NULL)) || close_err )
		{ err = "dec i/o flush/close error"; goto fail_with_err; }
	CAMLreturn(Val_unit);

	fail_with_err:
	if (fp_src) fclose(fp_src); else if (fd_src >= 0) close(fd_src);
	if (fp_dst) fclose(fp_dst); else if (fd_dst >= 0) close(fd_dst);
	caml_failwith(err);
}

value nacl_cct_decrypt(
		value v_sk, value v_pk, value v_nonce, value v_n, value v_ct ) {
	// Decode ciphertext chunk in an old py2 ghg script format
	CAMLparam5(v_sk, v_pk, v_nonce, v_n, v_ct);
	unsigned char *key_sk = (unsigned char *) Nativeint_val(v_sk);
	unsigned char *key_pk = (unsigned char *) Nativeint_val(v_pk);
	unsigned char *nonce_base = String_val(v_nonce);
	unsigned char *ct = String_val(v_ct);
	int ct_len = caml_string_length(v_ct);
	uint32_t n = Int_val(v_n);

	int nonce_base_len = 16;
	if (caml_string_length(v_nonce) != nonce_base_len)
		caml_failwith("cct-dec nonce length mismatch");
	unsigned char nonce[nonce_base_len + 8];
	memcpy(nonce, nonce_base, nonce_base_len);
	unsigned char *nonce_n = nonce + nonce_base_len;
	nonce_n[0] = nonce_n[1] = nonce_n[2] = nonce_n[3] = 0;
	nonce_n[4] = (char) (n >> 24) & 0xff; nonce_n[5] = (char) (n >> 16) & 0xff;
	nonce_n[6] = (char) (n >> 8) & 0xff; nonce_n[7] = (char) n & 0xff;

	int cb_pad = crypto_box_BOXZEROBYTES, cb_skip = crypto_box_ZEROBYTES;
	int cb_len = cb_pad + ct_len;
	unsigned char buff_in[cb_len];
	memset(buff_in, 0, cb_pad);
	memcpy(buff_in + cb_pad, ct, ct_len);
	unsigned char buff_out[cb_len];
	if (crypto_box_open(buff_out, buff_in, cb_len, nonce, key_pk, key_sk))
		caml_failwith("cct-dec crypto_box_open failed");

	CAMLreturn(caml_alloc_initialized_string(cb_len - cb_skip, buff_out + cb_skip));
}
