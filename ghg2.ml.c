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


int key_bs;
int b64_type = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
int enc_bs = 16384;

value nacl_init() {
	CAMLparam0();
	CAMLlocal1(v_consts);
	v_consts = caml_alloc_tuple(2);

	if (sodium_init()) caml_failwith("sodium_init failed");

	// Same lengths are used for all keys when parsing, so checked to be same here
	key_bs = crypto_secretstream_xchacha20poly1305_KEYBYTES;
	if ( key_bs != crypto_box_PUBLICKEYBYTES || key_bs != crypto_box_SECRETKEYBYTES)
		caml_failwith("unexpected libsodium key length values");

	Store_field(v_consts, 0, Val_int(key_bs));

	CAMLreturn(v_consts);
}

value nacl_key_load(value v_key_b64) {
	// Decodes base64 key string into a sodium_malloc'ed pointer
	CAMLparam1(v_key_b64);
	char *err;
	size_t key_b64_len = caml_string_length(v_key_b64);
	unsigned char *key_b64 = String_val(v_key_b64);
	const char *key_b64_end;
	size_t key_bin_len;
	unsigned char *key_bin = sodium_malloc(key_bs);
	if (sodium_base642bin( key_bin, key_bs,
			key_b64, key_b64_len, NULL, &key_bin_len, &key_b64_end, b64_type ))
		{ err = "sodium_base642bin failed"; goto fail_with_err; }
	if (key_bin_len != key_bs) { err = "key length mismatch"; goto fail_with_err; }
	CAMLreturn(caml_copy_nativeint((intptr_t) key_bin));

	fail_with_err:
	sodium_free(key_bin);
	caml_failwith(err);
}

value nacl_key_free(value v_key) {
	CAMLparam1(v_key);
	sodium_free((unsigned char *) Nativeint_val(v_key));
	CAMLreturn(Val_unit);
}

value nacl_key_sk_to_pk(value v_key_sk) {
	CAMLparam1(v_key_sk);
	unsigned char *key_sk = (unsigned char *) Nativeint_val(v_key_sk);
	unsigned char *key_pk = sodium_malloc(key_bs);
	if (crypto_scalarmult_base(key_pk, key_sk))
		{ sodium_free(key_pk); caml_failwith("crypto_scalarmult_base failed"); }
	CAMLreturn(caml_copy_nativeint((intptr_t) key_pk));
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

	int nonce_len = crypto_box_NONCEBYTES;
	int ct_len = key_bs + crypto_box_MACBYTES;
	unsigned char ct[nonce_len + ct_len];
	randombytes_buf(ct, nonce_len);
	if (crypto_box_easy(ct + nonce_len, key, key_bs, ct, key_pk, key_sk))
		caml_failwith("crypto_box_easy failed");

	int ct_b64_len = sodium_base64_encoded_len(nonce_len + ct_len, b64_type);
	unsigned char ct_b64[ct_b64_len];
	sodium_bin2base64(ct_b64, ct_b64_len, ct, nonce_len + ct_len, b64_type);

	CAMLreturn(caml_alloc_initialized_string(ct_b64_len-1, ct_b64));
}

value nacl_encrypt(value v_key, value v_chunk, value v_fd_src, value v_fd_dst) {
	CAMLparam4(v_key, v_chunk, v_fd_src, v_fd_dst);
	char *err;
	unsigned char *chunk, *key = (unsigned char *) Nativeint_val(v_key);
	int fd_src = -1, fd_dst = -1; FILE *fp_src, *fp_dst;

	unsigned char buff_in[enc_bs];
	unsigned char buff_out[enc_bs + crypto_secretstream_xchacha20poly1305_ABYTES];
	size_t hdr_len = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
	unsigned char hdr[hdr_len];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long out_len; size_t in_len; int eof; unsigned char tag;

	fd_src = dup(Int_val(v_fd_src)); fd_dst = dup(Int_val(v_fd_dst));
	if (fd_src < 0 || fd_dst < 0) { err = "enc fd dup failed"; goto fail_with_err; }
	fp_src = fdopen(Int_val(v_fd_src), "r"); fp_dst = fdopen(Int_val(v_fd_dst), "w");
	if (!fp_src || !fp_dst) { err = "enc fdopen failed"; goto fail_with_err; }

	if (crypto_secretstream_xchacha20poly1305_init_push(&st, hdr, key))
		{ err = "enc init_push failed"; goto fail_with_err; }
	fwrite(hdr, 1, hdr_len, fp_dst);
	if (feof(fp_dst) || ferror(fp_dst)) { err = "enc header write failed"; goto fail_with_err; }

	in_len = caml_string_length(v_chunk);
	if (in_len > enc_bs) { err = "enc bug - initial chunk too large"; goto fail_with_err; }
	if (in_len > 0) chunk = String_val(v_chunk);

	do {
		if (!chunk) {
			in_len = fread(buff_in, 1, enc_bs, fp_src);
			eof = feof(fp_src); }
		else {
			memcpy(buff_in, chunk, in_len);
			chunk = NULL; }
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		if (crypto_secretstream_xchacha20poly1305_push(
				&st, buff_out, &out_len, buff_in, in_len, NULL, 0, tag ))
			{ err = "enc push failed"; goto fail_with_err; }
		fwrite(buff_out, 1, (size_t) out_len, fp_dst);
		if (ferror(fp_src) || feof(fp_dst) || ferror(fp_dst)) { err = "enc i/o error"; goto fail_with_err; }
	} while (!eof);

	fclose(fp_src); fclose(fp_dst);
	CAMLreturn(Val_unit);

	fail_with_err:
	if (fp_src) fclose(fp_src); else if (fd_src >= 0) close(fd_src);
	if (fp_dst) fclose(fp_dst); else if (fd_dst >= 0) close(fd_dst);
	caml_failwith(err);
}
