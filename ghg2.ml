(* Simple command-line NaCl encryption tool.
 *
 * Build with:
 *   % ocamlopt -o ghg2 -O2 unix.cmxa str.cmxa \
 *      -cclib -lsodium -ccopt -Wl,--no-as-needed ghg2.ml ghg2.ml.c
 *   % strip ghg2
 *
 * Usage:
 *   % ./ghg2 --help
 *   % ./ghg2 ...
 * Debug: OCAMLRUNPARAM=b ./ghg2 ...
 *)

let cli_conf = ref "/etc/ghg.yaml"
let cli_enc = ref false
let cli_dec = ref false
let cli_key_sk = ref ""
let cli_key_pk = ref []
let cli_key_pk_add = (fun k -> cli_key_pk := !cli_key_pk @ [k])
let cli_key_convert = ref false
let cli_files = ref []

let () =
	let t, help = "\n      ", ref false in let args =
		[ ("-c", Arg.Set_string cli_conf, " ");
			("--conf", Arg.Set_string cli_conf,
				t^"Alternate encryption-keys-config file location. Default: " ^ !cli_conf ^ "\n");

			("-e", Arg.Set cli_enc, " ");
			("--encrypt", Arg.Set cli_enc,
				t^"Encrypt specified file or stdin stream." ^
				t^"Symmetric encryption is used for the data, using ad-hoc generated master key." ^
				t^"crypto_box(nonce, master_key, local_sk, recipient_pk) encrypts master key itself." ^
				t^"Default local pubkey(s) is/are used as a recipient by default.");
			("-d", Arg.Set cli_dec, " ");
			("--decrypt", Arg.Set cli_dec,
				t^"Decrypt specified file or stdin stream." ^
				t^"When decrypting to stdout, authentication/integrity" ^
				t^" is indicated by exit code (!!!), so ALWAYS CHECK IF EXIT CODE IS 0.\n");

			("-r", Arg.String cli_key_pk_add, " ");
			("--recipient", Arg.String cli_key_pk_add,
				t^"Public key name/id to encrypt to or decrypt with." ^
				t^"Public key itself can also be specified in pub64-* format." ^
				t^"Can be specified multiple times to encrypt for each of the keys." ^
				t^"Private raw64-* keys are not accepted here on purpose," ^
				t^" to avoid forming a habit of passing these on a command line," ^
				t^" use pub64-* keys and/or config file instead.");
			("-k", Arg.Set_string cli_key_sk, " ");
			("--key", Arg.Set_string cli_key_sk,
				t^"Local secret key name/id to use for encryption ops." ^
				t^"Same as with -r/--recipient option, raw64-* key strings are not allowed here.\n");

			("-p", Arg.Set cli_key_convert, " ");
			("--pubkey", Arg.Set cli_key_convert,
				t^"Print public key for specified -k/--key, or default configured key.\n");
			(* XXX: -g/--genkey option *)

			("-h", Arg.Set help, " "); ("-help", Arg.Set help, " ") ] in
	let usage_msg = ("Usage: " ^ Sys.argv.(0) ^ " [opts] [file ...]\
		\n\nEncrypt/decrypt specified files via libsodium, using specified/configured keys.\n") in
	Arg.parse args (fun file -> cli_files := file :: !cli_files) usage_msg;
	if !help then (Arg.usage args usage_msg; exit 0)


(* NaCl bindings from ghg2.ml.c *)
type nacl_constants_record = {key_len: int} [@@boxed]
external nacl_init : unit -> nacl_constants_record = "nacl_init"
external nacl_key_load : string -> nativeint = "nacl_key_load"
external nacl_key_free : nativeint -> unit = "nacl_key_free"
external nacl_key_sk_to_pk : nativeint -> nativeint = "nacl_key_sk_to_pk"
external nacl_key_b64 : nativeint -> string = "nacl_key_b64"
external nacl_key_gen : unit -> nativeint = "nacl_key_gen"
external nacl_key_encrypt : nativeint -> nativeint -> nativeint -> string = "nacl_key_encrypt"
external nacl_key_decrypt : nativeint -> string -> nativeint = "nacl_key_decrypt"
external nacl_encrypt : nativeint -> string -> int -> int -> unit = "nacl_encrypt"
external nacl_decrypt : nativeint -> int -> int -> unit = "nacl_decrypt"

let nacl = nacl_init()


(* Misc minor helpers and constants *)
let magic_v1 = "¯\\_ʻghgʻ_/¯ 1 "
let magic_v2 = "¯\\_ʻghgʻ_/¯ 2 "
let magic_len = String.length magic_v1
let header_end = "---"
let header_line_len = 256 (* longer lines will raise errors *)
let fmt = Printf.sprintf
let fdesc_to_int : Unix.file_descr -> int = Obj.magic (* ocamllabs/ocaml-ctypes#123 *)
let rec eintr_loop f x =
	try f x with Unix.Unix_error (Unix.EINTR, _, _) -> eintr_loop f x


exception KeyParseFail of string
exception DecryptFail of string

let parse_key =
	let re_key_pub64, re_key_raw64 =
		Str.regexp "^pub64-\\(.*\\)$", Str.regexp "^raw64-\\(.*\\)$" in
	let parse_key_b64 spec =
		try nacl_key_load spec
		with Failure err -> raise (KeyParseFail err) in
	fun key_name is_sk spec ->
		(* XXX: also lookup/translate keys from flattened config here *)
		try
			let pk = if Str.string_match re_key_pub64 spec 0
				then parse_key_b64 (Str.matched_group 1 spec) else 0n in
			let sk = if Str.string_match re_key_raw64 spec 0
				then parse_key_b64 (Str.matched_group 1 spec) else 0n in
			if pk = 0n && sk = 0n then raise (KeyParseFail "unknown key format");
			if is_sk && sk = 0n then raise (KeyParseFail "secret key is required");
			if is_sk then sk else if pk <> 0n then pk else nacl_key_sk_to_pk sk
		with KeyParseFail err -> raise (KeyParseFail (fmt "%s (%s)" err key_name))


let encrypt key key_encs chunk0 fdesc_src fdesc_dst =
	let buff = Bytes.create header_line_len in
	let write_line s =
		let s_len = String.length s in
		Bytes.blit_string s 0 buff 0 s_len; Bytes.set buff s_len '\n';
		let buff_len = s_len + 1 in
		if (Unix.write fdesc_dst buff 0 buff_len) < buff_len
			then raise (Failure "Write to destination file/fd failed") in
	write_line (magic_v2 ^ "-");
	List.iter write_line key_encs;
	write_line header_end;
	nacl_encrypt key chunk0 (fdesc_to_int fdesc_src) (fdesc_to_int fdesc_dst)


let decrypt sk fdesc_src fdesc_dst =
	let line_buff = Bytes.create header_line_len in
	let rec read_line n =
		let m = try eintr_loop (Unix.read fdesc_src line_buff n) 1
			with Invalid_argument err -> raise (DecryptFail (fmt "too long key line [pos=%d]" n)) in
		if m = 0 || (Bytes.get line_buff n) = '\n'
			then Bytes.sub_string line_buff 0 n else read_line (n + 1) in
	let rec read_key sk key =
		let key_enc_b64 = read_line 0 in
		if key_enc_b64 = header_end then key else
		let key = if key <> 0n then key else
			try nacl_key_decrypt sk key_enc_b64
			with Failure err ->
				if err = "crypto_box_open_easy failed" then key else raise (Failure err) in
		read_key sk key in
	let _magic_tail = read_line 0 in
	let key = match read_key sk 0n with
		| 0n -> raise (DecryptFail "key mismatch") | key -> key in
	nacl_decrypt key (fdesc_to_int fdesc_src) (fdesc_to_int fdesc_dst)


let () =
	(* XXX: implement src/dst file handling *)
	(* XXX: use keys from config file *)
	if !cli_key_sk = "" then ( prerr_endline (* XXX *)
		"ERROR: -k/--key option is required, as -c/--conf is not implemented"; exit 1 );

	if !cli_key_convert then
		let pk = parse_key "-k/--key" false !cli_key_sk in
		Fun.protect
			~finally:(fun () -> nacl_key_free pk)
			(fun () -> print_endline ("pub64-" ^ (nacl_key_b64 pk)); exit 0)
	else

	let magic = Bytes.create magic_len in
	let rec magic_read n =
		if n >= magic_len then Bytes.to_string magic else
		match eintr_loop (Unix.read Unix.stdin magic n) (magic_len - n) with
		| 0 -> Bytes.sub_string magic 0 n
		| m -> magic_read (n + m) in
	match magic_read 0 with

	| s when s = magic_v1 -> raise (Failure "magic_v1 decrypt")
		(* for box_dst_pk in box_dst_pk_list: *)
		(* readline -> src_pk, nonce_16B, dst_pkid_8B *)

	| s when s = magic_v2 ->
		let sk = parse_key "-k/--key" true !cli_key_sk in
		Fun.protect
			~finally:(fun () -> nacl_key_free sk)
			(fun () -> decrypt sk Unix.stdin Unix.stdout)

	| s ->
		(* XXX: bark at raw64- keys in pk_list when config will be implemented *)
		if (List.length !cli_key_pk) = 0 then ( prerr_endline (* XXX *)
			"ERROR: -r/--recipient option is required, as -c/--conf is not implemented"; exit 1 );
		let key = nacl_key_gen () in
		let pk_list = ref [] in
		Fun.protect
			~finally:(fun () -> List.iter (fun k -> nacl_key_free k) !pk_list)
			( fun () ->
				pk_list := [parse_key "-k/--key" true !cli_key_sk];
				List.iteri ( fun n k -> pk_list :=
					!pk_list @ [parse_key (fmt "-r/--recipient #%d" (n + 1)) false k] ) !cli_key_pk;
				let sk, pk_list = List.(hd !pk_list, tl !pk_list) in
				let key_encs = List.map (fun pk -> nacl_key_encrypt sk pk key) pk_list in
				encrypt key key_encs s Unix.stdin Unix.stdout )
