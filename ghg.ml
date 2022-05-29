(* Simple command-line NaCl/libsodium file encryption tool.
 *
 * Build with:
 *   % ocamlopt -o ghg -O2 unix.cmxa str.cmxa \
 *      -cclib -lsodium -ccopt -Wl,--no-as-needed ghg.ml ghg.ml.c
 *   % strip ghg
 *
 * Usage:
 *   % ./ghg --help
 *   % ./ghg <data >data.ghg
 * Debug: OCAMLRUNPARAM=b ./ghg ...
 *)

exception ArgsFail of string
exception KeyParseNoMatch
exception KeyParseMismatch
exception KeyParseFail of string
exception DecryptFail of string
exception ConfParseFail of string

let cli_conf = ref "/etc/ghg.yamlx"
let cli_enc = ref false
let cli_dec = ref false

let cli_key_sk = ref []
let cli_key_sk_add = (fun k -> cli_key_sk := !cli_key_sk @ [k])
let cli_key_pk = ref []
let cli_key_pk_add = (fun k -> cli_key_pk := !cli_key_pk @ [k])
let cli_key_convert = ref false
let cli_key_gen = ref false

let cli_argon_fd = ref (-1)
let cli_argon_ops = ref 3
let cli_argon_mem = ref (Int.of_float (256. *. 2. ** 20.))
let cli_argon_parse = (fun s ->
	if not (Str.string_match ( Str.regexp
		"^\\([0-9]+\\)\\(/\\([0-9]+\\)\\(-[0-9]+\\)?\\)?$" ) s 0)
	then raise (ArgsFail "Unrecognized -x/--argon-fd option value format")
	else
		cli_argon_fd := Str.matched_group 1 s |> int_of_string;
		try
			cli_argon_ops := Str.matched_group 3 s |> int_of_string;
			cli_argon_mem := Int.of_float ( (2. ** 20.) *.
				(Int.to_float (-1 * (Str.matched_group 4 s |> int_of_string))) )
		with Not_found -> ())

let cli_files = ref []
let cli_stdout = ref false

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
				t^" is indicated by exit code (!!!), so Always Check That Exit Code IS 0.\n");

			("-r", Arg.String cli_key_pk_add, "<key/name>");
			("--recipient", Arg.String cli_key_pk_add, "<key/name>" ^
				t^"Public key name/spec(s) to encrypt to." ^
				t^"Can be specified multiple times to encrypt for each of the keys." ^
				t^"If this option is used, only specified keys will be used as destination," ^
				t^" -k/--key is not automatically added to them, i.e. won't be able to decrypt output." ^
				t^"sk64.* keys can be used here, but shouldn't be - use pk64.* and/or config file.");
			("-k", Arg.String cli_key_sk_add, "<key/name>");
			("--key", Arg.String cli_key_sk_add, "<key/name>" ^
				t^"Local secret key name/spec(s) to use for encryption ops. Can be used multiple times." ^
				t^"Using the option disregards default key specs in the config file, if any." ^
				t^"Same as with -r/--recipient option, use config for sk64.* keys - args don't work for secrets.\n");

			("-x", Arg.String cli_argon_parse, "<fd[/ops-mem]>");
			("--argon-fd", Arg.String cli_argon_parse, "<fd[/ops-mem]>" ^
				t^"Run Argon2id on all used sk(s) plus a passphrase-line from specified fd to derive new one(s)." ^
				t^"Argument fd should be just >0 integer, and can optionally have a suffix with libsodium" ^
				t^" pwhash/argon2id ops and memory parameters, for example 0/3-256 to use fd=0 (stdin) and" ^
				t^" opslimit=3 memlimit=256M. 3-256 are defaults, see libsodium docs for more info on those." ^
				t^"Can optionally end in newline character, which will be stripped, but can only have one of it." ^
				t^"This changes the secret key(s), so make sure to print/use new pubkey after this operation.\n");
			("-x3", Arg.Unit (fun () -> cli_argon_fd := 3), "");
			("-dx3", Arg.Unit (fun () -> cli_argon_fd := 3; cli_dec := true), "");
			("-dox3", Arg.Unit (fun () -> cli_argon_fd := 3; cli_dec := true; cli_stdout := true), "");

			("-o", Arg.Set cli_stdout, " ");
			("--stdout", Arg.Set cli_stdout,
				t^"Encrypt/decrypt to stdout, even when file path is specified, not removing src files.");
			("-s", Arg.Unit Fun.id, " ");
			("--stable", Arg.Unit Fun.id,
				t^"Not Implemented: stable encryption option flag, left here for compatibility, does nothing.\n");
			("-do", Arg.Unit (fun () -> cli_stdout := true; cli_dec := true), "");
			("-eo", Arg.Unit (fun () -> cli_stdout := true; cli_enc := true), "");

			("-g", Arg.Set cli_key_gen, " ");
			("--genkey", Arg.Set cli_key_gen,
				t^"Generate/print new random private key and exit.");
			("-p", Arg.Set cli_key_convert, " ");
			("--pubkey", Arg.Set cli_key_convert,
				t^"Print public key for specified -k/--key or default configured key and exit." ^
				t^"Can be used together with -g/--genkey to print generated public/private keypair.\n");
			("-gp", Arg.Unit (fun () -> cli_key_convert := true; cli_key_gen := true), "");
			("-pg", Arg.Unit (fun () -> cli_key_convert := true; cli_key_gen := true), "");

			("-h", Arg.Set help, " "); ("-help", Arg.Set help, " ") ] in
	let usage_msg = ("Usage: " ^ Sys.argv.(0) ^ " [opts] [file ...]\
		\n\nEncrypt/decrypt file(s) via libsodium's crypto_box/xchacha20, using specified/configured keys.\n\
		Direction is auto-detected from file/stream contents, if not explicitly specified.\n\
		File suffix/extension .ghg is added when encrypting named files, and original unlinked.\n\
		When decrypting named files, .ghg suffix is stripped (or .dec added), encrypted file removed.\n\
		Default is to use stdin/stdout streams (\"-\" arg also works as those).\n") in
	Arg.parse args (fun file -> cli_files := file :: !cli_files) usage_msg;
	if !help then (Arg.usage args usage_msg; exit 0)


(* libsodium bindings from ghg.ml.c *)
type nacl_constants_record = {key_len: int} [@@boxed]
external nacl_init : unit -> nacl_constants_record = "nacl_init"
external nacl_b64_to_string : string -> int -> string = "nacl_b64_to_string"
external nacl_string_to_b64 : string -> string = "nacl_string_to_b64"
external nacl_gen_key : unit -> nativeint = "nacl_gen_key"
external nacl_gen_key_pair : unit -> (nativeint * nativeint) = "nacl_gen_key_pair"
external nacl_key_load : string -> nativeint = "nacl_key_load"
external nacl_key_free : nativeint -> unit = "nacl_key_free"
external nacl_key_sk_to_pk : nativeint -> nativeint = "nacl_key_sk_to_pk"
external nacl_key_b64 : nativeint -> string = "nacl_key_b64"
external nacl_key_hash : nativeint -> string = "nacl_key_hash"
external nacl_key_encrypt : nativeint -> nativeint -> nativeint -> string = "nacl_key_encrypt"
external nacl_key_decrypt : nativeint -> string -> nativeint = "nacl_key_decrypt"
external nacl_key_argon : nativeint -> string -> int -> int -> nativeint = "nacl_key_argon"
external nacl_encrypt : nativeint -> string -> int -> int -> unit = "nacl_encrypt"
external nacl_decrypt : nativeint -> int -> int -> unit = "nacl_decrypt"
external nacl_decrypt_v1 : nativeint -> nativeint -> string -> int -> string -> string = "nacl_decrypt_v1"
let nacl = nacl_init()


(* Misc minor helpers and constants *)
let magic_v1 = "¯\\_ʻghgʻ_/¯ 1 "
let magic_v2 = "¯\\_ʻghgʻ_/¯ 2 "
let magic_len = String.length magic_v1
let header_end = "---"
let header_line_len = 256 (* longer lines will raise errors *)
let fmt = Printf.sprintf
let fdesc_to_int : Unix.file_descr -> int = Obj.magic (* ocamllabs/ocaml-ctypes#123 *)
let fdesc_of_int : int -> Unix.file_descr = Obj.magic
let errno_to_int : Unix.error -> int = Obj.magic
let rec eintr_loop f x =
	try f x with Unix.Unix_error (Unix.EINTR, _, _) -> eintr_loop f x


let parse_conf =
	let re_v_sep, re_link, re_k, re_v, re_rem, re_kv = Str.(
		regexp "[ \t]+", regexp "^link\\.\\(.*\\)$",
		regexp "^\\([^:]+\\):[ \t]*$", regexp "^[ \t]+\\([^ \t].*\\)$",
		regexp "\\(^\\|[ \t]+\\)#.*$", regexp "^\\([^ \t][^:]+\\):[ \t]*\\([^ \t].*\\)$" ) in
	let conf_add_val c k s =
		if s = "" && not (Hashtbl.mem c k) then Hashtbl.add c k s else (* empty sets *)
		List.iter (fun v -> Hashtbl.add c k v) (Str.split re_v_sep s) in
	let rec conf_parse src c n k =
		let cadd, cparse = conf_add_val c, conf_parse src c (n + 1) in
		let line = try input_line src with End_of_file ->
			if k <> "" then cadd k ""; raise End_of_file in
		let line = Str.replace_first re_rem "" line in
		if line = "" then cparse k else
		if Str.string_match re_kv line 0 then (
			let mk, mv = Str.(matched_group 1 line, matched_group 2 line) in
			if k <> "" then cadd k ""; cadd mk mv; cparse ""
		) else if Str.string_match re_v line 0 then (
			let mv = Str.matched_group 1 line in
			if k = "" then raise (ConfParseFail (fmt "indentation mismatch (line %d)" n));
			cadd k mv; cparse k
		) else if Str.string_match re_k line 0 then (
			let mk = Str.matched_group 1 line in
			if k <> "" then cadd k ""; cparse mk
		) else raise (ConfParseFail (fmt "unrecognized line format (line %d)" n)) in
	let rec conf_links_expand c n =
		let conf_ext = ref [] in
		Hashtbl.filter_map_inplace ( fun k v ->
			if not (Str.string_match re_link v 0) then Some v else
			let dk = Str.matched_group 1 v in
			if n > 100 then raise (ConfParseFail (fmt "unresolvable link %s" dk));
			match Hashtbl.find_all c dk with
				| [] -> Some v | dv -> conf_ext := (k, dv) :: !conf_ext; None ) c;
		if (List.length !conf_ext) <> 0 then (
			List.iter (fun (k, dv) -> List.iter (fun v -> Hashtbl.add c k v) dv) !conf_ext;
			conf_links_expand c (n + 1)
		) else (Hashtbl.filter_map_inplace (fun k v -> if v = "" then None else Some v) c; c) in
	fun src ->
		let conf = Hashtbl.create 8 in
		try conf_parse src conf 1 "" with End_of_file -> ();
		conf_links_expand conf 0

let parse_key_list =
	(* Keys are NOT printed in errors here on purpose, to avoid exposing them *)
	let re_pk64, re_sk64, re_link = Str.(
		regexp "^pk64\\.\\(.*\\)$", regexp "^sk64\\.\\(.*\\)$", regexp "^link\\.\\(.*\\)$" ) in
	let parse_key_b64 spec =
		try nacl_key_load spec
		with Failure err -> raise (KeyParseFail err) in
	let parse_key key_name is_sk spec =
		try
			let pk = if Str.string_match re_pk64 spec 0
				then parse_key_b64 (Str.matched_group 1 spec) else 0n in
			let sk = if Str.string_match re_sk64 spec 0
				then parse_key_b64 (Str.matched_group 1 spec) else 0n in
			if pk = 0n && sk = 0n then raise KeyParseNoMatch;
			if is_sk && sk = 0n then raise KeyParseMismatch;
			if is_sk then sk else if pk <> 0n then pk else nacl_key_sk_to_pk sk
		with KeyParseFail err -> raise (KeyParseFail (fmt "%s (%s)" err key_name)) in
	fun conf key_name is_sk keys ->
		let key_list = ref [] in
		( try List.iteri ( fun n k ->
				let key_name = fmt "%s #%d" key_name (n + 1) in
				let k_list, k_filter =
					match Hashtbl.find_all conf (Str.replace_first re_link "\\1" k)
					with | [] -> [k], false | keys -> keys, true in
				List.iteri ( fun m kc ->
					let key_name = if (List.length k_list) = 1
						then key_name else fmt "%s.%d" key_name (m + 1) in
					(* prerr_endline (fmt "-- parse sk=%b %s %s (%s)" is_sk k kc key_name); *)
					try key_list := !key_list @ [parse_key key_name is_sk kc] with
					| KeyParseMismatch -> if not k_filter then
						raise (KeyParseFail (fmt "secret key is required (%s)" key_name))
					| KeyParseNoMatch ->
						if not (String.starts_with ~prefix:"-keys-" kc) then (* missing -keys-to: and such *)
						raise (KeyParseFail (fmt "no key matching spec (%s)" key_name)) ) k_list ) keys
			with e -> List.iter nacl_key_free !key_list; raise e );
		if (List.length !key_list) <> 0 then !key_list else
			raise (KeyParseFail (fmt "no secret keys found for %s spec(s)" key_name))


let encrypt key key_slots chunk0 fdesc_src fdesc_dst =
	let buff = Bytes.create header_line_len in
	let write_line s =
		let s_len = String.length s in
		Bytes.blit_string s 0 buff 0 s_len; Bytes.set buff s_len '\n';
		let buff_len = s_len + 1 in
		if (Unix.write fdesc_dst buff 0 buff_len) < buff_len
			then raise (Failure "Write to destination file/fd failed") in
	write_line (magic_v2 ^ "-");
	List.iter write_line key_slots;
	write_line header_end;
	nacl_encrypt key chunk0 (fdesc_to_int fdesc_src) (fdesc_to_int fdesc_dst)


let decrypt sk_list fdesc_src fdesc_dst =
	let line_buff = Bytes.create header_line_len in
	let rec read_line n =
		let m = try eintr_loop (Unix.read fdesc_src line_buff n) 1
			with Invalid_argument err ->
				raise (DecryptFail (fmt "too long key line [pos=%d]" n)) in
		if m = 0 || (Bytes.get line_buff n) = '\n'
			then Bytes.sub_string line_buff 0 n else read_line (n + 1) in
	let rec read_key key =
		let key_enc_b64 = read_line 0 in
		if key_enc_b64 = header_end then key else
		if key <> 0n then read_key key else (* skip past other keyslots with the key *)
		let try_sk sk =
			try Some (nacl_key_decrypt sk key_enc_b64)
			with Failure err ->
				if err = "crypto_box_open_easy failed"
				then None else raise (Failure err) in
		match List.find_map try_sk sk_list
		with | Some key -> read_key key | None -> read_key key in
	let _magic_tail = read_line 0 in
	let key = match read_key 0n with
		| 0n -> raise (DecryptFail "key mismatch") | key -> key in
	nacl_decrypt key (fdesc_to_int fdesc_src) (fdesc_to_int fdesc_dst)


let decrypt_v1 sk_list fdesc_src fdesc_dst =
	(* Decrypts more complicated old py2 ghg script format, can be dropped later *)
	let src = Unix.in_channel_of_descr fdesc_src in
	let dst = Unix.out_channel_of_descr fdesc_dst in
	let read_be_int () = Int32.to_int
		(String.get_int32_be (really_input_string src 4) 0) in
	let read_cct_cpt_lens () =
		let cct_len = read_be_int () in
		let cpt_len = read_be_int () in cct_len, cpt_len in
	let rec cct_skip () =
		let cct_len, cpt_len = read_cct_cpt_lens () in
		let _cct_skip = really_input_string src cct_len in
		if cpt_len = 0 then () else cct_skip () in
	let rec cct_dec sk pk nonce n =
		let cct_len, cpt_len = read_cct_cpt_lens () in
		let cct = really_input_string src cct_len in
		if cpt_len = 0 then () else
			let cpt = nacl_decrypt_v1 sk pk nonce n cct in
			output_string dst cpt;
			cct_dec sk pk nonce (n + 1) in
	let rec cct pk_id_map =
		let header =
			try List.rev (String.split_on_char ' ' (input_line src))
			with End_of_file -> raise (DecryptFail "key mismatch") in
		let pk_b64, nonce_b64, cct_pk_id =
			List.(nth header 2, nth header 1, nth header 0) in
		match Hashtbl.find_opt pk_id_map cct_pk_id with
		| Some sk ->
			let nonce = nacl_b64_to_string nonce_b64 16 in
			let pk = nacl_key_load pk_b64 in
			Fun.protect ~finally:(fun () -> nacl_key_free pk) (fun () -> cct_dec sk pk nonce 0)
		| None -> (cct_skip (); cct pk_id_map) in
	let pk_id_map = Hashtbl.create 1 in
	List.iter ( fun sk ->
		let pk = nacl_key_sk_to_pk sk in
		Hashtbl.add pk_id_map (nacl_key_hash pk) sk;
		nacl_key_free pk ) sk_list;
	cct pk_id_map; flush dst (* no need to close src/dst - done on fdesc's *)


let () =
	if !cli_enc && !cli_dec then
		raise (ArgsFail "-e/--encrypt and -d/--decrypt opts are mutually exclusive");
	if !cli_enc && !cli_argon_fd >= 0 then
		raise (ArgsFail "-x/--argon-fd option is meaningless with -e/--encrypt, and prohibited to avoid confusion");
	if !cli_stdout && (List.length !cli_files) > 1 then
		raise (ArgsFail "-o/--stdout cannot be used with more than one file");

	let conf_src =
		try Unix.in_channel_of_descr (Unix.openfile !cli_conf [O_RDONLY] 0)
		with Unix.Unix_error (Unix.ENOENT, _, _) -> open_in "/dev/null" in
	let conf = Fun.protect
		(fun () -> parse_conf conf_src)
		~finally:(fun () -> close_in conf_src) in
	(* Hashtbl.iter (fun k v -> print_endline (fmt "%S: %S" k v)) conf; flush_all (); *)

	(* Wrappers around nacl_gen_key_pair and parse_key_list to mix-in argon key derivation *)
	let key_argon = if !cli_argon_fd < 0 then "" else
		try
			let src = (Unix.in_channel_of_descr (fdesc_of_int !cli_argon_fd)) in
			try
				Fun.protect (fun () ->
						let line = input_line src in
						try (input_line src |> ignore);
							raise (ArgsFail "More than one input line at -x/--argon-fd")
						with End_of_file -> line)
					~finally:(fun () -> close_in src)
			with End_of_file -> raise (ArgsFail "EOF when reading from -x/--argon-fd")
		with Unix.Unix_error (errno, func, arg) -> raise (ArgsFail (fmt
			"Failure reading from -x/--argon-fd: [%s %d] %s"
			func (errno_to_int errno) (Unix.error_message errno) )) in
	let key_gen = if key_argon = "" then nacl_gen_key_pair else (fun () ->
		let sk, pk = nacl_gen_key_pair () in nacl_key_free pk;
		let sk = nacl_key_argon sk key_argon !cli_argon_ops !cli_argon_mem in
		let pk = nacl_key_sk_to_pk sk in (sk, pk)) in
	let key_parse_list is_sk keys =
		let key_name = if is_sk then "-k/--key" else "-r/--recipient" in
		let key_list = parse_key_list conf key_name is_sk keys in
		if not (is_sk && key_argon <> "") then key_list else
			List.map (fun sk -> nacl_key_argon sk key_argon !cli_argon_ops !cli_argon_mem) key_list in

	if (List.length !cli_key_sk) = 0 then cli_key_sk := ["-keys"];
	if (List.length !cli_key_pk) = 0 then cli_key_pk := ["-keys"; "-keys-to"];

	if !cli_key_gen then
		let sk, pk = key_gen () in
		Fun.protect ( fun () ->
				print_endline ("sk64." ^ (nacl_key_b64 sk));
				if !cli_key_convert then print_endline ("pk64." ^ (nacl_key_b64 pk)); exit 0 )
			~finally:(fun () -> nacl_key_free sk; nacl_key_free pk)
	else if !cli_key_convert then
		let sk_list = key_parse_list true !cli_key_sk in
		Fun.protect ( fun () -> List.iter (fun sk ->
				let pk = nacl_key_sk_to_pk sk in
				Fun.protect (fun () -> print_endline ("pk64." ^ (nacl_key_b64 pk)))
				~finally:(fun () -> nacl_key_free pk)) sk_list; exit 0 )
			~finally:(fun () -> List.iter nacl_key_free sk_list)
	else

	let fdesc_src, fdesc_dst = ref Unix.stdin, ref Unix.stdout in
	let proc_file fn =
		let fn_valid = fn <> "" && fn <> "-" in
		let fn_used = fn_valid && not !cli_stdout in
		if fn_valid then fdesc_src := Unix.openfile fn [O_RDONLY] 0;

		let magic = Bytes.create magic_len in
		let rec magic_read n =
			if n >= magic_len then Bytes.to_string magic else
			match eintr_loop (Unix.read !fdesc_src magic n) (magic_len - n) with
			| 0 -> Bytes.sub_string magic 0 n
			| m -> magic_read (n + m) in
		match if !cli_enc then "" else magic_read 0 with

		| s when !cli_dec || s = magic_v1 || s = magic_v2 ->
			let fn_dst = if String.ends_with ~suffix:".ghg" fn
				then String.sub fn 0 ((String.length fn) - 4) else (fn ^ ".dec") in
			let sk_list = key_parse_list true
				(if !cli_key_sk = ["-keys"] then ["-keys"; "-keys-dec"] else !cli_key_sk) in
			let dec_func = if s = magic_v1 then decrypt_v1 else decrypt in
			Fun.protect ( fun () ->
					if fn_used then fdesc_dst := Unix.openfile
						fn_dst [O_WRONLY; O_CREAT; O_EXCL] 0o600;
					try dec_func sk_list !fdesc_src !fdesc_dst
					with e -> if fn_used then Unix.unlink fn_dst; raise e )
				~finally:(fun () -> List.iter nacl_key_free sk_list);
			if fn_used then Unix.unlink fn

		| s ->
			let fn_dst = fn ^ ".ghg" in
			let key = nacl_gen_key () in
			let sk_list, pk_list = ref [], ref [] in
			Fun.protect ( fun () ->
					sk_list := key_parse_list true !cli_key_sk;
					pk_list := key_parse_list false !cli_key_pk;
					let sk = List.nth !sk_list 0 in (* no need for >1 sk, as its pk is embedded in the slot *)
					let key_slots = List.map (fun pk -> nacl_key_encrypt sk pk key) !pk_list in
					if fn_used then fdesc_dst := Unix.openfile
						fn_dst [O_WRONLY; O_CREAT; O_EXCL] 0o644;
					try encrypt key key_slots s !fdesc_src !fdesc_dst
					with e -> if fn_used then Unix.unlink fn_dst; raise e )
				~finally:(fun () -> List.iter nacl_key_free (!sk_list @ !pk_list));
			if fn_used then Unix.unlink fn in

	if (List.length !cli_files) = 0 then cli_files := ["-"];
	List.iter ( fun fn ->
		fdesc_src := Unix.stdin; fdesc_dst := Unix.stdout;
		Fun.protect (fun () -> proc_file fn) ~finally:( fun () ->
			if not !cli_stdout then
				(try Unix.close !fdesc_dst with Unix.Unix_error (Unix.EBADF, _, _) -> ());
			(try Unix.close !fdesc_src with Unix.Unix_error (Unix.EBADF, _, _) -> ()) ) ) !cli_files
