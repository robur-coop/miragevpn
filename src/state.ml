
type client_state =
  | Client_reset
  | Server_reset

let pp_client_state ppf = function
  | Client_reset -> Fmt.string ppf "client reset"
  | Server_reset -> Fmt.string ppf "server reset"

type t = {
  config : Openvpn_config.line list ;
  key : int ;
  state : client_state ;
  my_hmac : Cstruct.t ;
  my_session_id : int64 ;
  my_packet_id : int32 ;
  my_message_id : int32 ;
  their_hmac : Cstruct.t ;
  their_session_id : int64 ;
  their_packet_id : int32 ;
  their_message_id : int32 ;
  their_last_acked_message_id : int32 ;
}

let pp ppf t =
  Fmt.pf ppf "key %d state %a, my hmac %a session %Lu packet %lu message %lu@.their hmac %a session %Lu packet %lu message %lu (acked %lu)"
    t.key pp_client_state t.state
    Cstruct.hexdump_pp t.my_hmac t.my_session_id t.my_packet_id t.my_message_id
    Cstruct.hexdump_pp t.their_hmac t.their_session_id t.their_packet_id t.their_message_id t.their_last_acked_message_id

(* TODO maybe these should be elsewhere? *)
open Rresult.R.Infix

let retrieve_host (config : Openvpn_config.line list) =
  (* TODO handle multiple, this only handles the first *)
  match List.find_opt (function `Remote _ -> true | _ -> false) config with
  | None ->
    Logs.err (fun m -> m "no remote found in config") ;
    Error ()
  | Some (`Remote (name, port)) -> Ok (name, port)
  | _ -> assert false

let retrieve_key_block (config : Openvpn_config.line list) =
  match List.find_opt (function `Tls_auth _ -> true | _ -> false) config with
  | None ->
    Logs.err (fun m -> m "tried to retrieve keys, but no tls-auth config") ;
    Error ()
  | Some (`Tls_auth (`Path path)) ->
    Logs.err (fun m -> m "tls-auth configured to be in %s, not yet supported" path) ;
    Error ()
  | Some (`Tls_auth `Inline) ->
    begin match List.find_opt (function `Inline (tag, _) -> tag = "tls-auth" | _ -> false) config with
      | None ->
        Logs.err (fun m -> m "tls-auth configured inline, but no tls-auth inline tag found") ;
        Error ()
      | Some (`Inline (_, data)) -> Ok data
      | _ -> assert false
    end
  | _ -> assert false

let hmac_keys config =
  (* what we get: a "-----BEGIN OpenVPN Static key V1-----" block:
     - 16 lines, hex encoded
     - 16 bytes on each line
     - key offsets are 0, 64, 128, 194 (there are 4 keys in that block)
     - key size is only 20 (for sha1)
    it is not entirely clear which data to use for the hmac keys...
     -> SoftEther uses c->ExpansionKey + 64 for rx, + 192 for tx *)
  retrieve_key_block config >>= fun data ->
  match Astring.String.cuts ~empty:false ~sep:"\n" data with
  | [] | [ _ ] | _ :: _ :: [] ->
    Logs.err (fun m -> m "expected at least two newlines in %s" data) ;
    Error ()
  | fst :: rest ->
    let last, keydata =
      let revd = List.rev rest in
      List.hd revd, List.(rev (tl revd))
    in
    (if fst = "-----BEGIN OpenVPN Static key V1-----" &&
        last = "-----END OpenVPN Static key V1-----" &&
        List.length keydata = 16 &&
        List.for_all (fun l -> String.length l = 32) keydata
     then
       Ok (Cstruct.of_hex (Astring.String.concat keydata))
     else
       Error ()) >>| fun cs ->
    Cstruct.(sub cs 0 20, sub cs 64 20, sub cs 128 20, sub cs 194 20)
