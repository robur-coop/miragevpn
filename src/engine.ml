open State

let guard p e = if p then Ok () else Error e
let opt_guard p x e = match x with None -> Ok () | Some x -> guard (p x) e

let next_message_id state =
  { state with my_message_id = Int32.succ state.my_message_id },
  state.my_message_id

let header state timestamp =
  let rec acked_message_ids id =
    if state.their_message_id = id then
      []
    else
      id :: acked_message_ids (Int32.succ id)
  in
  let ack_message_ids = acked_message_ids state.their_last_acked_message_id in
  let remote_session = match ack_message_ids with [] -> None | _ -> Some state.their_session_id in
  let packet_id = state.my_packet_id
  and their_last_acked_message_id = state.their_message_id
  in
  { state with their_last_acked_message_id ; my_packet_id = Int32.succ packet_id },
  { Packet.local_session = state.my_session_id ;
    hmac = Cstruct.create_unsafe Packet.hmac_len ;
    packet_id = packet_id ;
    timestamp ;
    ack_message_ids ;
    remote_session
  }

let ptime_to_ts_exn now =
  let now = now () in
  match Ptime.(Span.to_int_s (to_span now)) with
  | None -> assert false
  | Some x -> Int32.of_int x

let compute_hmac key p hmac_key =
  let tbs = Packet.to_be_signed key p in
  Nocrypto.Hash.SHA1.hmac ~key:hmac_key tbs

let hmac_and_out key hmac_key header p =
  let hmac = compute_hmac key p hmac_key in
  let p' = Packet.with_header { header with Packet.hmac } p in
  Packet.encode (key, p')


let client config now rng () =
  match Openvpn_config.Conf_map.(find Tls_auth config) with
  | None -> Error (`Msg "no tls auth payload in config")
  | Some (_, my_hmac, _, _) ->
    let authenticator = match Openvpn_config.Conf_map.(find Ca config) with
      | None ->
        Logs.warn (fun m -> m "no CA certificate in config, not verifying peer certificate");
        X509.Authenticator.null
      | Some ca ->
        Logs.info (fun m -> m "authenticating against %s" (X509.common_name_to_string ca));
        X509.Authenticator.chain_of_trust ~time:(now ()) [ ca ]
    in
    let my_hmac = Cstruct.sub my_hmac 0 Packet.hmac_len in
    let state = {
      rng ;
      linger = Cstruct.empty ;
      authenticator ; key = 0 ; client_state = Expect_server_reset ;
      my_hmac ;
      my_session_id = 0xF00DBEEFL ;
      my_packet_id = 1l ;
      my_message_id = 0l ;
      their_hmac = my_hmac ;
      their_session_id = 0L ;
      their_packet_id = 1l ;
      their_message_id = 0l ;
      their_last_acked_message_id = 0l ;
    } in
    let timestamp = ptime_to_ts_exn now in
    let state, header = header state timestamp in
    let state, m_id = next_message_id state in
    let p = `Control (Packet.Hard_reset_client, (header, m_id, Cstruct.empty)) in
    let out = hmac_and_out state.key my_hmac header p in
    Ok (state, out)

let pp_tls_error ppf = function
  | `Eof -> Fmt.string ppf "EOF from other side"
  | `Alert typ -> Fmt.pf ppf "alert from other side %s" (Tls.Packet.alert_type_to_string typ)
  | `Fail f -> Fmt.pf ppf "failure from our side %s" (Tls.Engine.string_of_failure f)

let prf ?sids ~label ~secret ~client_random ~server_random len =
  (* This is the same as TLS_1_0 / TLS_1_1:
     - split secret into upper and lower half
     - compute md5 hmac (with upper half) and sha1 hmac (with lower half)
       - iterate until len reached: H seed ++ H (n-1 ++ seed)
     - XOR the md5 and sha1 output
  *)
  let sids = match sids with
    | None -> Cstruct.empty
    | Some (c, s) ->
      let buf = Cstruct.create 16 in
      Cstruct.BE.set_uint64 buf 0 c;
      Cstruct.BE.set_uint64 buf 8 s;
      buf
  in
  let seed = Cstruct.(concat [ of_string label ; client_random ; server_random ; sids ]) in
  let p_hash (hmac, hmac_len) key =
    let rec expand a to_go =
      let res = hmac ~key (Cstruct.append a seed) in
      if to_go > hmac_len then
        Cstruct.append res (expand (hmac ~key a) (to_go - hmac_len))
      else
        Cstruct.sub res 0 to_go
    in
    expand (hmac ~key seed) len
  in
  let halve secret =
    let size = Cstruct.len secret in
    if size mod 2 <> 0 then assert false;
    Cstruct.split secret (size / 2)
  in
  let s1, s2 = halve secret in
  let md5 = p_hash Nocrypto.Hash.MD5.(hmac, digest_size) s1
  and sha = p_hash Nocrypto.Hash.SHA1.(hmac, digest_size) s2
  in
  Nocrypto.Uncommon.Cs.xor md5 sha

let derive_keys (s : State.t) (key_source : State.key_source) (tls_data : Packet.tls_data) =
  let master_key =
    prf ~label:"OpenVPN master secret" ~secret:key_source.pre_master
      ~client_random:key_source.random1 ~server_random:tls_data.random1 48
  in
  let keys =
    prf ~label:"OpenVPN key expansion" ~secret:master_key
      ~client_random:key_source.random2 ~server_random:tls_data.random2
      ~sids:(s.my_session_id, s.their_session_id)
      (4 * 64)
  in
  keys

let handle_inner state now data =
  let open Rresult.R.Infix in
  match state.client_state, data with
  | Expect_server_reset, `Control (Packet.Hard_reset_server, _) ->
    (* we reply with ACK + TLS client hello! *)
    let state, header = header state (ptime_to_ts_exn now) in
    let state, m_id = next_message_id state in
    let tls, ch =
      let authenticator = state.authenticator in
      Tls.(Engine.client (Config.client ~authenticator ()))
    in
    let state = { state with client_state = TLS_handshake tls }
    and p = `Control (Packet.Control, (header, m_id, ch))
    in
    let out = hmac_and_out state.key state.my_hmac header p in
    Ok (state, [out])
  | TLS_handshake tls, `Control (Packet.Control, (_, _, data)) ->
    (* we reply with ACK + maybe TLS response *)
    let state, header = header state (ptime_to_ts_exn now) in
    (match Tls.Engine.handle_tls tls data with
     | `Fail (f, `Response _) -> Error (`Tls (`Fail f))
     | `Ok (r, `Response out, `Data d) ->
       match r with
       | `Eof | `Alert _ as e ->
         Logs.err (fun m -> m "response %a, TLS payload %a"
                      Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) out
                      Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) d);
         Error (`Tls e)
       | `Ok tls' -> Ok (tls', out, d)) >>= fun (tls', tls_response, d) ->
    Logs.info (fun m -> m "TLS payload is %a"
                  Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) d);
    let state, p =
      let client_state, payload =
        if Tls.Engine.can_handle_appdata tls' then (* this only true after server send finished, i.e. tls_response == None *)
          match tls_response with
          | None ->
            let pre_master, random1, random2 = state.rng 48, state.rng 32, state.rng 32 in
            (* TODO: options and auth+pass from config *)
            let tls_data = Packet.{ pre_master ; random1 ; random2 ; options = Packet.options ; user_pass = None } in
            let key_source = { State.pre_master ; random1 ; random2 } in
            begin match Tls.Engine.send_application_data tls' [Packet.encode_tls_data tls_data] with
              | None -> Logs.err (fun m -> m "send application data failed"); assert false
              | Some (tls'', payload) -> TLS_established (tls'', key_source), Some payload
            end
          | Some _ ->
            Logs.err (fun m -> m "can handle appdata, but client wants to send something as well");
            assert false
        else
          TLS_handshake tls', tls_response
      in
      let state = { state with client_state } in
      match payload with
      | None -> state, `Ack header
      | Some payload ->
        let state, m_id = next_message_id state in
        state, `Control (Packet.Control, (header, m_id, payload))
    in
    let out = hmac_and_out state.key state.my_hmac header p in
    Ok (state, [out])
  | TLS_established (tls, key), `Control (Packet.Control, (_, _, payload)) ->
    (match Tls.Engine.handle_tls tls payload with
     | `Fail (f, `Response _) -> Error (`Tls (`Fail f))
     | `Ok (r, `Response out, `Data d) ->
       match r with
       | `Eof | `Alert _ as e ->
         Logs.err (fun m -> m "response %a, TLS payload %a"
                      Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) out
                      Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) d);
         Error (`Tls e)
       | `Ok tls' -> Ok (tls', out, d)) >>= fun (tls', tls_response, d) ->
    (match tls_response with
     | None -> ()
     | Some _ -> Logs.err (fun m -> m "received TLS response while established"));
    (match d with
     | None -> Error (`Msg "TLS established, expected data, received nothing")
     | Some data ->
       Logs.info (fun m -> m "received tls payload %a" Cstruct.hexdump_pp data);
       Packet.decode_tls_data data >>= fun tls_data ->
       let keys = derive_keys state key tls_data in
       Logs.info (fun m -> m "received tls data %a, keys %a"
                     Packet.pp_tls_data tls_data Cstruct.hexdump_pp keys);
       (* now we send a PUSH_REQUEST\0 and see what happens *)
       let state, header = header state (ptime_to_ts_exn now) in
       let data = Cstruct.of_string "PUSH_REQUEST\000" in
       let tls'', data =
         match Tls.Engine.send_application_data tls' [data] with
         | None -> Logs.err (fun m -> m "send application data failed"); assert false
         | Some (tls'', payload) -> tls'', payload
       in
       let state, m_id = next_message_id state in
       let p = `Control (Packet.Control, (header, m_id, data)) in
       let out = hmac_and_out state.key state.my_hmac header p in
       let client_state = Push_request_sent (tls'', keys) in
       let state' = { state with client_state } in
       Ok (state', [out]))
  | Push_request_sent (tls, _key), `Control (Packet.Control, (_, _, payload)) ->
    (match Tls.Engine.handle_tls tls payload with
     | `Fail (f, `Response _) -> Error (`Tls (`Fail f))
     | `Ok (r, `Response out, `Data d) ->
       match r with
       | `Eof | `Alert _ as e ->
         Logs.err (fun m -> m "response %a, TLS payload %a"
                      Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) out
                      Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) d);
         Error (`Tls e)
       | `Ok tls' -> Ok (tls', out, d)) >>= fun (_tls', tls_response, d) ->
    (match tls_response with
     | None -> ()
     | Some _ -> Logs.err (fun m -> m "received TLS response while established"));
    (match d with
     | None -> Error (`Msg "push request sent, expected data, received nothing")
     | Some data ->
       Logs.info (fun m -> m "push request, received TLS payload %S %a"
                     (Cstruct.to_string data) Cstruct.hexdump_pp data);
       Ok (state, []))
  | _, `Ack _ ->
    Logs.warn (fun m -> m "TODO: ignoring ACK");
    Ok (state, [])
  | _ -> Error (`No_transition (state, (state.key, data)))

let expected_packet state data =
  let open Rresult.R.Infix in
  (* expects monotonic packet + message id, session ids matching *)
  (* TODO track ack'ed message ids from them (only really important for UDP) *)
  let hdr = Packet.header data
  and msg_id = Packet.message_id data
  in
  guard (Int32.equal state.their_packet_id hdr.Packet.packet_id)
    (`Non_monotonic_packet_id (state, hdr)) >>= fun () ->
  opt_guard (Int32.equal state.their_message_id) msg_id
    (`Non_monotonic_message_id (state, msg_id, hdr)) >>= fun () ->
  guard (Int64.equal state.their_session_id 0L ||
         Int64.equal state.their_session_id hdr.Packet.local_session)
    (`Mismatch_their_session_id (state, hdr)) >>= fun () ->
  opt_guard (Int64.equal state.my_session_id) hdr.Packet.remote_session
    (`Mismatch_my_session_id (state, hdr)) >>| fun () ->
  (* TODO do sth with timestamp? *)
  let their_message_id = match msg_id with None -> state.their_message_id | Some x -> Int32.succ x in
  { state with their_session_id = hdr.Packet.local_session ;
               their_packet_id = Int32.succ hdr.Packet.packet_id ;
               their_message_id }

let pp_error ppf = function
  | #Packet.error as e -> Fmt.pf ppf "decode %a" Packet.pp_error e
  | `Non_monotonic_packet_id (state, hdr) ->
    Fmt.pf ppf "non monotonic packet id in %a@ (state %a)"
      Packet.pp_header hdr pp state
  | `Non_monotonic_message_id (state, msg_id, hdr) ->
    Fmt.pf ppf "non monotonic message id %a in %a@ (state %a)"
      Fmt.(option ~none:(unit "no") int32) msg_id Packet.pp_header hdr pp state
  | `Mismatch_their_session_id (state, hdr) ->
    Fmt.pf ppf "mismatched their session id in %a@ (state %a)"
      Packet.pp_header hdr pp state
  | `Mismatch_my_session_id (state, hdr) ->
    Fmt.pf ppf "mismatched my session id in %a@ (state %a)"
      Packet.pp_header hdr pp state
  | `Bad_mac (state, computed, data) ->
    Fmt.pf ppf "bad mac: computed %a, data %a@ (state %a)"
      Cstruct.hexdump_pp computed Packet.pp data pp state
  | `No_transition (state, data) ->
    Fmt.pf ppf "no transition found for data %a@ (state %a)"
      Packet.pp data pp state
  | `Tls tls_e -> pp_tls_error ppf tls_e
  | `Msg msg -> Fmt.string ppf msg

let handle state now buf =
  let open Rresult.R.Infix in
  let rec handle_multi state buf out = match Packet.decode buf with
    | Error `Unknown_operation x -> Error (`Unknown_operation x)
    | Error `Partial -> Ok ({ state with linger = buf }, out)
    | Ok (key, data, linger) ->
      (* verify mac *)
      let computed_mac, packet_mac =
        compute_hmac key data state.their_hmac, Packet.((header data).hmac)
      in
      guard (Cstruct.equal computed_mac packet_mac)
        (`Bad_mac (state, computed_mac, (key, data))) >>= fun () ->
      Logs.info (fun m -> m "mac good@.(state %a@.received %a)"
                    State.pp state Packet.pp (key, data)) ;
      (* _first_ update state with last_received_message_id and packet_id *)
      expected_packet state data >>= fun state' ->
      handle_inner state' now data >>= fun (state', outs) ->
      Logs.debug (fun m -> m "out state is %a" State.pp state);
      Logs.debug (fun m -> m "outs is %a"
                     Fmt.(list ~sep:(unit "@.") Cstruct.hexdump_pp) outs);
      handle_multi state' linger (out@outs)
  in
  handle_multi state (Cstruct.append state.linger buf) []
