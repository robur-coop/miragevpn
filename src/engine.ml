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

let client config now () =
  match Openvpn_config.Conf_map.(find Tls_auth_payload config) with
  | None -> Error (`Msg "no tls auth payload in config")
  | Some (_, my_hmac, _, _) ->
    let my_hmac = Cstruct.sub my_hmac 0 Packet.hmac_len in
    let state = {
      config ; key = 0 ; state = Expect_server_reset ;
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

let handle_inner state now data =
  match state.state, data with
  | Expect_server_reset, `Control (Packet.Hard_reset_server, _) ->
    (* we reply with ACK + TLS client hello! *)
    let state, header = header state (ptime_to_ts_exn now) in
    let p = `Ack header in
    let out = hmac_and_out state.key state.my_hmac header p in
    Ok (state, Some out)
  | _ ->
    Error (`No_transition (state, (state.key, data)))

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
    (`Non_monotonic_message_id (state, hdr)) >>= fun () ->
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
  | `Non_monotonic_message_id (state, hdr) ->
    Fmt.pf ppf "non monotonic message id in %a@ (state %a)"
      Packet.pp_header hdr pp state
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

let handle state now buf =
  let open Rresult.R.Infix in
  Packet.decode buf >>= fun (key, data) ->
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
  handle_inner state' now data
