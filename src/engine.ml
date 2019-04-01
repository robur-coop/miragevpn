open State

let next_message_id state =
  state.my_message_id, { state with my_message_id = Int32.succ state.my_message_id }

let header state =
  let rec acked_packet_ids id =
    if state.their_packet_id = id then
      []
    else
      id :: acked_packet_ids (Int32.succ id)
  in
  let ack_packet_ids = acked_packet_ids state.their_acked_packet_id in
  let remote_session = match ack_packet_ids with [] -> None | _ -> Some state.their_session_id in
  { Packet.local_session = state.my_session_id ;
    hmac = Cstruct.create_unsafe Packet.hmac_len ;
    packet_id = state.my_packet_id ;
    timestamp = 0l ;
    ack_packet_ids ;
    remote_session
  }, {
    state with their_acked_packet_id = state.their_packet_id ;
               my_packet_id = Int32.succ state.my_packet_id
  }

let client () =
  let state = { key = 0 ; state = Client_reset ;
               my_session_id = 0xF00DBEEFL ;
               my_packet_id = 0l ;
               my_message_id = 0l ;
               their_session_id = 0L ;
               their_packet_id = 0l ;
               their_acked_packet_id = 0l ;
               their_message_id = 0l ;
             }
  in
  let header, state = header state in
  let m_id, state = next_message_id state in
  state, Packet.encode (state.key, `Control (Packet.Hard_reset_client, (header, m_id, Cstruct.empty)))

let handle state buf =
  match Packet.decode buf with
  | Error e ->
    Logs.err (fun m -> m "decoding failed %a@.%a" Packet.pp_error e Cstruct.hexdump_pp buf)
  | Ok data ->
    Logs.info (fun m -> m "state %a, received %a" State.pp state Packet.pp data)
