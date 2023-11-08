let operation_t =
  Alcotest.testable
    Packet.pp_operation
    ( = )

let cstruct_t =
  Alcotest.testable
    Cstruct.hexdump_pp
    Cstruct.equal

let bad_mac_packet =
  let hex =
    "04 b6 20 f1 0b 2c 55 9a  18 56 26 0f 00 00 04 65
     4a 4e 42 66 de 17 26 0b  86 88 cc cc c0 a0 9d 94
     36 bf 00 4a 3c 8c 20 ac  01 91 92 94 3f 50 fc 93
     6a 2b 63 40 0d 70 af 72  58 43 64 15 e2 06 51 41
     74 fd fd 90 32 89 8a 95  67 4c 47 73 cb 9a 63 78
     bc 70 fc 71 ca 02 d6 18  2c 0d cf d1 63 de 14 af
     4a 1d ee c6 cb 28 79 2c  2a 93 97 5f 0b e7 c3 f4
     eb 57 c8 ac 08 51 23 9e  0a 4f 5e 89 a0 11 00 67
     c9 f8 b4 52 39 98 31 1c  18 d3 d3 c0 76 00 67 15
     3e 6b 21 5f 56 9d 92 c4  d5 bf a4 37 2a 0b 00 e4
     3b fc df 4b 82 2d e1 ac  f1 a1 56 dc 95 28 41 b5
     ad 10 c7 68 96 60 d5 de  43 69 31 de b5 4f 7d ac
     59 7f 27 c8 d2 9d d5 3c  71 a5 7f 8b a2 03 78 06
     33 d1 fb b5 ff 70 52 c5  8c 9e 05 37 6e 11 08 98
     2b 31 7f c8 34 38 be f3  a5 02 80 76 da c4 fb 01
     00 e8 20 f1 0b 2c 55 9a  18 56 26 0f 00 00 06 65
     4a 4e 42 1e 75 0d 8c bf  15 cc 0f 14 5b 1c a8 90
     f7 36 6d d1 9e 13 ef 6e  9b dc f0 0b a4 b4 08 c9
     5b 8c 29 e9 69 71 a6 8d  d7 24 88 8b 16 79 94 71
     20 50 6b eb 9d 9e dd d4  44 5e a1 1a 87 93 04 9a
     0e 0f 97 85 d2 0c 8b 2e  44 d7 56 71 dd da f6 a2
     ea d6 be 65 2d 6e d1 b3  da 87 7d 24 7f 41 8b e3
     ac d5 f0 20 8a e1 0f 1a  9c f3 72 d5 8e 8b 50 5c
     99 2b 84 15 07 2a 79 e4  64 33 e4 7b 03 4b 45 4f
     6a 8b 6f 7f eb 82 c3 19  b6 f3 ac 61 69 bc 0f 8d
     60 07 e1 1e dd 76 38 79  15 4c c3 dc 3e 72 3e b6
     8b 7e bb 4b 79 da 0e 40  ac 38 ce ba 6c d9 c8 9a
     a3 c4 2f 31 19 f8 e5 88  18 4d e3 03 7b 41 7a be
     b3 7d cb 39 b9 db c0 d2  5c 6f 2d 00 d1 ef f8 48
     91 00 fc 84 7e fb 67 de  4d db 01 1d 20 f1 0b 2c
     55 9a 18 56 26 0f 00 00  07 65 4a 4e 42 ce d5 84
     6f cb ed a0 19 ad f7 09  74 be 36 62 21 85 7d 8d
     6a 0b 6b 55 41 b3 48 3e  9b 14 e3 3f 8e ff 53 c1
     8e 4e 4d 83 2a 3a 29 34  96 61 1e 0e 29 d0 b3 7d
     47 ea 2d 8f b6 ff 8f 75  5c d2 c8 8b dc f5 fa ff
     a9 f5 77 f5 82 fa df aa  88 23 72 2c 10 89 9d fc
     da 79 a3 9c 94 f4 d2 fa  12 40 ef 71 d2 99 86 ff
     40 57 09 53 72 c1 19 ab  07 e5 d7 68 44 d8 ee 23
     ef 6f 24 05 b0 fd c2 72  44 29 cb af 6f 2e 5e 5f
     6a 6d f6 b7 60 49 b9 b0  5d 02 41 21 5a d7 4a 16
     cc cd a6 01 6e c0 9d 71  f9 99 25 8c a4 ec 8e e5
     d9 a3 3f a3 b2 d5 8c d0  f4 30 1a 42 bc 16 a3 84
     56 f7 6d ee 40 e0 a0 a0  f0 57 11 55 9f 1f 32 e4
     b7 8e 6a 51 b1 ed d1 f6  6c ae 7d c8 85 73 ed c3
     51 03 49 2c 32 bd f2 c8  d0 7a ec 5e 4e 50 c5 ec
     f9 ab fc 04 a5 d3 40 b9  9a 46 e8 6e 3f 81 b5 3c
     70 9b 85 5d 63 f2 07 a8  48 fd 50 cf 1b f4 ab ea
     11 68 bc a3 76 f8 97 3d  e0 00 ec 20 f1 0b 2c 55
     9a 18 56 26 0f 00 00 08  65 4a 4e 42 c7 07 81 7e
     70 c6 dc fc e2 2a f4 f0  04 3e 92 92 f5 b6 9a d8
     0e 08 94 c7 62 e1 91 89  36 ba c5 f2 c8 5e 3a 76
     4a ce 8a 18 55 46 c3 1f  9f 23 48 53 b0 b7 70 53
     9c 06 99 d2 27 7d 17 86  82 b7 72 74 fd 8e 8f a5
     4b 52 01 7b 5a 2c 02 02  95 9c a0 81 17 2c 7d af
     16 7a 47 a1 5d bf 8f 0f  c5 6b 9f 93 f9 8c f7 e8
     a0 a9 be 84 de fd 8e a6  90 e7 a6 30 ee 5c b9 3b
     d9 a5 a7 ba 3b 3b 6a a6  f7 cb ee a0 c6 67 2c 59
     67 09 a0 fb 57 9b 99 77  23 68 cf be ee 60 1b c2
     07 02 14 df cb 71 15 6f  08 cf 19 50 96 a4 40 6b
     d7 0b a2 5d 0d 81 b4 b7  43 9c 19 93 c6 09 2a 7c
     28 29 66 95 71 d1 0c 40  06 bc 21 b8 94 28 db 86
     44 68 93 9a 06 f6 e2 41  b6 01 e7 21 7c a6 8d 02
     85 c0 75 7a 1b be 45 01  1d 20 f1 0b 2c 55 9a 18
     56 26 0f 00 00 09 65 4a  4e 42 a4 3c c3 89 93 0b
     0f 43 1e d7 87 dc 9c e6  d7 01 6e 13 68 43 1d e1
     81 1b 9c c6 0a b0 bb 35  eb ae a8 ed c5 e4 24 b0
     7a a5 01 7c c2 92 3d de  6f 55 33 ab 16 06 27 c3
     c9 82 dd 7c ca 8c ff 4d  2b a7 d7 f3 4a f6 74 33
     b0 de ad 5f c5 9c 94 42  da f3 e7 c1 02 9f 03 52
     be 78 12 8c 4d d4 02 27  84 48 d6 73 01 e5 d9 50
     f4 29 02 0b c4 ca 1f 13  b4 a1 f5 cf 07 62 37 f4
     bc d4 f1 4a 82 1b e6 32  3f 2e ac 30 45 92 e8 ca
     c9 f7 ef d0 62 ce 38 40  ff 7e 5a 0d 9f 40 1d bd
     b7 38 31 e6 e1 4e 31 8a  74 2d a9 31 e0 18 a6 3c
     52 7a f7 83 b6 37 ea 31  a0 f9 22 77 95 df 82 44
     40 2c 5d f0 17 81 9b cc  3a bd 92 b9 d5 f6 95 8a
     ab a6 f5 7c fb a7 ea 87  28 7c 29 6d 46 96 a8 1d
     3b 24 b0 26 ff 64 30 3d  8c a2 26 47 74 2b a1 f9
     74 4d 16 07 a3 70 cf 11  4a 27 16 3e 64 77 6a b0
     8b 05 e4 c5 ef 8d 13 7a  8a c2 c2 41 6e 89 53 86
     b7 57 42 8d ca d3"
  in
  Cstruct.of_hex hex

let client2_key =
  Base64.decode_exn
    "3heIqPoM22H0Dai9NMq2+KIlYndO56/mVjB/zQqyB/D1qNiatBQ92Xk4A1Wmz/Sb\
1spJ+Tp0A0PYBsAqPA1zchz8g6m+FylTT1LMRFxlmuhNeV+hTukLPRmPhPXNRwpH\
coiAc5y5Af3TZLEJC2RmaC6nByfc73kfxXjw++Ud1OnNj+SMYeYwmmLeUETURScG\
qRNzHcSkPAdo9w78Qm2ng5mjVhVb9kK/p2KA4twREABMV0Zcy/v1ZnDdOCmnt7uq\
ti0RRvESpg5OBc+141doL3pUOmc0/kE0lhwsbGxCWsVUbYu7A6+ii5l/1SL/gMic\
KhZMuNf3230k1jBNVruHfSIfvT/oHmU2z+weqjEFw3W6eyUdDSMEV7XIVbLFpCbl\
5UsL5u9JgMYC/rXLU86D0DDE3AictXEjFNTw0dbUe3DGG8yitKBlDW66+ZUianyZ\
pe2xTpy2oh4aSDDIBEAG+fjQFxNXrzDjJf8qDLh9zesKZZpHm6oGWsw6d5l3Ofoh\
mFSRdN76B/9quDDsRNsF3zcHGuRLkVzl+547jrSzbMWoLPw8alnyl3rKH0j7TRa2\
HZCbPJ59Xlunqv2wquK0wRNs6E9x04g0uVJO/Z3KYkVEdZOFsvfQ8NdhipHZQbFq\
+JrfUZMaRypHBAvmdTj+7ddaZncyPzUkWHv+gSou0S0rCb4tCUa48fKvncB+hMR2\
3NRBAG8ASp3EuZyaOkbcpzZ8nrpMUepxiWBRk94BLw=="


let control_v1_tls_crypt_v2 () =
  let orig_computed_mac =
    Cstruct.of_hex
      "b1 bf 35 51 db ea 95 74  fa ed 2d df be 5d fa fd
    29 7c 99 7b cf d7 6a 2a  d7 fc 58 ca 1e 1f e3 a4"
  in
  let their_key =
    Cstruct.of_string client2_key ~len:32
    |> Mirage_crypto.Cipher_block.AES.CTR.of_secret
  in
  let their_hmac = Cstruct.of_string client2_key ~off:64 ~len:Packet.Tls_crypt.hmac_len in
  let op, key, payload, rest =
    match Packet.decode_key_op `Tcp bad_mac_packet with
    | Error e -> Alcotest.failf "Packet.decode_key_op: %a" Packet.pp_error e
    | Ok r -> r
  in
  Alcotest.check operation_t "operation" Packet.Control op;
  Alcotest.(check int) "key" 0 key;
  let _ = their_hmac and _ = orig_computed_mac and _ = rest in
  (* Alcotest.check cstruct_t "rest" Cstruct.empty rest (* apparently not empty *) *)
  let clear_hdr, off =
    match Packet.Tls_crypt.decode_cleartext_header payload with
    | Error e -> Alcotest.failf "Packet.Tls_crypt.decode_cleartext_header: %a" Packet.pp_error e
    | Ok r -> r
  in
  Alcotest.(check int64) "local_session" 0xf10b2c559a185626L clear_hdr.local_session;
  Alcotest.(check int32) "packet_id" 251658244l clear_hdr.packet_id;
  Alcotest.(check int32) "timestamp" 1699368514l clear_hdr.timestamp;
  Alcotest.check cstruct_t "hmac"
    (Cstruct.of_hex 
       "66 de 17 26 0b 86 88 cc  cc c0 a0 9d 94 36 bf 00
        4a 3c 8c 20 ac 01 91 92  94 3f 50 fc 93 6a 2b 63")
    clear_hdr.hmac;
  let encrypted = Cstruct.shift payload off in
  let iv = Cstruct.sub clear_hdr.hmac 0 16 in
  let ctr = Mirage_crypto.Cipher_block.AES.CTR.ctr_of_cstruct iv in
  let decrypted =
    Mirage_crypto.Cipher_block.AES.CTR.decrypt ~key:their_key ~ctr
      encrypted
  in
  let hdr, msg_id, data =
    match Packet.Tls_crypt.decode_decrypted_control clear_hdr decrypted with
    | Error e -> Alcotest.failf "Packet.Tls_crypt.decode_decrypted_control: %a" Packet.pp_error e
    | Ok r -> r
  in
  Alcotest.(check (list int32)) "ack_message_ids" [1l; 0l] hdr.ack_message_ids;
  Alcotest.(check (option int64)) "remote_session" (Some 4567503907465202985L) hdr.remote_session;
  Alcotest.(check int32) "msg_id" 3l msg_id;
  let hmac = Mirage_crypto.Hash.SHA256.hmac_empty ~key:their_hmac in
  let hmac =
    Mirage_crypto.Hash.SHA256.hmac_feed hmac
      (Cstruct.sub bad_mac_packet 2 17)
  in
  let hmac = Mirage_crypto.Hash.SHA256.hmac_feed hmac decrypted in
  let hmac = Mirage_crypto.Hash.SHA256.hmac_get hmac in
  let to_be_signed = Packet.Tls_crypt.to_be_signed key (`Control (op, (hdr, msg_id, data))) in
  let hmac' = Mirage_crypto.Hash.SHA256.hmac ~key:their_hmac to_be_signed in
  Alcotest.check cstruct_t "computed hmac vs to_be_signed" hmac hmac';
  Alcotest.check cstruct_t "computed hmac vs packet hmac" clear_hdr.hmac hmac'

let mac_tests = [
  ("Control_v1 tls-crypt-v2", `Quick, control_v1_tls_crypt_v2);
]

let tests = [
  ("MAC tests", mac_tests);
]

let () =
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter ();
  Logs.(set_level @@ Some Debug);
  Alcotest.run "MirageVPN packet tests" tests
