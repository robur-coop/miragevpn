
type line = [
  | `Auth_retry of [ `Nointeract ]
  | `Auth_user_pass of [ `Inline | `Path of string ]
  | `Bind
  | `Blank
  | `Ca of [ `Inline | `Path of string ]
  | `Cipher of string
  | `Client
  | `Comp_lzo
  | `Connect_retry of int * int
  | `Dev of [ `Null | `Tap of int | `Tun of int ]
  | `Float
  | `Ifconfig_nowarn
  | `Inline of string * string
  | `Keepalive of int * int
  | `Mssfix of int
  | `Mute_replay_warnings
  | `Nobind
  | `Passtos
  | `Persist_key
  | `Pkcs12 of [ `Inline | `Path of string ]
  | `Proto of [ `Tcp | `Udp ]
  | `Proto_force of [ `Tcp | `Udp ]
  | `Remote of string * int
  | `Remote_cert_key_usage of int
  | `Remote_cert_tls of [ `Server ]
  | `Remote_random
  | `Replay_window of int * int
  | `Resolv_retry of [ `Infinite ]
  | `Socks_proxy of string * int * [ `Inline | `Path of string ]
  | `TLS_min of [ `v1_1 | `v1_2 | `v1_3 ]
  | `Tls_auth of [ `Inline | `Path of string ]
  | `Tls_client
  | `Tun_mtu of int
  | `Verb of int
]

val pp_line : line Fmt.t

val parse : string -> (line list, string) result
