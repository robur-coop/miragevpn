(* [or_empty cs] is [cs] unless [Cstruct.is_empty cs] where it is [Cstruct.empty].
   An empty cstruct will keep a live reference to its underlying buffer. It is
   preferable to keep a reference live to [Cstruct.empty.buffer] than
   [cs.buffer] if [cs] is empty. *)
let[@ocaml.inline always] or_empty cs =
  if Cstruct.is_empty cs then Cstruct.empty else cs

(* [Cstruct.sub cs 0 cs.len] will result in an empty cstruct **that keeps a
   live reference to [cs.buffer]**!! *)
let sub cs off len = or_empty (Cstruct.sub cs off len)

(* [Cstruct.shift cs cs.len] has a similar story *)
let shift cs len = or_empty (Cstruct.shift cs len)

(* If we append the empty cstruct and we don't need a fresh copy we can do
   nothing. This has different semantics than Cstruct.append. *)
let append' cs cs' =
  if Cstruct.is_empty cs then cs'
  else if Cstruct.is_empty cs' then cs
  else Cstruct.append cs cs'

let concat_with_empty_prefix prefix_len css =
  let len = prefix_len + Cstruct.lenv css in
  let b = Cstruct.create_unsafe len in
  Cstruct.memset (Cstruct.sub b 0 prefix_len) 0;
  let _ : int =
    List.fold_left
      (fun off cs ->
        let l = Cstruct.length cs in
        Cstruct.blit cs 0 b off l;
        off + l)
      prefix_len css
  in
  b
