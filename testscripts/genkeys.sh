#!/usr/bin/env bash
set -eux

if which certify
then
  echo certify installed
else
  opam switch default
  opam install certify
fi

domain="testing.net"
if ls ca.secret.key
then
  echo ca exists
else
  certify selfsign --ca -k ca.secret.key -c ca.public.certificate $domain
fi

certify csr --out server.csr -k server.secret.key server.$domain "server cert"
certify sign --cain ca.public.certificate --key ca.secret.key --csrin server.csr --out server.public.certificate

function newclient () {
  name=$1
  if ls $name.csr
  then
    echo "client $1 exists"
  else
    certify csr --out $name.csr -k $name.secret.key $name.$domain "$name cert"
    certify sign --client --cain ca.public.certificate --key ca.secret.key --csrin $name.csr --out $name.public.certificate
  fi
}
newclient client1

echo DONE
