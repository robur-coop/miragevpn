#!/bin/sh

action="summary --per-file"
if [ $# -eq 1 ]; then
  action=$1
fi
bisect-ppx-report $action --coverage-path test/e2e/ --coverage-path _build/default/test
