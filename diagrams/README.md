Link to editor: https://dreampuf.github.io/GraphvizOnline/

URL with #hash to dot/graphviz:
```
tail -1  FILE-WITH-URL  | { head -c 42 >/dev/null;cat; } | python2 -c 'import sys,urllib as ul;print(ul.unquote_plus(raw_input()))'
```
