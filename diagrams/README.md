Link to Graphviz editor: https://dreampuf.github.io/GraphvizOnline/

URL with #hash to dot/graphviz:
```
tail -1  FILE-WITH-URL  | { head -c 42 >/dev/null;cat; } | python2 -c 'import sys,urllib as ul;print(ul.unquote_plus(raw_input()))'
```

Link to Mermaid editor: https://mermaidjs.github.io/mermaid-live-editor/

URL with #hash to Mermaid:
```
tail -1 FILE-WITH-URL | cut -d '#' -f 2 | cut -d / -f 3-|python -c 'import base64;print(base64.urlsafe_b64decode(raw_input()))'|jq -r .code
```
