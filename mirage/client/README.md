# Compiling the unikernel for unix

The configuration file must be stored in the `config/` directory under the name `openvpn.config`.


```bash
set -e
make depend
opam install -y mirage mirage-random-stdlib
mirage configure -t unix --data-kv_ro=direct
make depend
ln -s /path/to/config config/openvpn.config
./main.native
```
