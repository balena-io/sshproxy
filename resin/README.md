# sshproxy/resin

A "resin-ready" binary, requiring minimal configuration.

Configuration is possible via commandline flags, environment variables
and config files.

Config files should be named `sshproxy.<ext>` and exist in the sshproxy
work dir. The following config file formats are supported:

* [YAML](http://yaml.org) (`sshproxy.yml`)
* [JSON](http://www.json.org) (`sshproxy.json`)
* [TOML](https://github.com/toml-lang/toml) (`sshproxy.toml`)
* [HCL](https://github.com/hashicorp/hcl) (`sshproxy.hcl`)
* [Java .properties](https://en.wikipedia.org/wiki/.properties) (`sshproxy.properties`)

There are a total of 7 configuration options. With the exception of `dir`
they can all be set via commandline, environment or config file.

| Name          | Commandline      | Environment        | Config    |
|---------------|------------------|--------------------|-----------|
| API Host      | `--apihost` `-H` | `RESIN_API_HOST`   | `apihost` |
| API Port      | `--apiport` `-P` | `RESIN_API_PORT`   | `apiport` |
| API Key       | `--apikey` `-K`  | `SSHPROXY_API_KEY` | `apikey`  |
| Dir           | `--dir` `-d`     | `SSHPROXY_DIR`     |           |
| Port          | `--port` `-p`    | `SSHPROXY_PORT`    | `port`    |
| Shell         | `--shell` `-s`   | `SSHPROXY_SHELL`   | `shell`   |
| Unauth Banner | `--unauth` `-u`  | `SSHPROXY_UNAUTH`  | `unauth`  |

```
Usage of sshproxy:
  -H, --apihost string   Resin API Host (default "api.resin.io")
  -K, --apikey string    Resin API Key (required)
  -P, --apiport string   Resin API Port (default "443")
  -d, --dir string       Work dir, holds ssh keys and sshproxy config (default "/etc/sshproxy")
  -p, --port int         Port the ssh service will listen on (default 22)
  -s, --shell string     Path to shell to execute post-authentication (default "shell.sh")
  -u, --unauth string    Path to template displayed after failed authentication
```

## Unauth Template

The 'unauth template' is a template rendered and displayed to the user after failed authentication. It should be a
[Go template](https://golang.org/pkg/text/template/) has two available properties; `.user` and `.fingerprints`.

## Example Usage

```
% go get github.com/resin-io/sshproxy/resin
% export SSHPROXY_DIR=$(mktemp -d /tmp/sshproxy.XXXXXXXX)
% echo -e '#!/usr/bin/env bash\nenv' > ${SSHPROXY_DIR}/shell.sh && chmod +x ${SSHPROXY_DIR}/shell.sh
  SSHPROXY_PORT=2222 \
  SSHPROXY_API_KEY=... \
  go run ${GOPATH}/src/github.com/resin-io/sshproxy/resin/main.go
...
% ssh -o 'StrictHostKeyChecking=no' \
      -o 'UserKnownHostsFile=/dev/null' \
    resin@localhost -p2222 -- some command
Warning: Permanently added '[localhost]:2222' (RSA) to the list of known hosts.
SSH_USER=resin
PWD=...
LANG=en_GB.UTF-8
SHLVL=1
SSH_ORIGINAL_COMMAND=some command
LC_CTYPE=en_GB.UTF-8
_=/usr/bin/env
```
