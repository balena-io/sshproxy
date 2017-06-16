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

There are a total of 9 configuration options. With the exception of `dir`
they can all be set via commandline, environment or config file.

| Name               | Commandline                 | Environment                   | Config               |
|--------------------|-----------------------------|-------------------------------|----------------------|
| API Host           | `--apihost` `-H`            | `RESIN_API_HOST`              | `apihost`            |
| API Port           | `--apiport` `-P`            | `RESIN_API_PORT`              | `apiport`            |
| API Key            | `--apikey` `-K`             | `SSHPROXY_API_KEY`            | `apikey`             |
| Dir                | `--dir` `-d`                | `SSHPROXY_DIR`                |                      |
| Port               | `--port` `-p`               | `SSHPROXY_PORT`               | `port`               |
| Shell              | `--shell` `-s`              | `SSHPROXY_SHELL`              | `shell`              |
| Auth Failed Banner | `--auth-failed-banner` `-b` | `SSHPROXY_AUTH_FAILED_BANNER` | `auth-failed-banner` |
| Max Auth Tries     | `--max-auth-tries` `-m`     | `SSHPROXY_MAX_AUTH_TRIES`     | `max-auth-tries`     |
| Allow Env          | `--allow-env` `-E`          | `SSHPROXY_ALLOW_ENV`          | `allow-env`          |
| Sentry DSN         | `--sentry-dsn` `-S`         | `SSHPROXY_SENTRY_DSN`         | `sentry-dsn`         |

```
Usage of sshproxy:
  -E, --allow-env                   Pass environment from client to shell (default: false) (warning: security implications)
  -H, --apihost string              Resin API Host (default "api.resin.io")
  -K, --apikey string               Resin API Key (required)
  -P, --apiport string              Resin API Port (default "443")
  -b, --auth-failed-banner string   Path to template displayed after failed authentication
  -d, --dir string                  Work dir, holds ssh keys and sshproxy config (default "/etc/sshproxy")
  -m, --max-auth-tries int          Maximum number of authentication attempts per connection (default 0; unlimited)
  -p, --port int                    Port the ssh service will listen on (default 22)
  -S, --sentry-dsn string           Sentry DSN for error reporting
  -s, --shell string                Path to shell to execute post-authentication (default "shell.sh")
```

## Auth Failed Banner/Template

The 'auth failed banner' is a template rendered and displayed to the user after failed authentication. It should be a
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

### Building

The `Makefile` in the project root contains all necessary rules for linting, testing and building sshproxy packages.
Building via a Docker image can be achieved with, for example:
`docker run --rm -v $PWD:/go/src/github.com/resin-io/sshproxy golang make -C /go/src/github.com/resin-io/sshproxy lint test release`.

