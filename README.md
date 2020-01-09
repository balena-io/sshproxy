# sshproxy

Configuration is possible via commandline flags, environment variables
and config files.

Config files should be named `sshproxy.<ext>` and exist in the sshproxy
work dir. The following config file formats are supported:

* [YAML](http://yaml.org) (`sshproxy.yml`)
* [JSON](http://www.json.org) (`sshproxy.json`)
* [TOML](https://github.com/toml-lang/toml) (`sshproxy.toml`)
* [HCL](https://github.com/hashicorp/hcl) (`sshproxy.hcl`)
* [Java .properties](https://en.wikipedia.org/wiki/.properties) (`sshproxy.properties`)

There are a total of 15 configuration options and with the exception of `dir`
they can all be set via commandline, environment or config file.

| Name               | Commandline                 | Environment                   | Config               |
|--------------------|-----------------------------|-------------------------------|----------------------|
| Allow Env          | `--allow-env` `-E`          | `SSHPROXY_ALLOW_ENV`          | `allow-env`          |
| API Host           | `--apihost`, `-H`           | `BALENA_API_HOST`             | `apihost`            |
| API Key            | `--apikey`, `-K`            | `SSHPROXY_API_KEY`            | `apikey`             |
| API Port           | `--apiport`, `-P`           | `BALENA_API_PORT`             | `apiport`            |
| Auth Failed Banner | `--auth-failed-banner` `-b` | `SSHPROXY_AUTH_FAILED_BANNER` | `auth-failed-banner` |
| Bind               | `--bind`, `-b`              | `SSHPROXY_BIND`               | `bind`               |
| Dir                | `--dir`, `-d`               | `SSHPROXY_DIR`                |                      |
| Idle Timeout       | `--idle-timeout`, `-i`      | `SSHPROXY_IDLE_TIMEOUT`       | `idle-timeout`       |
| Max Auth Tries     | `--max-auth-tries` `-m`     | `SSHPROXY_MAX_AUTH_TRIES`     | `max-auth-tries`     |
| Metrics Bind       | `--metrics-bind`, `-M`      | `SSHPROXY_METRICS_BIND`       | `metrics-bind`       |
| Sentry DSN         | `--sentry-dsn` `-S`         | `SSHPROXY_SENTRY_DSN`         | `sentry-dsn`         |
| Shell              | `--shell`, `-s`             | `SSHPROXY_SHELL`              | `shell`              |
| Shell GID          | `--shell-gid`, `-g`         | `SSHPROXY_SHELL_GID`          | `shell-gid`          |
| Shell UID          | `--shell-uid`, `-u`         | `SSHPROXY_SHELL_UID`          | `shell-uid`          |
| Use Proxy Protocol | `--use-proxyprotocol`, `-p` | `SSHPROXY_USE_PROXYPROTOCOL`  | `use-proxyprotocol`  |
| Verbosity          | `--verbosity`, `-v`         | `SSHPROXY_VERBOSITY`          | `verbosity`	 	  |

```
Usage of sshproxy:
  -E, --allow-env string            List of environment variables to pass from client to shell (default: None)
  -H, --apihost string              Balena API Host (default "api.balena-cloud.com")
  -K, --apikey string               Balena API Key (required)
  -P, --apiport string              Balena API Port (default "443")
  -B, --auth-failed-banner string   Path to template displayed after failed authentication
  -b, --bind string                 Address the ssh service will bind to (default ":22")
  -d, --dir string                  Work dir, holds ssh keys and sshproxy config (default "/etc/sshproxy")
  -i, --idle-timeout int            Idle timeout (seconds, 0 = none)
  -m, --max-auth-tries int          Maximum number of authentication attempts per connection (default 0; unlimited)
  -M, --metrics-bind string         Address the prometheus metrics server should bind to (default: disabled)
  -S, --sentry-dsn string           Sentry DSN for error reporting
  -s, --shell string                Path to shell to execute post-authentication (default "shell.sh")
  -g, --shell-gid int               Group to run shell as (default: current gid) (default -1)
  -u, --shell-uid int               User to run shell as (default: current uid) (default -1)
  -p, --use-proxyprotocol           Enable Proxy Protocol support
  -v, --verbosity int               Set verbosity level (0 = quiet, 1 = normal, 2 = verbose, 3 = debug, default: 1) (default 1)
      --version                     Display version and exit
```

## Auth Failed Banner/Template

The 'auth failed banner' is a template rendered and displayed to the user after failed authentication. It should be a
[Go template](https://golang.org/pkg/text/template/) has two available properties; `.user` and `.fingerprints`.

## Example Usage

```
% go get github.com/balena-io/sshproxy/balena
% export SSHPROXY_DIR=$(mktemp -d /tmp/sshproxy.XXXXXXXX)
% echo -e '#!/usr/bin/env bash\nenv' > ${SSHPROXY_DIR}/shell.sh && chmod +x ${SSHPROXY_DIR}/shell.sh
  SSHPROXY_PORT=2222 \
  SSHPROXY_API_KEY=... \
  go run ${GOPATH}/src/github.com/balena-io/sshproxy/main.go
...
% ssh -o 'StrictHostKeyChecking=no' \
      -o 'UserKnownHostsFile=/dev/null' \
    balena@localhost -p2222 -- some command
Warning: Permanently added '[localhost]:2222' (RSA) to the list of known hosts.
SSH_USER=balena
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
`docker run --rm -v $PWD:/go/src/github.com/balena-io/sshproxy golang make -C /go/src/github.com/balena-io/sshproxy lint test release`.
