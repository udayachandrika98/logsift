<p align="center">
  <img src="https://img.shields.io/badge/C-11-A8B9CC?logo=c&logoColor=white" alt="C11">
  <img src="https://img.shields.io/badge/build-make-427819" alt="Make">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/tests-31%20passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/dependencies-zero-lightgrey" alt="Dependencies">
</p>

<h1 align="center">logsift</h1>
<p align="center"><b>Filter, summarise and find spikes in log files</b></p>

---

`grep` doesn't know what a log line *is*. It can't filter by severity, group by status code,
or tell you that errors were 40× normal for four minutes at 10:12.

`logsift` parses logs into structured entries first, then filters and aggregates over them.
It sniffs the format, streams the file, and never dies on a malformed line.

Written in C11 — log scanning is a hot loop over a lot of bytes, and it's the same reason
`grep`, `ripgrep` and `awk` live close to the metal.

## Build

```bash
git clone https://github.com/udayachandrika98/logsift
cd logsift
make
```

**No dependencies** — C11 plus POSIX (`regex.h`, `strptime`), both in libc. Builds clean under
`-Wall -Wextra -Wpedantic -Wshadow` on GCC and Clang, Linux and macOS.

```bash
make test              # run the suite
sudo make install      # installs to /usr/local/bin
```

## Find the incident

```console
$ logsift summary examples/api.log
entries   : 1102
first     : 2026-08-01 10:00:02
last      : 2026-08-01 10:29:50
span      : 0:29:48
error rate: 37.48%

by level:
  error      413   37.5%  ##############
  info       344   31.2%  ############
  warn       184   16.7%  ######
  debug      161   14.6%  #####
```

37% errors — but *when*?

```console
$ logsift rate examples/api.log --at-level error -w 60
  2026-08-01 10:12:00     101  ######################################
  2026-08-01 10:13:00      84  ###############################
  2026-08-01 10:14:00      95  ###################################
  2026-08-01 10:15:00     106  ########################################
  2026-08-01 10:17:00       1  #
  ...

4 spike(s) at >= 3.0x the median bucket:
  2026-08-01 10:12:00  101
  2026-08-01 10:13:00  84
  2026-08-01 10:14:00  95
  2026-08-01 10:15:00  106
```

A four-minute window, not a gradual degradation. Which component?

```console
$ logsift top logger examples/api.log -n 5
top 5 by logger:
  api.db            544   49.4%
  api.orders        152   13.8%
  worker.queue      143   13.0%
  api.cache         139   12.6%
  api.auth          124   11.3%
```

`rate` exits `2` when it finds spikes, so it works as an alerting check in cron or CI.

## Commands

| Command | Does |
|---|---|
| `show` | Print matching raw lines (exits `1` if nothing matches) |
| `summary` | Entry count, level histogram, time span, error rate |
| `top KEY` | Most common values of a field — `status`, `path`, `client`, `logger`, `process` |
| `rate` | Entries per time bucket as a bar chart, plus spike detection |

Shared filters on every command:

```
-f, --format FORMAT   app | nginx | syslog | json | auto (default: sniff)
-l, --level LEVEL     keep this level and above
-g, --grep REGEX      raw line must match (POSIX extended)
-v, --invert          invert --grep
    --since / --until ISO time, or an offset like 30m / 2h / 1d
    --field KEY=VALUE require a field value
```

Reads stdin when no file is given, so it composes: `kubectl logs pod | logsift summary`.

## Formats

| Profile | Extracts |
|---|---|
| `app` | `2026-08-01 10:00:00 [INFO] api.auth - message` → timestamp, level, logger |
| `nginx` | Combined access log → client, user, method, path, status, bytes |
| `syslog` | `Aug  1 10:00:00 host sshd[2201]: msg` → host, process, pid |
| `json` | Newline-delimited JSON; unknown keys become queryable fields |

Format is sniffed from the first 20 lines by trying each profile most-specific-first and
taking the one with the most successful parses. Those lines are buffered and re-parsed with
the chosen profile rather than discarded.

## Design notes

**A line that won't parse is kept, not dropped.** It comes back with `parsed = false` and the
raw text as its message, and `summary` reports what share of the file failed to parse.
Silently discarding lines you can't read is how you miss the one line that mattered. Fed 20KB
of `/dev/urandom`, it reports 78 unparsed entries and exits cleanly.

**Entries with no level survive level filtering.** `--level error` won't drop a line just
because no severity could be extracted — a missing level isn't evidence the line is
unimportant. There's a test pinning this.

**Spikes are measured against the median, not the mean.** One enormous spike drags a mean
upward and masks the smaller spikes around it. The example above finds all four minutes of
the incident; a mean-based threshold finds two.

**Syslog gets the current year.** Syslog timestamps carry no year, and defaulting to 1900
breaks every time comparison silently. The syslog profile substitutes the current year before
`strptime`.

**Unparsed entries alias `message` to `raw` instead of copying it.** That halves the
allocations on a file that's mostly unparseable — and `entry_free` checks the pointers before
freeing so it can't double-free. It's the kind of thing that's fine until someone changes it
without reading, so the invariant is commented at the free site.

## Tests

```console
$ make test
...............................

31 passed (31 tests)
```

Covers all four format parsers, level aliasing (`CRITICAL` → `fatal`, `warning` → `warn`),
every filter and their AND-combination, malformed-input handling, aggregation, the
median-vs-mean spike property, and the syslog year substitution.

The harness is [`tests/check.h`](tests/check.h) — ~90 lines using `__attribute__((constructor))`
so test cases self-register, and reporting every failure rather than aborting on the first.

CI builds on Linux and macOS across GCC and Clang with `-Werror`, and runs the suite plus the
CLI under **AddressSanitizer, UndefinedBehaviorSanitizer and LeakSanitizer** — including
against 20KB of random binary input, a file with no trailing newline, and an empty file.

## Roadmap

- [ ] `--follow` mode for live tailing
- [ ] JSON output for piping into `jq`
- [ ] User-defined format profiles from a config file
- [ ] `mmap` the input for large files instead of `getline`

> Previously implemented in Python — see the git history if you want the comparison.

## License

MIT
