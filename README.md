# linaudit

**A read-only security audit for Linux, with a score from 1 to 10.**

[Leer en castellano](README.es.md) · More information: **<https://lexiworks.dev/linaudit>**

linaudit looks at your Linux machine the way an attacker or an auditor would, and tells you in plain words what
is wrong, how serious it is, and how to fix it. It works on Debian, Ubuntu, RHEL and their derivatives.

- **More than 100 checks in 9 categories**: accounts and sudo, SSH, file permissions, plaintext passwords and
  keys, network and firewall, updates, signs of compromise, system hardening, and common server applications
  (Tomcat, Redis, Docker, PostgreSQL, Samba, Apache, nginx).
- **A score from 1 (worst) to 10 (best)** that is easy to compare between machines, and findings sorted by severity,
  each with the command or setting that fixes it.
- **Safe to run anywhere**: it never changes anything on your system, and when it finds a password or a key it only
  tells you *where* it is, never its value.
- **A friendly terminal interface**, plus a plain-text report and JSON output for scripts and monitoring.
- **In English and Spanish.**

## Install

**Debian and derivatives** (on its way into the Debian archive):

```bash
sudo apt install linaudit
```

**Nix package manager** (with flakes enabled):
```bash
# Main branch
sudo nix run github:alexiarstein/linaudit

# Other branch
sudo nix run github:alexiarstein/linaudit/<branch>
```

**From source** (needs Rust 1.85 or newer):

```bash
git clone https://github.com/alexiarstein/linaudit
cd linaudit
cargo build --release
sudo install -m 755 target/release/linaudit /usr/local/bin/
```

## Use it

```bash
sudo linaudit
```

The first time, linaudit asks which language you prefer. Then it shows your system and asks what kind of machine it
is (a server, a desktop or laptop, or a container), and starts the audit. When it finishes you get three tabs:

- **Summary**: your score, open findings by severity, and the most urgent ones.
- **Findings**: every problem with its details and how to fix it. You can filter by severity or category, search,
  and copy the fix with `y`.
- **Categories**: how well each area is doing.

Press `?` at any moment to see the keyboard shortcuts, and `q` to quit.

> **Run it with `sudo`.** Without root, many checks cannot read what they need (for example the password database
> or the firewall rules). linaudit still runs, but it tells you which checks it could not evaluate and the score
> cannot go above 6.

### Other ways to run it

```bash
sudo linaudit --plain                  # text report instead of the interactive interface
sudo linaudit --plain --all            # also list the checks that passed
sudo linaudit --fast                   # skip the full disk scans: seconds instead of minutes
sudo linaudit --category ssh,accounts  # only some categories
sudo linaudit --profile server         # skip the question about the kind of machine
sudo linaudit --json --output report.json
sudo linaudit --min-score 7            # exit code 1 if the score is below 7 (for cron, CI, monitoring)
```

All the options are in `linaudit --help` and `man linaudit`.

## Profiles: server, desktop or container

Not every check makes sense on every machine. A legal login banner matters on a corporate server, not on your
laptop; the firewall of a container is managed by its host. The profile adapts the criteria:

| Profile | For | What changes |
|---|---|---|
| `server` | servers, VPSs, anything exposed | nothing: every check with its full severity |
| `desktop` | personal computers | relaxes checks meant for corporate servers and lowers the firewall check from HIGH to MEDIUM |
| `container` | containers and short-lived VMs | what the host manages (clock, firewall, kernel, logs) is marked as not applicable |

linaudit detects the right one and suggests it. A profile never hides a check: it only changes its severity or marks
it as not applicable, and says so in the report.

## How the score works

Each check weighs according to its severity (critical, high, medium, low). Passed checks add points, warnings add
half, failures add nothing, and the result is scaled from 1 to 10. Then it is capped by what is still open: with one
critical finding the score cannot go above 6, with two it cannot go above 4, and so on, because a "9 out of 10" with a
critical hole open would be a lie. Checks that could not be evaluated are never counted as good.

## Accepting a finding on purpose

Sometimes a finding is a deliberate decision: for example, the machine is protected by a dedicated firewall in front of
it. Write it down in `/etc/linaudit/waivers.conf`, one line per check, with the reason:

```
NET-001   # Dedicated perimeter firewall. Ticket INF-1234
```

A waived check no longer affects the score, and it is still listed in the report with its reason, so the decision
stays visible.

## Language

linaudit speaks English and Spanish. It asks once, the first time you open it, and remembers your choice in
`~/.config/linaudit/config.toml`. **To choose again, delete that file** (or press `i` on the welcome screen). For a
single run or in scripts, use `--lang en` / `--lang es` or the `LINAUDIT_LANG` variable.

## Weekly audits

The Debian package includes a systemd timer that runs the audit once a week and keeps the latest report in
`/var/lib/linaudit/latest.json`. It is off by default; to turn it on:

```bash
sudo systemctl enable --now linaudit.timer
```

## Good to know

- Reports describe the weak spots of your machine: keep them private.
- Some checks are heuristic and can give false positives, especially the search for passwords in files. Treat
  findings as things to review, not as verdicts.
- linaudit does not replace a formal compliance audit (CIS, STIG), a forensic analysis or an antivirus/EDR. It is a
  fast, honest health check that you can run as often as you like.
- The checks for the Red Hat family (RHEL, Rocky, Alma, Fedora) and NixOS are less tested than the Debian ones. Reports and
  pull requests are very welcome.

## More

- Website and documentation: **<https://lexiworks.dev/linaudit>**
- Full list of checks: [docs/CHECKS.md](docs/CHECKS.md)
- Bugs and ideas: <https://github.com/alexiarstein/linaudit/issues>
- Contributing (building, testing, translating): [CONTRIBUTING.md](CONTRIBUTING.md)

Made by Alexia Michelle. Free software under the [GNU AGPL v3.0 or later](LICENSE).

