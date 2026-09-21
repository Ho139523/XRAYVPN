# VPN appliance

One command turns a fresh Ubuntu/Debian server into a VLESS + Reality VPN
(3X-UI + Xray) with a per-user family filter:

* porn blocked for everyone, even if a client sets its own DNS;
* each VPN user has parents who choose, per site, *always blocked*, *blocked
  only in some places* or *blocked everywhere except some places*;
* places are drawn on a map and the phone reports its position;
* every user you create in 3X-UI automatically gets a parent account, and
  parents can add other parents and change usernames and passwords.

Details, limits and phone setup: [docs/content-policy.md](docs/content-policy.md).

## Install on a new server

Needs root, Ubuntu or Debian (amd64/arm64), 2 GB free disk and a port 443 that
is free. Nothing else has to be installed first.

```
git clone https://github.com/ho139523/xrayvpn.git
cd xrayvpn
sudo ./install.sh
```

Optional, before installing: `cp config/appliance.env.example config/.env` and
edit it (for example `CLIENT_EMAIL=name` for the first VPN user).

The installer checks the machine, installs Docker and the missing tools, starts
3X-UI (pinned to the release this was tested with), creates the VPN inbound and
the first user, installs the content policy and the location gate service, runs
a health check, and prints:

* the VPN link (import it in v2rayNG, Shadowrocket, V2Box, Streisand...),
* the 3X-UI panel address and login,
* the parent page address, `http://192.0.2.1:9099/admin`, reachable only while
  the VPN is connected, and each parent's login (also in
  `state/parent-credentials.txt`),
* the phone URLs for reporting position.

The 3X-UI panel listens on the server's public address with a generated login;
change it or put it behind a firewall if you do not need it.

If a run fails the message says which step. Fix the cause and run it again. If it
stopped after the panel container was created, `sudo ./uninstall.sh` starts clean.

## Moving to another server

A new server has a new address and new Reality keys, so VPN users import a new
link. Users' policies, places, parent accounts and phone tokens can come along:

```
# on the old server
./backup.sh                                   # writes vpn-backup-<date>.tar.gz (keep it private)

# on the new server
sudo ./install.sh --restore vpn-backup-<date>.tar.gz
```

The first VPN user is created with the email from the backup so it picks up its
policy and parents at once. Create any other users in 3X-UI with the same
emails and they attach automatically. Phone automations keep working unchanged:
their addresses do not depend on the server.

## Day to day

```
python3 policy/vpn_policy.py verify           # is everything healthy?
python3 policy/vpn_policy.py parents list     # parent accounts
sudo ./uninstall.sh                           # remove everything this installed
python3 -m unittest discover -s tests         # run the tests
```

## Layout

| Path | Purpose |
| --- | --- |
| `install.sh`, `scripts/` | the installer, one script per step |
| `policy/` | content policy: Xray rules, parent web page, location gate |
| `config/appliance.env.example` | every setting, with defaults |
| `state/` | generated secrets and data (git-ignored) |
| `backup.sh`, `uninstall.sh` | move or remove a server |
| `docs/content-policy.md` | how the filter, places and parents work |
