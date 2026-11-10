# Production secrets from OpenBao

`deploy/load-secrets.sh` creates the `brigid_master_key` Docker secret from OpenBao, so the
master key lives in one place and a rebuilt VM gets it back without anyone pasting it.

| What | Where |
| ---- | ----- |
| OpenBao | `https://bao.baxyz.dev:8200`, reachable on the tailnet only |
| Secret | KV v2 mount `kv`, path `prod/brig-id/leaf-1` |
| Fields | `BRIGID_MASTER_KEY` (64 hex), `ORACLE_CLOUD_PUBLIC_IP`, `ORACLE_CLOUD_PRIVATE_IP` |
| VM credentials | AppRole `leaf-1`, files `/etc/brigid/bao-role-id` and `/etc/brigid/bao-secret-id` |

## One-time setup

### 1. Join the leaf-1 VM to the tailnet

In the Tailscale admin console:

1. Access controls: declare the tag and let the leaf-1 VM reach OpenBao, and nothing else. The
   tag names the org (the tailnet is shared with other projects) and the role, so a future
   second leaf reuses it; the per-machine restriction is the AppRole's CIDR binding below.
   `dst` takes an IP or a `hosts` alias, not a bare machine name: without the `hosts` entry
   the editor rejects the policy (`"fajro": invalid address`).

   ```jsonc
   "tagOwners": { "tag:brigid-leaf": ["autogroup:admin"] },
   // The tailnet IP of the machine serving OpenBao (what bao.baxyz.dev resolves to).
   "hosts":     { "fajro": "100.67.31.127" },
   "grants": [
     { "src": ["tag:brigid-leaf"], "dst": ["fajro"], "ip": ["tcp:8200"] }
   ],
   "tests": [
     { "src": "tag:brigid-leaf", "accept": ["fajro:8200"], "deny": ["fajro:22"] }
   ]
   ```

2. Settings → Keys → Generate auth key: not reusable, not ephemeral, pre-approved,
   tag `tag:brigid-leaf`. Tagged nodes have key expiry off, so the VM stays connected.

On the leaf-1 VM (`ssh ubuntu@helm.brig.id`):

```bash
curl -fsSL https://tailscale.com/install.sh | sh
# --accept-dns=false: bao.baxyz.dev is in public DNS, and Docker keeps the VM's resolver
sudo tailscale up --auth-key=tskey-auth-... --hostname=brigid-leaf-1 --accept-dns=false
tailscale ip -4                                    # the VM's tailnet IP, used in step 2
curl -sS https://bao.baxyz.dev:8200/v1/sys/health  # must answer
```

No inbound port is needed: Tailscale connects outbound (UDP 41641, or HTTPS relays).

### 2. AppRole for the leaf-1 VM

On fajro, the machine that serves OpenBao (or any machine with an OpenBao admin token):

```bash
bao policy write leaf-1 - <<'EOF'
path "kv/data/prod/brig-id/leaf-1" { capabilities = ["read"] }
EOF

VM_IP=...   # the output of `tailscale ip -4` on the VM, e.g. 100.64.0.1
bao write auth/approle/role/leaf-1 \
  token_policies=leaf-1 token_ttl=5m token_max_ttl=10m \
  secret_id_bound_cidrs="$VM_IP/32" token_bound_cidrs="$VM_IP/32"

bao read -field=role_id auth/approle/role/leaf-1/role-id
bao write -f -field=secret_id auth/approle/role/leaf-1/secret-id
```

The bindings match the address OpenBao sees: run the script on the VM itself, not from a
container, whose traffic may not carry the tailnet IP.

Note the policy names the secret's own path: `prod/brig-id/leaf-1/*` would match only paths
below it, not the secret itself.

On the leaf-1 VM, store both values, readable by root only:

```bash
sudo install -d -m 700 /etc/brigid
sudo sh -c 'umask 077; cat > /etc/brigid/bao-role-id'    # paste, then Ctrl-D
sudo sh -c 'umask 077; cat > /etc/brigid/bao-secret-id'  # paste, then Ctrl-D
```

### 3. Get the script onto the VM

The VM has no checkout of this repository. Fetch the script and compare it with the version
you reviewed (`sha256sum deploy/load-secrets.sh` in a checkout):

```bash
curl -fsSLo load-secrets.sh \
  https://raw.githubusercontent.com/brig-id/server-leaf/main/deploy/load-secrets.sh
sha256sum load-secrets.sh
chmod +x load-secrets.sh
```

### 4. Check

```bash
sudo ./load-secrets.sh --check
```

## On every deployment

```bash
sudo ./load-secrets.sh   # creates the Docker secret only if it is missing
```

The script leaves an existing secret alone: Swarm secrets cannot change while a service uses
them. Rotating the master key stays a separate procedure (`leaf rotate-key`, then a new
secret).
