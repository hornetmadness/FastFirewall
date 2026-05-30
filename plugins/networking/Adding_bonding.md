# Plan: Bond Interface CRUD Endpoints

## Context

The networking plugin manages interfaces and routes via ifstate. Bonded interfaces (LACP/802.3ad and other modes) require coordinated management of a logical bond interface plus its physical member interfaces. Currently there is no bond-aware API — users would have to manually `PUT /config/interfaces` for the bond and each member separately. This plan adds a dedicated `/config/bonds` resource that treats a bond as a single unit.

## Storage model

Bonds are stored in `self._interfaces` (unchanged from existing format) as two kinds of entries:

- Bond interface: `{link: {kind: "bond", state: "up", bond_mode: "802.3ad", bond_miimon: 100, ...}, addresses: [...]}`
- Each member: `{link: {kind: "physical", state: "up", master: "bond0"}}`

`_build_ifstate_yaml()` already passes through all `link.*` keys verbatim, so no changes to the YAML builder are needed.

## Files to modify

- `plugins/networking/plugin.py` — models, helpers, handlers, route registration
- `plugins/networking/test_networking_api_routes.py` — new test cases
- `plugins/networking/CLAUDE.md` — document new endpoints and events

---

## 1. New Pydantic models (add after `AliasCreate`, before `_ALIAS_NAME_RE`)

```python
BondMode = Literal[
    "802.3ad", "active-backup", "balance-rr",
    "balance-xor", "broadcast", "balance-tlb", "balance-alb",
]

class BondCreate(BaseModel):
    name: str = Field(max_length=15)
    mode: BondMode = "802.3ad"
    members: list[Annotated[str, Field(max_length=15)]] = Field(min_length=1)
    addresses: Optional[list[str]] = None
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)
    ad_lacp_rate: Optional[Literal["slow", "fast"]] = None
    xmit_hash_policy: Optional[Literal["layer2","layer2+3","layer3+4","encap2+3","encap3+4","vlan+srcmac"]] = None
    miimon: Optional[int] = Field(default=None, ge=0, le=10000)
    updelay: Optional[int] = Field(default=None, ge=0, le=60000)
    downdelay: Optional[int] = Field(default=None, ge=0, le=60000)
    min_links: Optional[int] = Field(default=None, ge=0, le=64)
    # addresses validator reusing _validate_cidr (same pattern as InterfaceUpdate)

class BondUpdate(BaseModel):
    # all fields Optional — only supplied fields are applied (exclude_unset=True)
    mode: Optional[BondMode] = None
    members: Optional[list[Annotated[str, Field(max_length=15)]]] = None
    addresses: Optional[list[str]] = None
    mtu: Optional[int] = Field(default=None, ge=68, le=65535)
    ad_lacp_rate: Optional[Literal["slow", "fast"]] = None
    xmit_hash_policy: Optional[Literal["layer2","layer2+3","layer3+4","encap2+3","encap3+4","vlan+srcmac"]] = None
    miimon: Optional[int] = Field(default=None, ge=0, le=10000)
    updelay: Optional[int] = Field(default=None, ge=0, le=60000)
    downdelay: Optional[int] = Field(default=None, ge=0, le=60000)
    min_links: Optional[int] = Field(default=None, ge=0, le=64)
    # addresses validator reusing _validate_cidr

class BondAddMember(BaseModel):
    interface: str = Field(max_length=15)
```

## 2. Helper methods (add after `_desired_snapshot`)

**`_get_bond_members(self, bond_name) -> list[str]`**
Scan `self._interfaces` for entries where `link.master == bond_name`.

**`_bond_to_response(self, name) -> dict`**
Build response from the bond entry + member list:
```json
{"name": "bond0", "mode": "802.3ad", "members": ["eth0","eth1"],
 "addresses": [...], "miimon": 100, "updelay": 300, ...}
```
Only include optional bond_* keys when present in link dict.

**`_parse_proc_bond(text: str) -> dict`** (module-level)
Parse the `/proc/net/bonding/<name>` text format into structured JSON. Iterates lines:
- Top-level `Key: Value` pairs (before any `Slave Interface:` section) map to bond-level fields
- Each `Slave Interface:` line starts a new member block; subsequent key/value pairs until the next slave or EOF belong to that member
- Numeric values (speeds, counts, intervals) are cast to `int`; unknown fields are included as raw strings so the parser is forward-compatible

## 3. CRUD handlers

| Handler | Method | Path | Status |
|---|---|---|---|
| `_list_bonds` | GET | `/config/bonds` | 200 |
| `_create_bond` | POST | `/config/bonds` | 201 |
| `_get_bond` | GET | `/config/bonds/{name}` | 200 |
| `_update_bond` | PUT | `/config/bonds/{name}` | 200 |
| `_delete_bond` | DELETE | `/config/bonds/{name}` | 200 |
| `_get_bond_status` | GET | `/bonds/{name}/status` | 200 |
| `_add_bond_member` | POST | `/config/bonds/{name}/members` | 201 |
| `_delete_bond_member` | DELETE | `/config/bonds/{name}/members/{member}` | 200 |

**`_create_bond`** — 409 if `body.name` already in `_interfaces`; 409 if any member is already a member of a *different* bond. Creates bond entry + one entry per member. **Alias redirect on add:** for each member, scan `_aliases` for any entry pointing to that member (`alias_value == member_name`) and redirect it to the bond name instead. Set default alias for bond (`setdefault(bond_name, bond_name)`). Saves state, emits `networking.interface.configured` for the bond.

**`_update_bond`** — uses `model_dump(exclude_unset=True)`. For the `members` field: computes old vs new member sets. For newly added members, apply the same alias redirect as `_create_bond`. For removed members, aliases that were redirected to the bond are *not* automatically restored (member is leaving the bond; caller should manage aliases explicitly). For bond link params, `None` values remove the key from link; `mode=None` is ignored. Emits `networking.interface.configured`.

**`_delete_bond`** — removes all member entries then the bond entry, saves state, emits `networking.interface.removed`.

**`_add_bond_member`** — 409 if interface is already a member of any bond. Adds the member entry. **Alias redirect:** redirect any existing aliases pointing at the member to the bond (same logic as `_create_bond`). Saves state, emits `networking.interface.configured`, returns updated bond response.

**`_delete_bond_member`** — 422 if the interface is not a member of *this* bond (vs 404 if not in config at all). Removes member, saves state, emits `networking.interface.removed`, returns updated bond response.

**`_get_bond_status`** — live status from `/proc/net/bonding/{name}`. Returns 404 if the bond isn't up in the kernel (file absent). Parses the procfs text into structured JSON. Helper `_parse_proc_bond(text) -> dict` handles the parsing — top-level fields (bonding mode, MII status, active slave, etc.) plus a `members` list with per-slave fields (interface name, MII status, speed, duplex, link failure count, permanent MAC, slave queue ID). The route lives under `/bonds/` (live state prefix), not `/config/bonds/`, consistent with the existing `/interfaces/` vs `/config/interfaces/` split.

Example response shape:
```json
{
  "bond": "bond0",
  "mode": "IEEE 802.3ad Dynamic link aggregation",
  "mii_status": "up",
  "mii_polling_interval_ms": 100,
  "members": [
    {"interface": "eth0", "mii_status": "up", "speed_mbps": 1000,
     "duplex": "full", "link_failure_count": 0, "permanent_mac": "00:11:22:33:44:55"},
    {"interface": "eth1", "mii_status": "up", "speed_mbps": 1000,
     "duplex": "full", "link_failure_count": 0, "permanent_mac": "00:11:22:33:44:66"}
  ]
}
```

## 4. Route registration (add after interfaces routes in `_register_routes`)

```python
add("/config/bonds",                         self._list_bonds,         methods=["GET"],    ...)
add("/config/bonds",                         self._create_bond,        methods=["POST"],   status_code=201, ...)
add("/config/bonds/{name}",                  self._get_bond,           methods=["GET"],    ...)
add("/config/bonds/{name}",                  self._update_bond,        methods=["PUT"],    ...)
add("/config/bonds/{name}",                  self._delete_bond,        methods=["DELETE"], ...)
add("/config/bonds/{name}/members",          self._add_bond_member,    methods=["POST"],   status_code=201, ...)
add("/config/bonds/{name}/members/{member}", self._delete_bond_member, methods=["DELETE"], ...)
add("/bonds/{name}/status",                  self._get_bond_status,    methods=["GET"],    ...)
```

## 5. Tests (append to test_networking_api_routes.py)

Group under `# ── bond CRUD ──` comment block. Each test uses `_make_plugin(tmp_path)` + `_make_client(plugin)`. No real `ifstatecli` calls needed (state mutations don't touch the kernel). For `_get_bond_status`, patch `pathlib.Path.read_text` or pass a tmp procfs fixture file.

| Test | Asserts |
|---|---|
| `test_create_bond_basic` | 201, bond+members in `_interfaces`, response has members list |
| `test_create_bond_with_params` | miimon/updelay/ad_lacp_rate stored in link dict |
| `test_create_bond_duplicate_name` | 409 |
| `test_create_bond_member_already_bonded` | 409 when member belongs to another bond |
| `test_list_bonds` | only bond-kind interfaces returned |
| `test_get_bond` | 200 with correct structure |
| `test_get_bond_not_found` | 404 |
| `test_get_non_bond_as_bond` | 404 (regular interface not returned as bond) |
| `test_update_bond_params` | PUT changes mode/miimon, members unchanged |
| `test_update_bond_members` | PUT members set replaces old set, dropped members removed from `_interfaces` |
| `test_update_bond_member_conflict` | 409 when new member already belongs to different bond |
| `test_delete_bond` | 200, bond + all members gone from `_interfaces` |
| `test_delete_bond_not_found` | 404 |
| `test_create_bond_alias_redirect` | existing alias pointing at member is redirected to bond name |
| `test_add_bond_member` | 201, member added to `_interfaces` with correct master |
| `test_add_bond_member_alias_redirect` | existing alias for member is redirected to bond |
| `test_add_bond_member_duplicate` | 409 (already member of same bond) |
| `test_add_bond_member_belongs_to_other_bond` | 409 |
| `test_delete_bond_member` | 200, member removed, bond response reflects new member list |
| `test_delete_bond_member_wrong_bond` | 422 |
| `test_delete_bond_member_not_in_config` | 404 |
| `test_get_bond_status_parsed` | parses sample procfs text, validates response shape |
| `test_get_bond_status_not_up` | returns 404 when `/proc/net/bonding/{name}` absent |
| `test_parse_proc_bond_lacp` | unit-tests `_parse_proc_bond` with a realistic LACP procfs fixture |

## 6. CLAUDE.md update

Add bond endpoints table and bond-specific events to `plugins/networking/CLAUDE.md`.

## Verification

```bash
uv run pytest plugins/networking/test_networking_api_routes.py -q
uv run pytest -q   # full suite
uv run --with pyright pyright plugins/networking/plugin.py
```
