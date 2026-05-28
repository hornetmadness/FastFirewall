"""
nftables script compiler — pure functions, no FastAPI/pydantic imports.

Consumed by plugin.py; isolated here so the compiler can be tested and
extended independently of the plugin lifecycle.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
from typing import Any

from plugin_system.core.macros import macro_registry


# ── address / port helpers ─────────────────────────────────────────────────────

def _addr_family(addr: str) -> str:
    """Return 'ip' for IPv4 addresses/CIDRs, 'ip6' for IPv6."""
    try:
        return "ip" if ipaddress.ip_network(addr, strict=False).version == 4 else "ip6"
    except ValueError:
        return "ip"


def _resolve_address_macro(
    value: str,
    field: str,
    rule_name: str,
    logger: Any,
) -> tuple[str, str] | None:
    """Resolve an address macro to (nft_family, nft_address_expr), or None to skip."""
    resolved = macro_registry.resolve(value)
    if resolved is None:
        logger.warning(
            "Skipping rule %r: macro %r could not be resolved (plugin not loaded?)",
            rule_name, value,
        )
        return None
    addrs = [resolved] if isinstance(resolved, str) else [str(a) for a in resolved]
    if not addrs:
        return None
    
    ipv4 = [a for a in addrs if _addr_family(a) == "ip"]
    ipv6 = [a for a in addrs if _addr_family(a) == "ip6"]
    if ipv4 and ipv6:
        logger.warning(
            "Rule %r: macro %r has mixed IPv4/IPv6 addresses; using IPv4 only for %s",
            rule_name, value, field,
        )
        addrs = ipv4
    
    fam = _addr_family(addrs[0])
    expr = addrs[0] if len(addrs) == 1 else "{ " + ", ".join(addrs) + " }"
    return fam, expr



def _port_set(ports: list[int]) -> str:
    if len(ports) == 1:
        return str(ports[0])
    return "{ " + ", ".join(str(p) for p in sorted(ports)) + " }"


# ── filter rule expression compiler ───────────────────────────────────────────

def _rule_to_nft_expr(rule: Any, logger: Any, sets: dict[str, Any] | None = None) -> str | None:
    """Convert a FirewallRule to an nft match-action expression, or None to skip."""
    parts: list[str] = []

    # §2 interface matching
    if rule.src_interface:
        parts.append(f'iif "{rule.src_interface}"')
    if rule.dst_interface:
        parts.append(f'oif "{rule.dst_interface}"')

    # §3 address set references, then plain address matching
    src_set = getattr(rule, "src_address_set", None)
    if src_set:
        set_def = (sets or {}).get(src_set)
        family = "ip6" if set_def and getattr(set_def, "type", "") == "ipv6_addr" else "ip"
        parts.append(f"{family} saddr @{src_set}")
    elif rule.src_address and rule.src_address != "any":
        result = _resolve_address_macro(rule.src_address, "src_address", rule.name, logger)
        if result is None:
            return None
        fam, addr_expr = result
        parts.append(f"{fam} saddr {addr_expr}")

    dst_set = getattr(rule, "dst_address_set", None)
    if dst_set:
        set_def = (sets or {}).get(dst_set)
        family = "ip6" if set_def and getattr(set_def, "type", "") == "ipv6_addr" else "ip"
        parts.append(f"{family} daddr @{dst_set}")
    elif rule.dst_address and rule.dst_address != "any":
        result = _resolve_address_macro(rule.dst_address, "dst_address", rule.name, logger)
        if result is None:
            return None
        fam, addr_expr = result
        parts.append(f"{fam} daddr {addr_expr}")

    # §12 verdict maps — when set, the vmap is the verdict; skip normal port+verdict
    dst_vmap = getattr(rule, "dst_port_vmap", None)
    src_vmap = getattr(rule, "src_port_vmap", None)

    # protocol, port, and protocol-specific matches
    proto = rule.protocol
    if proto and proto != "any":
        if proto in ("tcp", "udp"):
            # src port — suppressed when src_vmap provides the verdict
            if not src_vmap:
                if rule.src_port is not None:
                    raw = macro_registry.resolve(rule.src_port)
                    ports = [raw] if isinstance(raw, int) else (raw or [])
                    if not ports:
                        logger.warning("Skipping rule %r: port %r resolved to no ports", rule.name, rule.src_port)
                        return None
                    parts.append(f"{proto} sport {_port_set(ports)}")
                elif rule.src_port_range is not None:  # §9d
                    lo, hi = rule.src_port_range
                    parts.append(f"{proto} sport {lo}-{hi}")
            # dst port — suppressed when dst_vmap provides the verdict
            if not dst_vmap:
                if rule.dst_port is not None:
                    raw = macro_registry.resolve(rule.dst_port)
                    ports = [raw] if isinstance(raw, int) else (raw or [])
                    if not ports:
                        logger.warning("Skipping rule %r: port %r resolved to no ports", rule.name, rule.dst_port)
                        return None
                    parts.append(f"{proto} dport {_port_set(ports)}")
                elif rule.dst_port_range is not None:  # §9d
                    lo, hi = rule.dst_port_range
                    parts.append(f"{proto} dport {lo}-{hi}")
            # §9a TCP flags
            if proto == "tcp" and rule.tcp_flags is not None:
                mask = rule.tcp_flags_mask
                flags = rule.tcp_flags
                if mask:
                    mask_str = "|".join(mask)
                    flags_val = ("(" + "|".join(flags) + ")") if flags else "0"
                    parts.append(f"tcp flags & ({mask_str}) == {flags_val}")
                elif flags:
                    parts.append("tcp flags { " + ", ".join(flags) + " }")
        elif proto in ("icmp", "icmpv6", "esp", "ah"):
            nft_name = "ipv6-icmp" if proto == "icmpv6" else proto
            parts.append(f"meta l4proto {nft_name}")
            # §9b ICMP type
            if rule.icmp_type is not None:
                icmp_kw = "icmpv6" if proto == "icmpv6" else "icmp"
                parts.append(f"{icmp_kw} type {rule.icmp_type}")

    # §9e meta expressions — mark, dscp, pkttype
    if getattr(rule, "mark", None) is not None:
        parts.append(f"meta mark {rule.mark}")
    if getattr(rule, "dscp", None) is not None:
        parts.append(f"ip dscp {rule.dscp}")
    pkttype = getattr(rule, "pkttype", None)
    if pkttype:
        parts.append(f"meta pkttype {pkttype}")

    # §9c explicit ct state match (e.g. "new", "invalid")
    if rule.ct_state:
        if len(rule.ct_state) == 1:
            parts.append(f"ct state {rule.ct_state[0]}")
        else:
            parts.append("ct state { " + ", ".join(rule.ct_state) + " }")

    # §5 rate limiting — after matches, before log and verdict
    if rule.rate_limit is not None:
        rl = rule.rate_limit
        rate_str = (
            f"{rl.rate} {rl.unit}/second" if rl.unit in ("kbytes", "mbytes")
            else f"{rl.rate}/{rl.unit}"
        )
        burst_str = f" burst {rl.burst} {rl.burst_unit}" if rl.burst is not None else ""
        over_str = " over" if rl.over else ""
        parts.append(f"limit rate{over_str} {rate_str}{burst_str}")

    # §6 logging — immediately before verdict
    if rule.log is not None:
        lg = rule.log
        log_parts = [f"log prefix {json.dumps(lg.prefix)} level {lg.level}"]
        if lg.group is not None:
            log_parts.append(f"group {lg.group}")
        if lg.flags:
            log_parts.append(f"flags {lg.flags}")
        if lg.snaplen is not None:
            log_parts.append(f"snaplen {lg.snaplen}")
        parts.append(" ".join(log_parts))

    # §8 counter + quota — after log, before verdict
    counter_name = getattr(rule, "counter_name", None)
    if counter_name:
        parts.append(f"counter name {counter_name}")
    quota_name = getattr(rule, "quota_name", None)
    if quota_name:
        parts.append(f"quota name {quota_name}")

    # §12 verdict map takes precedence over normal verdict
    if dst_vmap:
        proto_qualifier = f"{proto} " if proto and proto in ("tcp", "udp") else ""
        parts.append(f"{proto_qualifier}dport vmap @{dst_vmap}")
    elif src_vmap:
        proto_qualifier = f"{proto} " if proto and proto in ("tcp", "udp") else ""
        parts.append(f"{proto_qualifier}sport vmap @{src_vmap}")
    elif rule.action == "accept":
        parts.append("accept")
    elif rule.action == "reject":
        parts.append("reject")
    elif rule.action == "return":
        parts.append("return")
    elif rule.action == "jump":
        target = getattr(rule, "jump_target", None)
        if not target:
            logger.warning("Skipping rule %r: action is 'jump' but no jump_target specified", rule.name)
            return None
        parts.append(f"jump {target}")
    else:
        parts.append("drop")

    return " ".join(parts)


# ── NAT rule expression compiler (§4) ─────────────────────────────────────────

def _nat_rule_to_nft_expr(rule: Any, logger: Any) -> str | None:
    """Convert a NatRule to an nft match-action expression, or None to skip."""
    parts: list[str] = []

    if rule.in_interface:
        parts.append(f'iif "{rule.in_interface}"')
    if rule.out_interface:
        parts.append(f'oif "{rule.out_interface}"')

    if rule.src_address and rule.src_address != "any":
        result = _resolve_address_macro(rule.src_address, "src_address", rule.name, logger)
        if result is None:
            return None
        fam, addr_expr = result
        parts.append(f"{fam} saddr {addr_expr}")
    if rule.dst_address and rule.dst_address != "any":
        result = _resolve_address_macro(rule.dst_address, "dst_address", rule.name, logger)
        if result is None:
            return None
        fam, addr_expr = result
        parts.append(f"{fam} daddr {addr_expr}")

    proto = rule.protocol
    if proto:
        if rule.src_port is not None:
            parts.append(f"{proto} sport {rule.src_port}")
        if rule.dst_port is not None:
            raw = macro_registry.resolve(rule.dst_port)
            ports = [raw] if isinstance(raw, int) else (raw or [])
            if not ports:
                logger.warning("Skipping rule %r: port %r resolved to no ports", rule.name, rule.dst_port)
                return None
            parts.append(f"{proto} dport {_port_set(ports)}")

    flags_str = " " + ",".join(rule.flags) if rule.flags else ""

    if rule.type == "masquerade":
        parts.append(f"masquerade{flags_str}")
    elif rule.type == "snat":
        if not rule.to_address:
            logger.warning("Skipping SNAT rule %r: no to_address specified", rule.name)
            return None
        target = f"{rule.to_address}:{rule.to_port}" if rule.to_port else rule.to_address
        parts.append(f"snat to {target}{flags_str}")
    elif rule.type == "dnat":
        if not rule.to_address:
            logger.warning("Skipping DNAT rule %r: no to_address specified", rule.name)
            return None
        target = f"{rule.to_address}:{rule.to_port}" if rule.to_port else rule.to_address
        parts.append(f"dnat to {target}{flags_str}")
    elif rule.type == "redirect":
        if rule.to_port:
            parts.append(f"redirect to {rule.to_port}{flags_str}")
        else:
            parts.append(f"redirect{flags_str}")
    else:
        logger.warning("Skipping NAT rule %r: unknown type %r", rule.name, rule.type)
        return None

    return " ".join(parts)


# ── ingress rule expression compiler (§11) ────────────────────────────────────

def _ingress_rule_to_nft_expr(rule: Any, logger: Any, sets: dict[str, Any] | None = None) -> str | None:
    """Convert an IngressRule to an nft match-action expression for the netdev table."""
    parts: list[str] = []

    src_set = getattr(rule, "src_address_set", None)
    if src_set:
        set_def = (sets or {}).get(src_set)
        family = "ip6" if set_def and getattr(set_def, "type", "") == "ipv6_addr" else "ip"
        parts.append(f"{family} saddr @{src_set}")
    elif rule.src_address and rule.src_address != "any":
        result = _resolve_address_macro(rule.src_address, "src_address", rule.name, logger)
        if result is None:
            return None
        fam, addr_expr = result
        parts.append(f"{fam} saddr {addr_expr}")

    dst_set = getattr(rule, "dst_address_set", None)
    if dst_set:
        set_def = (sets or {}).get(dst_set)
        family = "ip6" if set_def and getattr(set_def, "type", "") == "ipv6_addr" else "ip"
        parts.append(f"{family} daddr @{dst_set}")
    elif rule.dst_address and rule.dst_address != "any":
        result = _resolve_address_macro(rule.dst_address, "dst_address", rule.name, logger)
        if result is None:
            return None
        fam, addr_expr = result
        parts.append(f"{fam} daddr {addr_expr}")

    proto = rule.protocol
    if proto and proto != "any":
        if proto in ("tcp", "udp"):
            if rule.src_port is not None:
                raw = macro_registry.resolve(rule.src_port)
                ports = [raw] if isinstance(raw, int) else (raw or [])
                if not ports:
                    logger.warning("Skipping rule %r: port %r resolved to no ports", rule.name, rule.src_port)
                    return None
                parts.append(f"{proto} sport {_port_set(ports)}")
            if rule.dst_port is not None:
                raw = macro_registry.resolve(rule.dst_port)
                ports = [raw] if isinstance(raw, int) else (raw or [])
                if not ports:
                    logger.warning("Skipping rule %r: port %r resolved to no ports", rule.name, rule.dst_port)
                    return None
                parts.append(f"{proto} dport {_port_set(ports)}")
        elif proto in ("icmp", "icmpv6", "esp", "ah"):
            nft_name = "ipv6-icmp" if proto == "icmpv6" else proto
            parts.append(f"meta l4proto {nft_name}")

    if rule.rate_limit is not None:
        rl = rule.rate_limit
        rate_str = (
            f"{rl.rate} {rl.unit}/second" if rl.unit in ("kbytes", "mbytes")
            else f"{rl.rate}/{rl.unit}"
        )
        burst_str = f" burst {rl.burst} {rl.burst_unit}" if rl.burst is not None else ""
        over_str = " over" if rl.over else ""
        parts.append(f"limit rate{over_str} {rate_str}{burst_str}")

    if rule.log is not None:
        lg = rule.log
        log_parts = [f"log prefix {json.dumps(lg.prefix)} level {lg.level}"]
        if lg.group is not None:
            log_parts.append(f"group {lg.group}")
        if lg.flags:
            log_parts.append(f"flags {lg.flags}")
        if lg.snaplen is not None:
            log_parts.append(f"snaplen {lg.snaplen}")
        parts.append(" ".join(log_parts))

    if rule.action == "accept":
        parts.append("accept")
    elif rule.action == "reject":
        parts.append("reject")
    else:
        parts.append("drop")

    return " ".join(parts) if parts else "drop"


# ── script compiler ────────────────────────────────────────────────────────────

def _compile_to_script(
    rules: list[Any],
    filter_name: str,
    chains: dict[str, Any],
    logger: Any,
    sets: dict[str, Any] | None = None,
    nat_rules: list[Any] | None = None,
    flowtables: list[Any] | None = None,
    custom_chains: dict[str, Any] | None = None,
    ingress_rules: list[Any] | None = None,
    ingress_table: str = "ff_ingress",
    verdict_maps: dict[str, Any] | None = None,
    quotas: dict[str, Any] | None = None,
) -> str:
    """Generate a complete nftables script from enabled rules and chain configs."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# FastFirewall managed ruleset — do not edit manually",
        f"# generated: {ts}  table: inet {filter_name}",
        f"add table inet {filter_name}",
        f"flush table inet {filter_name}",
    ]

    # §7 flowtables — declared before chains
    for ft in (flowtables or []):
        devices_str = ", ".join(ft.devices)
        lines.append(f"# flowtable: {ft.name}  priority: {ft.priority}")
        lines.append(
            f"add flowtable inet {filter_name} {ft.name} "
            f"{{ hook ingress priority {ft.priority}; devices = {{ {devices_str} }}; }}"
        )

    # §12 verdict maps — declared after flowtables, before chains
    for vmap_name, vmap in (verdict_maps or {}).items():
        map_opts: list[str] = [f"type {vmap.key_type} : verdict"]
        if vmap.flags:
            map_opts.append(f"flags {','.join(vmap.flags)}")
        map_body = "; ".join(map_opts)
        lines.append(f"# vmap: {vmap_name}  type: {vmap.key_type} : verdict")
        lines.append(f"add map inet {filter_name} {vmap_name} {{ {map_body}; }}")
        if vmap.entries:
            entry_parts: list[str] = []
            for e in vmap.entries:
                if e.verdict == "jump":
                    entry_parts.append(f"{e.key} : jump {e.jump_target}")
                else:
                    entry_parts.append(f"{e.key} : {e.verdict}")
            lines.append(f"add element inet {filter_name} {vmap_name} {{ {', '.join(entry_parts)} }}")

    # §3 named sets — declared before chains so rules can reference them
    for set_name, fw_set in (sets or {}).items():
        set_opts: list[str] = [f"type {fw_set.type}"]
        if fw_set.flags:
            set_opts.append(f"flags {','.join(fw_set.flags)}")
        if fw_set.auto_merge:
            set_opts.append("auto-merge")
        if fw_set.timeout is not None:
            set_opts.append(f"timeout {fw_set.timeout}s")
        set_body = "; ".join(set_opts)
        lines.append(f"# set: {set_name}  type: {fw_set.type}")
        lines.append(f"add set inet {filter_name} {set_name} {{ {set_body}; }}")
        if fw_set.elements:
            lines.append(f"add element inet {filter_name} {set_name} {{ {', '.join(fw_set.elements)} }}")

    # §8 named counters — declared before chains; one per unique counter_name across all rules
    seen_counters: set[str] = set()
    for rule in rules:
        cn = getattr(rule, "counter_name", None)
        if cn and cn not in seen_counters:
            lines.append(f"add counter inet {filter_name} {cn}")
            seen_counters.add(cn)

    # §8 named quotas — declared before chains
    for quota in (quotas or {}).values():
        over_str = "over " if quota.over else ""
        lines.append(f"# quota: {quota.name}  {over_str}{quota.amount} {quota.unit}")
        lines.append(f"add quota {over_str}inet {filter_name} {quota.name} {{ {quota.amount} {quota.unit} }}")

    # filter chains
    for chain_name, cfg in chains.items():
        lines.append(f"# chain: {chain_name}  policy: {cfg.policy}  priority: {cfg.priority}")
        lines.append(
            f"add chain inet {filter_name} {chain_name} "
            f"{{ type filter hook {chain_name} priority {cfg.priority}; policy {cfg.policy}; }}"
        )

    # §10 custom chains (no hook — jump targets only)
    for cc_name, cc in (custom_chains or {}).items():
        lines.append(f"# custom chain: {cc_name}")
        lines.append(f"add chain inet {filter_name} {cc_name}")

    # §4 nat chains — only emitted when there are enabled NAT rules
    enabled_nat = [r for r in (nat_rules or []) if r.enabled]
    if enabled_nat:
        if any(r.chain == "prerouting" for r in enabled_nat):
            lines.append("# chain: prerouting  type: nat  priority: -100")
            lines.append(
                f"add chain inet {filter_name} prerouting "
                f"{{ type nat hook prerouting priority -100; policy accept; }}"
            )
        if any(r.chain == "postrouting" for r in enabled_nat):
            lines.append("# chain: postrouting  type: nat  priority: 100")
            lines.append(
                f"add chain inet {filter_name} postrouting "
                f"{{ type nat hook postrouting priority 100; policy accept; }}"
            )

    # §7 flowtable offload rules — injected at the head of the forward chain
    for ft in (flowtables or []):
        if ft.offload_forward:
            lines.append(f"add rule inet {filter_name} forward flow add @{ft.name}")

    # filter chain preamble rules
    for chain_name, cfg in chains.items():
        for expr in cfg.preamble:
            lines.append(f"add rule inet {filter_name} {chain_name} {expr}")

    # filter rules
    all_chains = set(chains.keys()) | set((custom_chains or {}).keys())
    seen_exprs: set[str] = set()
    for rule in sorted(rules, key=lambda r: r.priority):
        if rule.chain not in all_chains:
            logger.warning("Skipping rule %r: chain %r not defined", rule.name, rule.chain)
            continue
        expr = _rule_to_nft_expr(rule, logger, sets=sets)
        if expr is None:
            continue
        dedup_key = f"{rule.chain}:{expr}"
        if dedup_key in seen_exprs:
            logger.warning("Skipping duplicate rule %r: identical nft expression already emitted", rule.name)
            continue
        seen_exprs.add(dedup_key)
        lines.append(f"# rule_id: {rule.id}  name: {rule.name}  priority: {rule.priority}")
        label = json.dumps(f"{rule.comment or rule.name} [id:{rule.id}]")
        lines.append(f"add rule inet {filter_name} {rule.chain} {expr} comment {label}")

    # §4 NAT rules
    for rule in sorted(enabled_nat, key=lambda r: r.priority):
        expr = _nat_rule_to_nft_expr(rule, logger)
        if expr is None:
            continue
        lines.append(f"# nat_rule_id: {rule.id}  name: {rule.name}  priority: {rule.priority}")
        label = json.dumps(f"{rule.comment or rule.name} [id:{rule.id}]")
        lines.append(f"add rule inet {filter_name} {rule.chain} {expr} comment {label}")

    # §11 ingress (netdev family) — separate table, early-drop per device
    enabled_ingress = [r for r in (ingress_rules or []) if r.enabled]
    if enabled_ingress:
        lines.append(f"add table netdev {ingress_table}")
        lines.append(f"flush table netdev {ingress_table}")
        devices: dict[str, list[Any]] = {}
        for rule in enabled_ingress:
            devices.setdefault(rule.device, []).append(rule)
        for device, dev_rules in devices.items():
            chain_name = device.replace("-", "_") + "_in"
            lines.append(f"# ingress chain: {chain_name}  device: {device}")
            lines.append(
                f"add chain netdev {ingress_table} {chain_name} "
                f"{{ type filter hook ingress device {device} priority filter; policy accept; }}"
            )
            for rule in sorted(dev_rules, key=lambda r: r.priority):
                expr = _ingress_rule_to_nft_expr(rule, logger, sets=sets)
                if expr is None:
                    continue
                lines.append(f"# ingress_rule_id: {rule.id}  name: {rule.name}  priority: {rule.priority}")
                label = json.dumps(f"{rule.comment or rule.name} [id:{rule.id}]")
                lines.append(f"add rule netdev {ingress_table} {chain_name} {expr} comment {label}")

    return "\n".join(lines)
