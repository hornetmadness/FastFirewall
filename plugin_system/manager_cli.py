import argparse
import sys
from pathlib import Path


def run(loader, plugins_dir: str | Path, cfg) -> tuple[list[str] | None, bool, bool]:
    """
    Parse CLI arguments, handle any management commands, and return
    ``(only, ignore_plugins_states, show_macros)`` for normal server startup.

    ``only`` is the plugin allow-list (None means load all plugins).
    ``ignore_plugins_states`` is True when --ignore-plugins-states was passed.
    ``show_macros`` is True when --show-macros was passed; the caller should
    call ``print_macros(loader)`` and exit after loading plugins.
    """
    parser = _build_parser()
    args, _ = parser.parse_known_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    if args.showcfg:
        print_cfg(cfg)
        sys.exit(0)

    if args.makecfg:
        make_cfg(Path(args.makecfg).expanduser().resolve(), cfg)
        sys.exit(0)

    if args.enable_plugin:
        loader.set_plugin_enabled(plugins_dir, args.enable_plugin, True)
        print(f"Plugin '{args.enable_plugin}' enabled.")
        sys.exit(0)

    if args.disable_plugin:
        loader.set_plugin_enabled(plugins_dir, args.disable_plugin, False)
        print(f"Plugin '{args.disable_plugin}' disabled.")
        sys.exit(0)

    if args.list_plugins:
        print_plugin_table(loader.list_plugins(plugins_dir))
        sys.exit(0)

    return args.plugins or None, bool(args.ignore_plugins_states), bool(args.show_macros)


def get_macros(loader) -> dict:
    """
    Return macro namespace data as a structured dict, suitable for JSON or CLI display.

    Shape::

        {
            "service_port": {
                "kind": "built-in",
                "entries": {"$service_port.dns.udp": [53], ...}
            },
            "interface": {
                "kind": "plugin",
                "plugin": "networking",
                "entries": {"$interface.lan1": "enp0s25", ...}
            },
            ...
        }
    """
    from plugin_system.core.macros import macro_registry
    from plugin_system.core.macro_provider_plugin import MacroProviderPlugin

    result: dict = {}

    sp = macro_registry._service_ports
    sp_entries: dict[str, list[int]] = {}
    for svc, proto_map in sp.items():
        for proto, ports in proto_map.items():
            sp_entries[f"$service_port.{svc}.{proto}"] = ports
    result["service_port"] = {"kind": "built-in", "entries": sp_entries}

    for loaded in loader._plugins.values():
        if loaded.instance is not None and isinstance(loaded.instance, MacroProviderPlugin):
            for ns, entries_dict in loaded.instance.macro_snapshot().items():
                result[ns] = {
                    "kind": "plugin",
                    "plugin": loaded.plugin_id,
                    "entries": {f"${ns}.{k}": v for k, v in entries_dict.items()},
                }

    return result


def print_macros(loader) -> None:
    """Print all macro namespaces after plugins have been loaded."""
    data = get_macros(loader)

    print("Macro namespaces\n")
    for ns, info in data.items():
        if info["kind"] == "built-in":
            print(f"  ${ns}  (built-in — aggregated from enabled plugins' plugin.yaml)\n")
        else:
            print(f"\n  ${ns}  (plugin-defined — provided by '{info['plugin']}')\n")

        entries = info["entries"]
        if not entries:
            print("    (no entries registered)")
        else:
            rows = [
                (macro, ", ".join(str(p) for p in val) if isinstance(val, list) else str(val))
                for macro, val in entries.items()
            ]
            macro_w = max(len(r[0]) for r in rows)
            print(f"    {'MACRO':<{macro_w}}  VALUE")
            print("    " + "-" * (macro_w + 10))
            for macro, val in rows:
                print(f"    {macro:<{macro_w}}  {val}")
        print()


def print_cfg(cfg) -> None:
    """Print the active config file path and all resolved plugin paths."""

    def _status(p: Path) -> str:
        return "exists" if p.is_dir() or p.is_file() else "missing"

    print(f"Config file:  {cfg.config_path}  [{_status(cfg.config_path)}]")
    print()
    print(f"Server:       {cfg.server.host}:{cfg.server.port}")
    print(f"Auth:         {'enabled' if cfg.auth.enabled else 'disabled'}")
    backup = cfg.state.backup
    if backup.enabled:
        print(f"State backup: enabled → {backup.directory}")
    else:
        print(f"State backup: disabled")
    print()

    plugins_dir = cfg.plugins_src_dir()
    print(f"plugins.src_code_dir:  {plugins_dir}  [{_status(plugins_dir)}]")

    scan_dirs = cfg.plugins_scan_dirs()
    if scan_dirs:
        print(f"plugins.scan_dirs:")
        for d in scan_dirs:
            print(f"  {d}  [{_status(d)}]")
    else:
        print(f"plugins.scan_dirs:  (none configured)")

    data_dir = cfg.plugins_data_dir()
    if data_dir:
        print(f"plugins.data_dir:   {data_dir}  [{_status(data_dir)}]")
    else:
        print(f"plugins.data_dir:   (not set — state stored inside each plugin directory)")

    cfg_dir = cfg.plugins_cfg_dir()
    if cfg_dir:
        print(f"plugins.cfg_dir:    {cfg_dir}  [{_status(cfg_dir)}]")
    else:
        print(f"plugins.cfg_dir:    (not set — config stored inside each plugin directory)")


def make_cfg(dest: Path, cfg) -> None:
    """Scaffold a production config directory tree at *dest*."""
    import secrets as _secrets
    import yaml as _yaml

    created = []
    for d in [dest, dest / "plugins", dest / "backups"]:
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created.append(d)

    cfg_file = dest / "app_config.yaml"
    if not cfg_file.exists():
        starter = {
            "logging": {
                "level": cfg.logging.level,
                "format": cfg.logging.format,
            },
            "plugins": {
                "src_code_dir": "plugins",
                "scan_dirs": [str(dest / "plugins")],
                "data_dir": str(dest / "plugins"),
                "cfg_dir": str(dest / "plugins"),
            },
            "server": {
                "host": cfg.server.host,
                "port": cfg.server.port,
                "reload": False,
            },
            "state": {
                "backup": {
                    "enabled": True,
                    "directory": str(dest / "backups"),
                }
            },
            "auth": {
                "enabled": cfg.auth.enabled,
                "secret_key": (
                    cfg.auth.secret_key
                    if not cfg.auth.secret_key.startswith("CHANGE-ME")
                    else _secrets.token_hex(32)
                ),
                "algorithm": cfg.auth.algorithm,
                "token_expire_minutes": cfg.auth.token_expire_minutes,
                "users": cfg.auth.users,
            },
        }
        cfg_file.write_text(_yaml.dump(starter, default_flow_style=False, sort_keys=False))
        created.append(cfg_file)

    if created:
        print("Created:")
        for p in created:
            print(f"  {p}")
    else:
        print(f"Nothing to create — {dest} is already fully set up.")

    print()
    print("Point fastfirewall at this config:")
    print(f"  FASTFIREWALL_CONFIG={cfg_file} fastfirewall-api")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fastfirewall-api",
        description="FastFirewall — plugin-driven FastAPI firewall server.",
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Show this help message and exit.",
    )
    parser.add_argument(
        "--plugin",
        dest="plugins",
        metavar="PLUGIN_ID",
        action="append",
        help="Load only this plugin (may be repeated). Omit to load all enabled plugins.",
    )
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="Print all discovered plugins and their enabled state, then exit.",
    )
    parser.add_argument(
        "--enable-plugin",
        metavar="PLUGIN_ID",
        help="Enable a plugin in its plugin.yaml, then exit.",
    )
    parser.add_argument(
        "--disable-plugin",
        metavar="PLUGIN_ID",
        help="Disable a plugin in its plugin.yaml, then exit.",
    )
    parser.add_argument(
        "--show-macros",
        action="store_true",
        help="Print all available macro namespaces and their resolved values, then exit.",
    )
    parser.add_argument(
        "--ignore-plugins-states",
        dest="ignore_plugins_states",
        action="store_true",
        help="Skip re-applying saved state files on boot (all plugins).",
    )
    parser.add_argument(
        "--showcfg",
        action="store_true",
        help="Show the active config file and all resolved plugin paths, then exit.",
    )
    parser.add_argument(
        "--makecfg",
        metavar="PATH",
        help="Scaffold a config directory tree at PATH with a starter app_config.yaml, then exit.",
    )
    return parser


def _format_services(services: list) -> str:
    return ", ".join(services) if services else "-"


def _format_service_ports(service_ports) -> str:
    if service_ports in (-1, None):
        return "-"
    parts = []
    for svc, proto_map in service_ports.items():
        proto_parts = []
        for proto, ports in proto_map.items():
            real = [p for p in ports if p != -1]
            if real:
                proto_parts.append(f"{proto}:{','.join(str(p) for p in real)}")
        if proto_parts:
            parts.append(f"{svc} {' '.join(proto_parts)}")
    return "  ".join(parts) if parts else "-"


def print_plugin_table(rows: list[dict]) -> None:
    formatted_services = [_format_services(r.get("services", []))      for r in rows]
    formatted_ports    = [_format_service_ports(r.get("service_ports")) for r in rows]

    id_w    = max((len(r["id"])      for r in rows),              default=2)
    name_w  = max((len(r["name"])    for r in rows),              default=4)
    ver_w   = max((len(r["version"]) for r in rows),              default=7)
    req_w   = max((len(", ".join(r["plugin_requirements"])) for r in rows), default=8)
    svc_w   = max((len(s)            for s in formatted_services), default=8)
    ports_w = max((len(p)            for p in formatted_ports),    default=5)

    header = (
        f"{'ID':<{id_w}}  {'NAME':<{name_w}}  {'VERSION':<{ver_w}}  "
        f"STATE     {'REQUIRES':<{req_w}}  {'SERVICES':<{svc_w}}  {'PORTS':<{ports_w}}"
    )
    print(header)
    print("-" * len(header))
    for r, svc, ports in zip(rows, formatted_services, formatted_ports):
        state    = "enabled" if r["enabled"] else "disabled"
        requires = ", ".join(r["plugin_requirements"]) if r["plugin_requirements"] else "-"
        print(
            f"{r['id']:<{id_w}}  {r['name']:<{name_w}}  {r['version']:<{ver_w}}  "
            f"{state:<9} {requires:<{req_w}}  {svc:<{svc_w}}  {ports}"
        )
