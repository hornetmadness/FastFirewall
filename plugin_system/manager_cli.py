import argparse
import sys
from pathlib import Path


def run(loader, plugins_dir: str | Path) -> list[str] | None:
    """
    Parse CLI arguments, handle any management commands, and return the plugin
    allow-list for normal server startup (None means load all plugins).
    """
    parser = _build_parser()
    args, _ = parser.parse_known_args()

    if args.help:
        parser.print_help()
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
        _print_plugin_table(loader.list_plugins(plugins_dir))
        sys.exit(0)

    return args.plugins or None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="app.py",
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


def _print_plugin_table(rows: list[dict]) -> None:
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
