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


def _print_plugin_table(rows: list[dict]) -> None:
    id_w = max((len(r["id"]) for r in rows), default=2)
    name_w = max((len(r["name"]) for r in rows), default=4)
    ver_w = max((len(r["version"]) for r in rows), default=7)
    header = f"{'ID':<{id_w}}  {'NAME':<{name_w}}  {'VERSION':<{ver_w}}  STATE"
    print(header)
    print("-" * len(header))
    for r in rows:
        state = "enabled" if r["enabled"] else "disabled"
        print(f"{r['id']:<{id_w}}  {r['name']:<{name_w}}  {r['version']:<{ver_w}}  {state}")
