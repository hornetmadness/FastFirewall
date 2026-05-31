import sys
import textwrap
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from plugin_system.core import EventBus, PluginLoader, Service
from plugin_system.core.loader import PluginError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_plugin(root: Path, name: str, yaml_content: str, py_content: str) -> Path:
    plugin_dir = root / name
    plugin_dir.mkdir()
    content = textwrap.dedent(yaml_content)
    if "service_ports" not in content:
        content += "service_ports: -1\n"
    (plugin_dir / "plugin.yaml").write_text(content)
    (plugin_dir / "plugin.py").write_text(textwrap.dedent(py_content))
    return plugin_dir


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def loader(bus):
    return PluginLoader(bus=bus)


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------

def test_load_minimal_plugin(tmp_path, loader):
    make_plugin(tmp_path, "minimal", "name: Minimal\nid: minimal\n", "# empty\n")
    pid = loader.load_plugin(tmp_path / "minimal")
    assert pid == "minimal"
    assert "minimal" in loader.plugins


def test_plugin_id_defaults_to_directory_name(tmp_path, loader):
    plugin_dir = tmp_path / "dir_name_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.yaml").write_text("name: Dir Name\nservice_ports: -1\n")  # no id field
    (plugin_dir / "plugin.py").write_text("# empty\n")
    pid = loader.load_plugin(plugin_dir)
    assert pid == "dir_name_plugin"


def test_load_plugin_with_pluginbase_instance(tmp_path, loader):
    make_plugin(tmp_path, "base_plugin", "name: Base\nid: base_plugin\n", """
        from plugin_system.core import PluginBase

        class MyPlugin(PluginBase):
            def setup(self):
                self.was_setup = True
    """)
    loader.load_plugin(tmp_path / "base_plugin")
    instance = loader.plugins["base_plugin"].instance
    assert instance is not None
    assert instance.was_setup is True


def test_plugin_instance_receives_meta_and_config(tmp_path, loader):
    make_plugin(tmp_path, "meta_plugin", """
        name: Meta Plugin
        id: meta_plugin
        version: "2.3.4"
        config:
          key: value
    """, """
        from plugin_system.core import PluginBase

        class MetaPlugin(PluginBase):
            pass
    """)
    loader.load_plugin(tmp_path / "meta_plugin")
    inst = loader.plugins["meta_plugin"].instance
    assert inst.meta["name"] == "Meta Plugin"
    assert inst.meta["version"] == "2.3.4"
    assert inst.config == {"key": "value"}


def test_loaded_plugin_stores_plugin_dir(tmp_path, loader):
    make_plugin(tmp_path, "dir_plugin", "name: Dir\nid: dir_plugin\n", "# empty\n")
    loader.load_plugin(tmp_path / "dir_plugin")
    assert loader.plugins["dir_plugin"].plugin_dir == (tmp_path / "dir_plugin").resolve()


def test_plugin_instance_has_plugin_dir_before_setup(tmp_path, loader):
    make_plugin(tmp_path, "dir_inst", "name: DI\nid: dir_inst\n", """
        from plugin_system.core import PluginBase

        class DirInst(PluginBase):
            def setup(self):
                self.dir_at_setup = self.plugin_dir
    """)
    loader.load_plugin(tmp_path / "dir_inst")
    inst = loader.plugins["dir_inst"].instance
    assert inst.dir_at_setup == (tmp_path / "dir_inst").resolve()


def test_plugin_dir_is_none_for_disabled_plugin(tmp_path, loader):
    make_plugin(tmp_path, "disabled_dir", "name: DD\nid: disabled_dir\nenabled: false\n", "# empty\n")
    loader.load_plugin(tmp_path / "disabled_dir")
    assert "disabled_dir" not in loader.plugins


def test_disabled_plugin_is_skipped(tmp_path, loader):
    make_plugin(tmp_path, "disabled", "name: Disabled\nid: disabled\nenabled: false\n", "# empty\n")
    pid = loader.load_plugin(tmp_path / "disabled")
    assert pid == "disabled"
    assert "disabled" not in loader.plugins


def test_plugins_property_returns_snapshot(tmp_path, loader):
    make_plugin(tmp_path, "snap", "name: Snap\nid: snap\n", "# empty\n")
    loader.load_plugin(tmp_path / "snap")
    snapshot = loader.plugins
    # mutating the snapshot does not affect internal state
    snapshot.pop("snap")
    assert "snap" in loader.plugins


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

def test_missing_yaml_raises(tmp_path, loader):
    d = tmp_path / "no_yaml"
    d.mkdir()
    (d / "plugin.py").write_text("# no yaml\n")
    with pytest.raises(PluginError, match="Missing plugin.yaml"):
        loader.load_plugin(d)


def test_missing_module_raises(tmp_path, loader):
    d = tmp_path / "no_module"
    d.mkdir()
    (d / "plugin.yaml").write_text("name: X\nid: x\n")
    with pytest.raises(PluginError, match="Missing plugin.py"):
        loader.load_plugin(d)


def test_duplicate_load_raises(tmp_path, loader):
    make_plugin(tmp_path, "dup", "name: Dup\nid: dup\n", "# empty\n")
    loader.load_plugin(tmp_path / "dup")
    with pytest.raises(PluginError, match="already loaded"):
        loader.load_plugin(tmp_path / "dup")


def test_syntax_error_in_plugin_module_raises(tmp_path, loader):
    make_plugin(tmp_path, "syntax_err", "name: Bad\nid: syntax_err\n", "this is not valid python !!!\n")
    with pytest.raises(Exception):
        loader.load_plugin(tmp_path / "syntax_err")


def test_missing_service_ports_raises(tmp_path, loader):
    d = tmp_path / "no_ports"
    d.mkdir()
    (d / "plugin.yaml").write_text("name: NoPorts\nid: no_ports\n")
    (d / "plugin.py").write_text("# empty\n")
    with pytest.raises(PluginError, match="service_ports"):
        loader.load_plugin(d)


def test_invalid_service_ports_bad_type_raises(tmp_path, loader):
    d = tmp_path / "bad_ports"
    d.mkdir()
    (d / "plugin.yaml").write_text("name: Bad\nid: bad_ports\nservice_ports: somestring\n")
    (d / "plugin.py").write_text("# empty\n")
    with pytest.raises(PluginError, match="service_ports"):
        loader.load_plugin(d)


def test_invalid_service_ports_unknown_protocol_raises(tmp_path, loader):
    d = tmp_path / "bad_proto"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: BP\nid: bad_proto\nservice_ports:\n  svc:\n    icmp: [1]\n"
    )
    (d / "plugin.py").write_text("# empty\n")
    with pytest.raises(PluginError, match="icmp"):
        loader.load_plugin(d)


def test_service_ports_minus_one_is_valid(tmp_path, loader):
    d = tmp_path / "no_svc_ports"
    d.mkdir()
    (d / "plugin.yaml").write_text("name: NS\nid: no_svc_ports\nservice_ports: -1\n")
    (d / "plugin.py").write_text("# empty\n")
    loader.load_plugin(d)
    assert loader.plugins["no_svc_ports"].service_ports == -1


def test_service_ports_dict_stored_on_loaded_plugin(tmp_path, loader):
    d = tmp_path / "has_ports"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: HP\nid: has_ports\nservice_ports:\n  dns:\n    tcp: [8080, 443]\n    udp: [53]\n"
    )
    (d / "plugin.py").write_text(textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class HasPorts(PluginBase):
            services = [Service.DNS]
    """))
    with patch.object(loader, "_get_os_listening_ports", return_value=set()):
        loader.load_plugin(d)
    sp = loader.plugins["has_ports"].service_ports
    assert sp == {"dns": {"tcp": [8080, 443], "udp": [53]}}


def test_service_ports_minus_one_with_declared_service_raises(tmp_path, loader):
    d = tmp_path / "mismatch_a"
    d.mkdir()
    (d / "plugin.yaml").write_text("name: MA\nid: mismatch_a\nservice_ports: -1\n")
    (d / "plugin.py").write_text(textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class MismatchA(PluginBase):
            services = [Service.DNS]
    """))
    with pytest.raises(PluginError, match="service_ports is -1"):
        loader.load_plugin(d)


def test_service_ports_key_mismatch_raises(tmp_path, loader):
    d = tmp_path / "mismatch_b"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: MB\nid: mismatch_b\nservice_ports:\n  dhcp:\n    udp: [67]\n"
    )
    (d / "plugin.py").write_text(textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class MismatchB(PluginBase):
            services = [Service.DNS]
    """))
    with pytest.raises(PluginError, match="service_ports keys do not match"):
        loader.load_plugin(d)


def test_service_ports_dict_with_no_services_raises(tmp_path, loader):
    d = tmp_path / "mismatch_c"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: MC\nid: mismatch_c\nservice_ports:\n  dns:\n    udp: [53]\n"
    )
    (d / "plugin.py").write_text("# empty\n")
    with pytest.raises(PluginError, match="service_ports keys do not match"):
        loader.load_plugin(d)


# ---------------------------------------------------------------------------
# Port conflict checks
# ---------------------------------------------------------------------------

def test_plugin_port_conflict_raises(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    # DNS and MDNS are different services but both can listen on UDP 5353 — use
    # that to trigger a port collision without a service-exclusivity collision.
    make_plugin(tmp_path, "dns_p", (
        "name: DNS\nid: dns_p\n"
        "service_ports:\n  dns:\n    udp: [5353]\n"
    ), textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class DNSP(PluginBase):
            services = [Service.DNS]
    """))
    make_plugin(tmp_path, "mdns_p", (
        "name: MDNS\nid: mdns_p\n"
        "service_ports:\n  mdns:\n    udp: [5353]\n"
    ), textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class MDNSP(PluginBase):
            services = [Service.MDNS]
    """))
    loader.load_plugin(tmp_path / "dns_p")
    with pytest.raises(PluginError, match="already claimed by plugin"):
        loader.load_plugin(tmp_path / "mdns_p")


def test_port_released_after_unload(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "dns_p", (
        "name: DNS\nid: dns_p\n"
        "service_ports:\n  dns:\n    udp: [5353]\n"
    ), textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class DNSP(PluginBase):
            services = [Service.DNS]
    """))
    make_plugin(tmp_path, "mdns_p", (
        "name: MDNS\nid: mdns_p\n"
        "service_ports:\n  mdns:\n    udp: [5353]\n"
    ), textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class MDNSP(PluginBase):
            services = [Service.MDNS]
    """))
    loader.load_plugin(tmp_path / "dns_p")
    loader.unload_plugin("dns_p")
    loader.load_plugin(tmp_path / "mdns_p")
    assert "mdns_p" in loader.plugins


def test_os_port_conflict_raises(tmp_path, loader):
    from unittest.mock import patch
    d = tmp_path / "smtp_p"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: SMTP\nid: smtp_p\nservice_ports:\n  smtp:\n    tcp: [25]\n"
    )
    (d / "plugin.py").write_text(textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class SMTPPlugin(PluginBase):
            services = [Service.SMTP]
    """))
    with patch.object(loader, "_get_os_listening_ports", return_value={25}):
        with pytest.raises(PluginError, match="already in use by the OS"):
            loader.load_plugin(d)


def test_skip_host_os_port_check_bypasses_os_check(tmp_path, loader):
    from unittest.mock import patch
    d = tmp_path / "managed_smtp"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: MS\nid: managed_smtp\n"
        "skip_host_os_port_check: true\n"
        "service_ports:\n  smtp:\n    tcp: [25]\n"
    )
    (d / "plugin.py").write_text(textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class ManagedSMTP(PluginBase):
            services = [Service.SMTP]
    """))
    with patch.object(loader, "_get_os_listening_ports", return_value={25}) as mock_check:
        loader.load_plugin(d)
    mock_check.assert_not_called()
    assert "managed_smtp" in loader.plugins


def test_os_port_conflict_skips_sentinel(tmp_path, loader):
    from unittest.mock import patch
    d = tmp_path / "no_real_port"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: NRP\nid: no_real_port\nservice_ports:\n  firewall:\n    tcp: [-1]\n"
    )
    (d / "plugin.py").write_text(textwrap.dedent("""
        from plugin_system.core import PluginBase, Service

        class NRPPlugin(PluginBase):
            services = [Service.FIREWALL]
    """))
    with patch.object(loader, "_get_os_listening_ports", return_value={-1}):
        loader.load_plugin(d)
    assert "no_real_port" in loader.plugins


def test_invalid_service_raises_plugin_error(tmp_path, loader):
    make_plugin(tmp_path, "bad_svc", "name: BadSvc\nid: bad_svc\n", """
        from plugin_system.core import PluginBase

        class BadSvcPlugin(PluginBase):
            services = ["not_a_service_enum"]
    """)
    with pytest.raises(PluginError, match="unknown service"):
        loader.load_plugin(tmp_path / "bad_svc")


# ---------------------------------------------------------------------------
# Service registry
# ---------------------------------------------------------------------------

def test_service_registered_after_load(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "dns_plugin", "name: DNS\nid: dns_plugin\nservice_ports:\n  dns:\n    udp: [53]\n", """
        from plugin_system.core import PluginBase, Service

        class DNSPlugin(PluginBase):
            services = [Service.DNS]
    """)
    with patch.object(loader, "_get_os_listening_ports", return_value=set()):
        loader.load_plugin(tmp_path / "dns_plugin")
    assert loader.service_registry[Service.DNS] == "dns_plugin"


def test_service_conflict_raises(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "plugin_a", "name: A\nid: plugin_a\nservice_ports:\n  dns:\n    udp: [53]\n", """
        from plugin_system.core import PluginBase, Service

        class PluginA(PluginBase):
            services = [Service.DNS]
    """)
    make_plugin(tmp_path, "plugin_b", "name: B\nid: plugin_b\nservice_ports:\n  dns:\n    udp: [53]\n", """
        from plugin_system.core import PluginBase, Service

        class PluginB(PluginBase):
            services = [Service.DNS]
    """)
    with patch.object(loader, "_get_os_listening_ports", return_value=set()):
        loader.load_plugin(tmp_path / "plugin_a")
        with pytest.raises(PluginError, match="already owned"):
            loader.load_plugin(tmp_path / "plugin_b")


def test_service_registry_snapshot(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "reg_plugin", "name: Reg\nid: reg_plugin\nservice_ports:\n  ntp:\n    udp: [123]\n", """
        from plugin_system.core import PluginBase, Service

        class RegPlugin(PluginBase):
            services = [Service.NTP]
    """)
    loader.load_plugin(tmp_path / "reg_plugin")
    snapshot = loader.service_registry
    assert snapshot[Service.NTP] == "reg_plugin"
    # mutating snapshot does not affect internal state
    snapshot.pop(Service.NTP)
    assert Service.NTP in loader.service_registry


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def test_unmet_dependency_raises(tmp_path, loader):
    make_plugin(tmp_path, "dep_plugin", """
        name: Dep Plugin
        id: dep_plugin
        plugin_requirements: [missing_dep]
    """, "# empty\n")
    with pytest.raises(PluginError, match="requires"):
        loader.load_plugin(tmp_path / "dep_plugin")


def test_met_dependency_loads(tmp_path, loader):
    make_plugin(tmp_path, "base_dep", "name: Base\nid: base_dep\n", "# empty\n")
    make_plugin(tmp_path, "consumer", """
        name: Consumer
        id: consumer
        plugin_requirements: [base_dep]
    """, "# empty\n")
    loader.load_plugin(tmp_path / "base_dep")
    loader.load_plugin(tmp_path / "consumer")
    assert "consumer" in loader.plugins


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

def test_decorated_handler_registered_on_bus(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "handler_plugin", "name: H\nid: handler_plugin\n", """
        from plugin_system.core.decorators import on

        @on("test.event")
        def handle(event):
            pass
    """)
    loader.load_plugin(tmp_path / "handler_plugin")
    assert len(bus._subscribers["test.event"]) == 1


def test_wildcard_handler_registered_on_bus(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "wildcard_plugin", "name: W\nid: wildcard_plugin\n", """
        from plugin_system.core.decorators import on_any

        @on_any
        def handle_all(event):
            pass
    """)
    loader.load_plugin(tmp_path / "wildcard_plugin")
    assert len(bus._wildcard) == 1


def test_instance_method_handlers_registered(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "method_plugin", "name: M\nid: method_plugin\n", """
        from plugin_system.core import PluginBase
        from plugin_system.core.decorators import on

        class MethodPlugin(PluginBase):
            @on("method.event")
            def handle(self, event):
                pass
    """)
    loader.load_plugin(tmp_path / "method_plugin")
    assert len(bus._subscribers["method.event"]) == 1


def test_handler_fires_when_event_emitted(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "fire_plugin", "name: F\nid: fire_plugin\n", """
        from plugin_system.core.decorators import on

        received = []

        @on("fire.event")
        def handle(event):
            received.append(event.payload.get("value"))
    """)
    loader.load_plugin(tmp_path / "fire_plugin")
    from plugin_system.core.events import Event
    bus.emit(Event("fire.event", payload={"value": 42}))
    mod = sys.modules["_plugin_fire_plugin.plugin"]
    assert mod.received == [42]


# ---------------------------------------------------------------------------
# Unload / reload
# ---------------------------------------------------------------------------

def test_unload_removes_plugin(tmp_path, loader):
    make_plugin(tmp_path, "gone", "name: Gone\nid: gone\n", "# empty\n")
    loader.load_plugin(tmp_path / "gone")
    loader.unload_plugin("gone")
    assert "gone" not in loader.plugins


def test_unload_unknown_plugin_raises(loader):
    with pytest.raises(PluginError, match="not loaded"):
        loader.unload_plugin("ghost")


def test_unload_releases_service_for_reuse(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "svc_a", "name: SvcA\nid: svc_a\nservice_ports:\n  dns:\n    udp: [53]\n", """
        from plugin_system.core import PluginBase, Service

        class SvcA(PluginBase):
            services = [Service.DNS]
    """)
    make_plugin(tmp_path, "svc_b", "name: SvcB\nid: svc_b\nservice_ports:\n  dns:\n    udp: [53]\n", """
        from plugin_system.core import PluginBase, Service

        class SvcB(PluginBase):
            services = [Service.DNS]
    """)
    with patch.object(loader, "_get_os_listening_ports", return_value=set()):
        loader.load_plugin(tmp_path / "svc_a")
        loader.unload_plugin("svc_a")
        loader.load_plugin(tmp_path / "svc_b")
    assert "svc_b" in loader.plugins


def test_unload_removes_handlers_from_bus(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "rm_handler", "name: RH\nid: rm_handler\n", """
        from plugin_system.core.decorators import on

        @on("rm.event")
        def handle(event):
            pass
    """)
    loader.load_plugin(tmp_path / "rm_handler")
    loader.unload_plugin("rm_handler")
    assert len(bus._subscribers["rm.event"]) == 0


def test_teardown_called_on_unload(tmp_path, loader):
    make_plugin(tmp_path, "td_plugin", "name: TD\nid: td_plugin\n", """
        from plugin_system.core import PluginBase

        class TDPlugin(PluginBase):
            def teardown(self):
                self.was_torn_down = True
    """)
    loader.load_plugin(tmp_path / "td_plugin")
    instance = loader.plugins["td_plugin"].instance
    loader.unload_plugin("td_plugin")
    assert instance.was_torn_down is True


def test_teardown_error_does_not_abort_unload(tmp_path, loader):
    make_plugin(tmp_path, "bad_teardown", "name: BT\nid: bad_teardown\n", """
        from plugin_system.core import PluginBase

        class BadTeardown(PluginBase):
            def teardown(self):
                raise RuntimeError("teardown exploded")
    """)
    loader.load_plugin(tmp_path / "bad_teardown")
    loader.unload_plugin("bad_teardown")
    assert "bad_teardown" not in loader.plugins


def test_reload_plugin(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "reloadable", "name: R\nid: reloadable\n", "# empty\n")
    loader.load_plugin(tmp_path / "reloadable")
    loader.reload_plugin("reloadable", tmp_path / "reloadable")
    assert "reloadable" in loader.plugins


# ---------------------------------------------------------------------------
# Events emitted by the loader itself
# ---------------------------------------------------------------------------

def test_plugin_loaded_event_emitted(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    events = []
    bus.subscribe("plugin.loaded", lambda e: events.append(e))
    make_plugin(tmp_path, "ev_load", "name: EV\nid: ev_load\n", "# empty\n")
    loader.load_plugin(tmp_path / "ev_load")
    assert len(events) == 1
    assert events[0].payload["plugin_id"] == "ev_load"


def test_plugin_unloaded_event_emitted(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "ev_unload", "name: EU\nid: ev_unload\n", "# empty\n")
    loader.load_plugin(tmp_path / "ev_unload")
    events = []
    bus.subscribe("plugin.unloaded", lambda e: events.append(e))
    loader.unload_plugin("ev_unload")
    assert len(events) == 1
    assert events[0].payload["plugin_id"] == "ev_unload"


# ---------------------------------------------------------------------------
# load_directory
# ---------------------------------------------------------------------------

def test_load_directory_loads_all_valid_plugins(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "dir_a", "name: A\nid: dir_a\n", "# empty\n")
    make_plugin(tmp_path, "dir_b", "name: B\nid: dir_b\n", "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert "dir_a" in loaded
    assert "dir_b" in loaded


def test_load_directory_skips_bad_plugins(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "good_dir", "name: Good\nid: good_dir\n", "# empty\n")
    bad_dir = tmp_path / "bad_dir"
    bad_dir.mkdir()
    (bad_dir / "plugin.yaml").write_text("name: Bad\nid: bad_dir\n")
    (bad_dir / "plugin.py").write_text("this is not valid python !!!\n")
    loaded = loader.load_directory(tmp_path)
    assert "good_dir" in loaded
    assert "bad_dir" not in loaded


def test_load_directory_skips_non_plugin_dirs(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    # A directory without plugin.yaml should be silently ignored
    orphan = tmp_path / "no_yaml_dir"
    orphan.mkdir()
    (orphan / "something.py").write_text("# not a plugin\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded == []


def test_load_directory_not_a_dir_raises(loader):
    with pytest.raises(PluginError, match="Not a directory"):
        loader.load_directory("/nonexistent/path/xyz")


# ---------------------------------------------------------------------------
# Topological load ordering (plugin_requirements)
# ---------------------------------------------------------------------------

def test_dependency_loads_before_dependent(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "base",     "name: Base\nid: base\n",                                         "# empty\n")
    make_plugin(tmp_path, "consumer", "name: Consumer\nid: consumer\nplugin_requirements: [base]\n",    "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded.index("base") < loaded.index("consumer")


def test_alphabetical_tiebreaker_within_same_level(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "charlie", "name: C\nid: charlie\n", "# empty\n")
    make_plugin(tmp_path, "alice",   "name: A\nid: alice\n",   "# empty\n")
    make_plugin(tmp_path, "bob",     "name: B\nid: bob\n",     "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded == ["alice", "bob", "charlie"]


def test_chain_of_dependencies_ordered_correctly(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "c", "name: C\nid: c\nplugin_requirements: [b]\n", "# empty\n")
    make_plugin(tmp_path, "b", "name: B\nid: b\nplugin_requirements: [a]\n", "# empty\n")
    make_plugin(tmp_path, "a", "name: A\nid: a\n",                           "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded == ["a", "b", "c"]


def test_circular_dependency_raises(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "alpha", "name: A\nid: alpha\nplugin_requirements: [beta]\n",  "# empty\n")
    make_plugin(tmp_path, "beta",  "name: B\nid: beta\nplugin_requirements: [alpha]\n",  "# empty\n")
    with pytest.raises(PluginError, match="Circular dependency"):
        loader.load_directory(tmp_path)


def test_three_way_cycle_raises(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "x", "name: X\nid: x\nplugin_requirements: [z]\n", "# empty\n")
    make_plugin(tmp_path, "y", "name: Y\nid: y\nplugin_requirements: [x]\n", "# empty\n")
    make_plugin(tmp_path, "z", "name: Z\nid: z\nplugin_requirements: [y]\n", "# empty\n")
    with pytest.raises(PluginError, match="Circular dependency"):
        loader.load_directory(tmp_path)


def test_missing_required_plugin_raises(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "needy", "name: N\nid: needy\nplugin_requirements: [ghost]\n", "# empty\n")
    with pytest.raises(PluginError, match="ghost"):
        loader.load_directory(tmp_path)


def test_disabled_dependency_skips_dependent(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "dep",      "name: Dep\nid: dep\nenabled: false\n",                              "# empty\n")
    make_plugin(tmp_path, "consumer", "name: C\nid: consumer\nplugin_requirements: [dep]\n",               "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert "consumer" not in loaded
    assert "dep" not in loaded


def test_disabled_cascades_transitively(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "root",    "name: R\nid: root\nenabled: false\n",                               "# empty\n")
    make_plugin(tmp_path, "middle",  "name: M\nid: middle\nplugin_requirements: [root]\n",                 "# empty\n")
    make_plugin(tmp_path, "leaf",    "name: L\nid: leaf\nplugin_requirements: [middle]\n",                 "# empty\n")
    make_plugin(tmp_path, "unrelated", "name: U\nid: unrelated\n",                                         "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert "root" not in loaded
    assert "middle" not in loaded
    assert "leaf" not in loaded
    assert "unrelated" in loaded


def test_only_expands_to_include_transitive_deps(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "infra",    "name: I\nid: infra\n",                                              "# empty\n")
    make_plugin(tmp_path, "service",  "name: S\nid: service\nplugin_requirements: [infra]\n",              "# empty\n")
    make_plugin(tmp_path, "unrelated","name: U\nid: unrelated\n",                                          "# empty\n")
    loaded = loader.load_directory(tmp_path, only=["service"])
    assert "infra" in loaded
    assert "service" in loaded
    assert "unrelated" not in loaded
    assert loaded.index("infra") < loaded.index("service")


def test_load_plugin_auto_loads_dep_from_sibling_directory(tmp_path, loader):
    """load_plugin() should discover and load an unloaded dep from path.parent."""
    make_plugin(tmp_path, "base", "name: Base\nid: base\n", "# empty\n")
    make_plugin(tmp_path, "consumer", """
        name: Consumer
        id: consumer
        plugin_requirements: [base]
    """, "# empty\n")
    # Call load_plugin on consumer WITHOUT first loading base — it should auto-load base.
    loader.load_plugin(tmp_path / "consumer")
    assert "base" in loader.plugins
    assert "consumer" in loader.plugins


def test_load_plugin_auto_loads_transitive_deps(tmp_path, loader):
    """Auto-loading recurses through the full dep chain."""
    make_plugin(tmp_path, "a", "name: A\nid: a\n", "# empty\n")
    make_plugin(tmp_path, "b", "name: B\nid: b\nplugin_requirements: [a]\n", "# empty\n")
    make_plugin(tmp_path, "c", "name: C\nid: c\nplugin_requirements: [b]\n", "# empty\n")
    loader.load_plugin(tmp_path / "c")
    assert "a" in loader.plugins
    assert "b" in loader.plugins
    assert "c" in loader.plugins


def test_load_directory_skips_dependent_when_dep_fails(tmp_path, bus):
    """When a dep fails to load, load_directory should skip dependents gracefully."""
    make_plugin(tmp_path, "bad_dep", "name: Bad\nid: bad_dep\n", "raise RuntimeError('boom')\n")
    make_plugin(tmp_path, "consumer", """
        name: Consumer
        id: consumer
        plugin_requirements: [bad_dep]
    """, "# empty\n")
    make_plugin(tmp_path, "unrelated", "name: U\nid: unrelated\n", "# empty\n")
    loader = PluginLoader(bus=bus)
    loaded = loader.load_directory(tmp_path)
    assert "bad_dep" not in loaded
    assert "consumer" not in loaded
    assert "unrelated" in loaded


def test_bad_yaml_plugin_is_skipped_gracefully(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "good", "name: Good\nid: good\n", "# empty\n")
    bad_dir = tmp_path / "bad_yaml"
    bad_dir.mkdir()
    (bad_dir / "plugin.yaml").write_text("this: {is: [bad yaml\n")
    (bad_dir / "plugin.py").write_text("# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert "good" in loaded


# ---------------------------------------------------------------------------
# OS package manager detection
# ---------------------------------------------------------------------------

def test_detect_os_pkg_apt_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        _, _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_dnf_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/dnf" if b == "dnf" else None):
        _, _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_yum_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/yum" if b == "yum" else None):
        _, _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_pacman_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/pacman" if b == "pacman" else None):
        _, _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_apk_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/sbin/apk" if b == "apk" else None):
        _, _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_brew_no_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Darwin"):
        _, _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert "_sudo" not in kwargs


def test_detect_os_pkg_all_packages_in_one_call(loader):
    pkgs = ["curl", "wget", "jq"]
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        _, _, kwargs = loader._detect_os_pkg_op("p", pkgs)
    assert kwargs["packages"] == pkgs


def test_detect_os_pkg_no_manager_raises(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", return_value=None):
        with pytest.raises(PluginError, match="No supported OS package manager"):
            loader._detect_os_pkg_op("p", ["curl"])


# ---------------------------------------------------------------------------
# Pending changes startup summary
# ---------------------------------------------------------------------------

def test_no_warning_when_no_pending_changes(tmp_path, loader, caplog):
    make_plugin(tmp_path, "clean", "name: Clean\nid: clean\n", """
        from plugin_system.core import PluginBase
        class CleanPlugin(PluginBase):
            def setup(self): pass
    """)
    import logging
    with caplog.at_level(logging.WARNING, logger="plugin_system.core.loader"):
        loader.load_directory(tmp_path)
    assert "pending" not in caplog.text


def test_warning_logged_for_plugins_with_pending_changes(tmp_path, loader, caplog):
    make_plugin(tmp_path, "dirty", "name: Dirty\nid: dirty\n", """
        from plugin_system.core import PluginBase
        class DirtyPlugin(PluginBase):
            def setup(self): pass
    """)
    loader.load_directory(tmp_path)
    inst = loader.plugins["dirty"].instance
    state_file = MagicMock()
    state_file.pending_changes = True
    inst._state_file = state_file

    import logging
    with caplog.at_level(logging.WARNING, logger="plugin_system.core.loader"):
        loader._log_pending_changes()
    assert "dirty" in caplog.text
    assert "pending changes" in caplog.text


def test_warning_lists_all_pending_plugins(tmp_path, loader, caplog):
    for name in ("alpha", "beta"):
        make_plugin(tmp_path, name, f"name: {name}\nid: {name}\n", """
            from plugin_system.core import PluginBase
            class P(PluginBase):
                def setup(self): pass
        """)
    loader.load_directory(tmp_path)
    for pid in ("alpha", "beta"):
        state_file = MagicMock()
        state_file.pending_changes = True
        loader.plugins[pid].instance._state_file = state_file

    import logging
    with caplog.at_level(logging.WARNING, logger="plugin_system.core.loader"):
        loader._log_pending_changes()
    assert "alpha" in caplog.text
    assert "beta" in caplog.text


def test_plugins_without_state_file_ignored_in_pending_check(tmp_path, loader, caplog):
    make_plugin(tmp_path, "stateless", "name: S\nid: stateless\n", """
        from plugin_system.core import PluginBase
        class StatelessPlugin(PluginBase):
            def setup(self): pass
    """)
    import logging
    with caplog.at_level(logging.WARNING, logger="plugin_system.core.loader"):
        loader.load_directory(tmp_path)
    assert "pending" not in caplog.text


# ---------------------------------------------------------------------------
# cfg_dir seeding
# ---------------------------------------------------------------------------

def test_cfg_dir_seeds_plugin_yaml_on_first_boot(tmp_path, loader):
    """plugin.yaml is copied to cfg_dir/<plugin_id>/ when not already present."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    cfg_dir = tmp_path / "cfg"
    make_plugin(plugins_dir, "alpha", "name: Alpha\nid: alpha\nconfig:\n  key: original\n", """
        from plugin_system.core import PluginBase
        class AlphaPlugin(PluginBase):
            def setup(self): pass
    """)
    loader.load_directory(plugins_dir, cfg_dir=cfg_dir)
    seeded = cfg_dir / "alpha" / "plugin.yaml"
    assert seeded.exists(), "plugin.yaml should be copied into cfg_dir on first boot"


def test_cfg_dir_config_read_from_cfg_yaml_on_subsequent_boot(tmp_path, loader):
    """If cfg_dir/<plugin_id>/plugin.yaml already exists, its config: section is used."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    cfg_dir = tmp_path / "cfg"
    make_plugin(plugins_dir, "alpha", "name: Alpha\nid: alpha\nconfig:\n  key: original\n", """
        from plugin_system.core import PluginBase
        class AlphaPlugin(PluginBase):
            def setup(self): pass
    """)
    # Pre-seed a cfg_dir copy with an operator override
    (cfg_dir / "alpha").mkdir(parents=True)
    (cfg_dir / "alpha" / "plugin.yaml").write_text(
        "name: Alpha\nid: alpha\nservice_ports: -1\nconfig:\n  key: operator_value\n"
    )
    loader.load_directory(plugins_dir, cfg_dir=cfg_dir)
    inst = loader.plugins["alpha"]
    assert inst.config["key"] == "operator_value"


def test_cfg_dir_not_set_leaves_plugin_dir_unchanged(tmp_path, loader):
    """When cfg_dir is None, no seeding happens and config comes from plugin.yaml."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    make_plugin(plugins_dir, "alpha", "name: Alpha\nid: alpha\nconfig:\n  key: original\n", """
        from plugin_system.core import PluginBase
        class AlphaPlugin(PluginBase):
            def setup(self): pass
    """)
    loader.load_directory(plugins_dir)
    inst = loader.plugins["alpha"]
    assert inst.config["key"] == "original"
