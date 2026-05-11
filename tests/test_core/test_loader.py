import sys
import textwrap
import pytest
from pathlib import Path
from unittest.mock import patch

from plugin_system.core import EventBus, PluginLoader, Service
from plugin_system.core.loader import PluginError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_plugin(root: Path, name: str, yaml_content: str, py_content: str) -> Path:
    plugin_dir = root / name
    plugin_dir.mkdir()
    (plugin_dir / "plugin.yaml").write_text(textwrap.dedent(yaml_content))
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
    (plugin_dir / "plugin.yaml").write_text("name: Dir Name\n")  # no id field
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
    make_plugin(tmp_path, "dns_plugin", "name: DNS\nid: dns_plugin\n", """
        from plugin_system.core import PluginBase, Service

        class DNSPlugin(PluginBase):
            services = [Service.DNS]
    """)
    loader.load_plugin(tmp_path / "dns_plugin")
    assert loader.service_registry[Service.DNS] == "dns_plugin"


def test_service_conflict_raises(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "plugin_a", "name: A\nid: plugin_a\n", """
        from plugin_system.core import PluginBase, Service

        class PluginA(PluginBase):
            services = [Service.DNS]
    """)
    make_plugin(tmp_path, "plugin_b", "name: B\nid: plugin_b\n", """
        from plugin_system.core import PluginBase, Service

        class PluginB(PluginBase):
            services = [Service.DNS]
    """)
    loader.load_plugin(tmp_path / "plugin_a")
    with pytest.raises(PluginError, match="already owned"):
        loader.load_plugin(tmp_path / "plugin_b")


def test_service_registry_snapshot(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "reg_plugin", "name: Reg\nid: reg_plugin\n", """
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
    bus.emit(Event("fire.event", "test", payload={"value": 42}))
    mod = sys.modules["_plugin_fire_plugin"]
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
    make_plugin(tmp_path, "svc_a", "name: SvcA\nid: svc_a\n", """
        from plugin_system.core import PluginBase, Service

        class SvcA(PluginBase):
            services = [Service.DNS]
    """)
    make_plugin(tmp_path, "svc_b", "name: SvcB\nid: svc_b\n", """
        from plugin_system.core import PluginBase, Service

        class SvcB(PluginBase):
            services = [Service.DNS]
    """)
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
# boot_priority ordering
# ---------------------------------------------------------------------------

def test_boot_priority_zero_loads_before_default(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "zzz_late", "name: Late\nid: zzz_late\n", "# empty\n")
    make_plugin(tmp_path, "aaa_early", "name: Early\nid: aaa_early\nboot_priority: 0\n", "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded.index("aaa_early") < loaded.index("zzz_late")


def test_boot_priority_explicit_ordering(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "p3", "name: P3\nid: p3\nboot_priority: 30\n", "# empty\n")
    make_plugin(tmp_path, "p1", "name: P1\nid: p1\nboot_priority: 10\n", "# empty\n")
    make_plugin(tmp_path, "p2", "name: P2\nid: p2\nboot_priority: 20\n", "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded == ["p1", "p2", "p3"]


def test_boot_priority_ties_broken_alphabetically(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "charlie", "name: C\nid: charlie\nboot_priority: 50\n", "# empty\n")
    make_plugin(tmp_path, "alice",   "name: A\nid: alice\nboot_priority: 50\n",   "# empty\n")
    make_plugin(tmp_path, "bob",     "name: B\nid: bob\nboot_priority: 50\n",     "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded == ["alice", "bob", "charlie"]


def test_boot_priority_missing_defaults_to_100(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    make_plugin(tmp_path, "explicit_99", "name: E\nid: explicit_99\nboot_priority: 99\n", "# empty\n")
    make_plugin(tmp_path, "no_priority", "name: N\nid: no_priority\n", "# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded.index("explicit_99") < loaded.index("no_priority")


def test_boot_priority_bad_yaml_falls_back_to_100(tmp_path, bus):
    loader = PluginLoader(bus=bus)
    # Plugin with boot_priority: 1 should load before the one with a bad YAML (defaults to 100)
    make_plugin(tmp_path, "good",  "name: Good\nid: good\nboot_priority: 1\n", "# empty\n")
    bad_dir = tmp_path / "bad_yaml"
    bad_dir.mkdir()
    (bad_dir / "plugin.yaml").write_text("this: {is: [bad yaml\n")
    (bad_dir / "plugin.py").write_text("# empty\n")
    loaded = loader.load_directory(tmp_path)
    assert loaded.index("good") == 0


# ---------------------------------------------------------------------------
# OS package manager detection
# ---------------------------------------------------------------------------

def test_detect_os_pkg_apt_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_dnf_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/dnf" if b == "dnf" else None):
        _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_yum_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/yum" if b == "yum" else None):
        _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_pacman_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/pacman" if b == "pacman" else None):
        _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_apk_includes_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/sbin/apk" if b == "apk" else None):
        _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert kwargs["_sudo"] is True


def test_detect_os_pkg_brew_no_sudo(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Darwin"):
        _, kwargs = loader._detect_os_pkg_op("p", ["curl"])
    assert "_sudo" not in kwargs


def test_detect_os_pkg_all_packages_in_one_call(loader):
    pkgs = ["curl", "wget", "jq"]
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", side_effect=lambda b: "/usr/bin/apt-get" if b == "apt-get" else None):
        _, kwargs = loader._detect_os_pkg_op("p", pkgs)
    assert kwargs["packages"] == pkgs


def test_detect_os_pkg_no_manager_raises(loader):
    with patch("plugin_system.core.loader.platform.system", return_value="Linux"), \
         patch("plugin_system.core.loader.shutil.which", return_value=None):
        with pytest.raises(PluginError, match="No supported OS package manager"):
            loader._detect_os_pkg_op("p", ["curl"])
