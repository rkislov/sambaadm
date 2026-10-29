"""Run the actual upstream ALT client parser on sambaadm and GPUI output."""
import os
import sys
import types
from pathlib import Path

checkout, fixtures = map(Path, sys.argv[1:])
sys.path[:0] = [str(checkout / "gpoa"), str(checkout / "gpoa_lib")]
# Load the upstream parser and DynamicAttributes unchanged, without running
# unrelated package initializers that open the client's NSS/storage backends.
# Only namespace packages are provided here; no parser or client class is mocked.
for package, directory in (
    ("gpt", checkout / "gpoa/gpt"),
    ("gpoa_lib", checkout / "gpoa_lib/gpoa_lib"),
    ("gpoa_lib.storage", checkout / "gpoa_lib/gpoa_lib/storage"),
):
    namespace = types.ModuleType(package)
    namespace.__path__ = [str(directory)]
    sys.modules[package] = namespace
from gpt.scriptsini import read_scripts

expected = [("--ключ=значение=a", "ПРИМЕР.SH"), ("--two", "SECOND.SH")]
for event, files in {"STARTUP": ["ПРИМЕР.SH", "SECOND.SH"], "SHUTDOWN": ["STOP.SH"]}.items():
    (fixtures / event).mkdir(exist_ok=True)
    for name in files:
        (fixtures / event / name).write_bytes(b"#!/bin/sh\nexit 0\n")
for name in ("input.ini", "gpui.ini"):
    scripts = read_scripts(str(fixtures / name))
    actual = [(script.args, os.path.basename(script.path)) for script in scripts.get_startup_scripts()]
    assert actual == expected, (name, actual)
    assert len(scripts.get_shutdown_scripts()) == 1
print("PASS: upstream gpupdate reads ordered Unicode scripts from sambaadm and GPUI")
