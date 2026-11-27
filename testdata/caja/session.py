#!/usr/bin/python3
"""Actual Caja/GVfs GUI probe, deliberately run as an unprivileged ALT user."""
import json
import os
import pathlib
import subprocess
import time

import gi
gi.require_version('Gio', '2.0')
gi.require_version('Atspi', '2.0')
from gi.repository import Gio, GLib, Atspi

ART = pathlib.Path('/tmp/caja-artifacts')
ROOT = '/srv/sambaadm-caja-test'
BASE = 'smb://127.0.0.1/acl-test'
assert os.geteuid() == 1000, 'Caja must not run as root'
assert 'CapEff:\t0000000000000000' in pathlib.Path('/proc/self/status').read_text(), 'Unexpected capabilities'
results = []


def call(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def tree():
    def walk(obj, depth=0):
        if depth > 20:
            return None
        try:
            data = {'name': obj.get_name() or '', 'role': obj.get_role_name()}
            count = min(obj.get_child_count(), 300)
            data['children'] = [item for i in range(count) if (item := walk(obj.get_child_at_index(i), depth + 1))]
            return data
        except Exception:
            return None
    return walk(Atspi.get_desktop(0))


def names(data):
    if not data:
        return []
    return [data.get('name', '')] + [name for child in data.get('children', []) for name in names(child)]


def wait_for(predicate, seconds=12):
    deadline = time.monotonic() + seconds
    value = None
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.25)
    raise AssertionError('Timed out waiting for Caja UI')


def gui_navigate(uri):
    call('xdotool', 'key', '--clearmodifiers', 'Escape')
    call('xdotool', 'key', '--clearmodifiers', 'ctrl+l')
    call('xdotool', 'type', '--clearmodifiers', '--delay', '0', uri)
    call('xdotool', 'key', 'Return')
    time.sleep(1)


def record(label, uri, expected=None):
    gui_navigate(uri)
    data = tree()
    all_names = names(data)
    errors = ('permission denied', 'access was denied', 'could not display', 'could not be displayed', 'do not have the permissions')
    error = any(phrase in n.lower() for n in all_names for phrase in errors)
    marker_visible = any('inside.txt' in n for n in all_names)
    def frames(item):
        if not item:
            return []
        return ([item['name']] if item.get('role') == 'frame' else []) + [name for child in item.get('children', []) for name in frames(child)]
    frame_titles = frames(data)
    opened = uri.rstrip('/').split('/')[-1] in frame_titles and not error
    # The screenshot records the actual Caja window, not a reconstructed view.
    call('scrot', str(ART / (label + '.png')))
    (ART / (label + '-a11y.json')).write_text(json.dumps(data, indent=2))
    row = {'case': label, 'uri': uri, 'caja_contains_inside_file': marker_visible, 'caja_error': error, 'navigation_succeeded': opened, 'frame_titles': frame_titles,
           'ui_names': [n for n in all_names if n][:100]}
    results.append(row)
    print(json.dumps(row), flush=True)
    if expected == 'open':
        assert opened and marker_visible and not error, label + ': Caja did not display the readable child file'
    if expected == 'deny':
        assert error, label + ': Caja did not show the expected access error'
    return row


def contents(uri):
    try:
        ok, value, _ = Gio.File.new_for_uri(uri).load_contents(None)
        return {'ok': ok, 'text': value.decode()}
    except GLib.Error as error:
        return {'ok': False, 'error': error.message}


def mount_smb():
    loop = GLib.MainLoop()
    state = {}
    operation = Gio.MountOperation()
    def password(op, message, username, domain, flags):
        op.set_username('cajaqa')
        op.set_domain('WORKGROUP')
        op.set_password('Lab-Caja-Only1!')
        op.reply(Gio.MountOperationResult.HANDLED)
    operation.connect('ask-password', password)
    file = Gio.File.new_for_uri(BASE)
    def finished(source, result, data):
        try:
            state['ok'] = source.mount_enclosing_volume_finish(result)
        except GLib.Error as error:
            state['error'] = error.message
        loop.quit()
    file.mount_enclosing_volume(Gio.MountMountFlags.NONE, operation, None, finished, None)
    GLib.timeout_add_seconds(20, lambda: (loop.quit(), False)[1])
    loop.run()
    assert state.get('ok'), state


try:
    print('Caja GUI probe: uid=1000, effective capabilities=0, ALT p11', flush=True)
    subprocess.Popen(['openbox'], stdout=open('/tmp/caja-artifacts/openbox.log', 'w'), stderr=subprocess.STDOUT)
    for schema, key in [('org.mate.interface', 'accessibility'), ('org.gnome.desktop.interface', 'toolkit-accessibility')]:
        subprocess.run(['gsettings', 'set', schema, key, 'true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    mount_smb()
    subprocess.Popen(['caja', '--no-desktop', '--browser', ROOT + '/mode-r-x/nested'], stdout=open(ART / 'caja.log', 'w'), stderr=subprocess.STDOUT)
    wait_for(lambda: 'inside.txt' in '\n'.join(names(tree())))
    windows = call('xdotool', 'search', '--onlyvisible', '--class', 'Caja').splitlines()
    assert windows, 'Caja did not create a visible window'
    call('xdotool', 'windowsize', windows[0], '1260', '750')
    call('xdotool', 'windowmove', windows[0], '10', '20')
    call('xdotool', 'windowactivate', '--sync', windows[0])
    record('01-local-r-x', 'file://' + ROOT + '/mode-r-x/nested', 'open')
    record('01b-local-parent-no-x', 'file://' + ROOT + '/mode-r--')
    record('02-local-no-x', 'file://' + ROOT + '/mode-r--/nested', 'deny')
    record('03-local-acl-mask-no-x', 'file://' + ROOT + '/acl-mask-no-x/nested', 'deny')
    record('04-smb-r-x', BASE + '/mode-r-x/nested', 'open')
    # Capture SMB behavior independently of local-filesystem assumptions.
    record('04b-smb-parent-no-x', BASE + '/mode-r--')
    smb_no_x = record('05-smb-no-x', BASE + '/mode-r--/nested', 'deny')
    smb_mask = record('06-smb-acl-mask-no-x', BASE + '/acl-mask-no-x/nested', 'deny')
    for protocol, prefix in [('local', 'file://' + ROOT), ('smb', BASE)]:
        for folder in ['mode-r-x', 'mode-r--', 'acl-mask-no-x']:
            row = {'read_test': protocol + '/' + folder, **contents(prefix + '/' + folder + '/nested/inside.txt')}
            results.append(row)
            print(json.dumps(row), flush=True)
            assert row['ok'] == (folder == 'mode-r-x'), row
    for prefix in ['file://' + ROOT, BASE]:
        assert contents(prefix + '/file-no-exec.txt')['ok'], 'Ordinary readable file required x'
    (ART / 'needs-x').touch()
    wait_for(lambda: (ART / 'x-restored').exists(), seconds=60)
    record('07-local-x-restored', 'file://' + ROOT + '/mode-r--/nested', 'open')
    record('08-local-mask-restored', 'file://' + ROOT + '/acl-mask-no-x/nested', 'open')
    record('09-smb-x-restored', BASE + '/mode-r--/nested', 'open')
    record('10-smb-mask-restored', BASE + '/acl-mask-no-x/nested', 'open')
    for prefix in ['file://' + ROOT, BASE]:
        for folder in ['mode-r--', 'acl-mask-no-x']:
            assert contents(prefix + '/' + folder + '/nested/inside.txt')['ok'], 'Restoring x did not restore child access'
    (ART / 'results.json').write_text(json.dumps(results, indent=2))
    print('PASS actual ALT p11 Caja local/SMB traversal checks, ACL mask, and restoration', flush=True)
except Exception:
    (ART / 'results.json').write_text(json.dumps(results, indent=2))
    (ART / 'failure-a11y.json').write_text(json.dumps(tree(), indent=2))
    subprocess.run(['scrot', str(ART / 'failure.png')])
    raise
