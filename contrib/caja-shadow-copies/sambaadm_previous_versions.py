"""Caja extension for SMB Previous Versions."""
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit


TOKEN = re.compile(r"@GMT-\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}")
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")
EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="caja-shadow")


@dataclass(frozen=True)
class SMBPath:
    host: str
    share: str
    parts: tuple

    @classmethod
    def parse(cls, uri):
        if any(ord(c) < 32 or ord(c) == 127 for c in uri):
            return None
        try:
            url = urlsplit(uri)
            if (url.scheme != "smb" or not HOST.fullmatch(url.netloc)
                    or url.query or url.fragment):
                return None
            share, *parts = [unquote(p, errors="strict") for p in url.path[1:].rstrip("/").split("/")]
        except (UnicodeError, ValueError):
            return None
        for part in (share, *parts):
            # smbclient -c splits on semicolons even inside quoted arguments.
            if (not part or part in (".", "..") or TOKEN.fullmatch(part)
                    or any(c in part for c in '/\\;"')
                    or any(ord(c) < 32 or ord(c) == 127 for c in part)):
                return None
        if "%" in share:
            return None
        return cls(url.netloc, share, tuple(parts))

    def uri(self, snapshot=None, parts=None):
        path = (self.share,)
        if snapshot is not None:
            path += (snapshot,)
        path += self.parts if parts is None else parts
        return "smb://" + self.host + "/" + "/".join(quote(part, safe="@") for part in path)

    def list_command(self, executable):
        relative = "\\".join(self.parts) or "/"
        return [executable, f"//{self.host}/{self.share}", "--use-kerberos=required",
                "--no-pass", "--client-protection=sign", "--timeout=8", "-c",
                f'allinfo "{relative}"']


def snapshot_time(token):
    return datetime.strptime(token, "@GMT-%Y.%m.%d-%H.%M.%S").replace(tzinfo=timezone.utc)


def parse_versions(output):
    versions = set()
    token = None
    for line in output.splitlines():
        if TOKEN.fullmatch(line):
            token = line
        elif token and line.startswith("create_time:"):
            # Samba prints the token before checking whether the selected path
            # existed in that snapshot. Keep only successful path lookups.
            try:
                snapshot_time(token)
            except ValueError:
                pass
            else:
                versions.add(token)
            token = None
    return sorted(versions, reverse=True)


def list_versions(target):
    client = shutil.which("smbclient")
    if not client:
        raise RuntimeError("Установите smbclient для запроса предыдущих версий.")
    try:
        result = subprocess.run(target.list_command(client), text=True, errors="replace",
                                capture_output=True, env={**os.environ, "LC_ALL": "C"},
                                timeout=30, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Сервер не ответил на запрос предыдущих версий.") from error
    versions = parse_versions(result.stdout)
    if result.returncode or re.search(r"NT_STATUS_\w+ getting shadow copy data", result.stderr):
        raise RuntimeError(
            "SMB не вернул список снимков. Проверьте билет Kerberos "
            "и поддержку предыдущих версий на сервере."
        )
    if not versions and not any(line.startswith("create_time:") for line in result.stdout.splitlines()):
        raise RuntimeError("Не удалось прочитать объект через SMB. Проверьте доступ и билет Kerberos.")
    return versions


try:
    import gi
except ImportError:
    gi = None

if gi is not None:
    gi.require_version("Caja", "2.0")
    gi.require_version("Gtk", "3.0")
    from gi.repository import Caja, Gio, GLib, GObject, Gtk

    class PreviousVersions(GObject.GObject, Caja.MenuProvider):
        def get_file_items(self, window, files):
            if len(files) == 1:
                return self._items(window, files[0], False)
            return []

        def get_background_items(self, window, folder):
            return self._items(window, folder, True)

        def _items(self, window, file, background):
            target = SMBPath.parse(file.get_uri())
            if target is None:
                return []
            kind = "Folder" if background else "Selection"
            item = Caja.MenuItem(name=f"SambaADM::PreviousVersions{kind}",
                                 label="Предыдущие версии…",
                                 tip="Открыть снимок сетевого ресурса SMB")
            item.connect("activate", self._show_versions, window, target, file.is_directory())
            return [item]

        @staticmethod
        def _message(parent, message, error=False):
            dialog = Gtk.MessageDialog(transient_for=parent, modal=True,
                                       message_type=Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO,
                                       buttons=Gtk.ButtonsType.CLOSE, text=message)
            dialog.connect("response", lambda widget, response: widget.destroy())
            dialog.show()

        def _show_versions(self, item, window, target, directory):
            dialog = Gtk.Dialog(title="Предыдущие версии", transient_for=window, modal=False,
                                destroy_with_parent=True)
            dialog.set_default_size(450, 140)
            dialog.add_button("Закрыть", Gtk.ResponseType.CLOSE)
            dialog.connect("response", lambda widget, response: widget.destroy())
            cancellation = Gio.Cancellable()
            dialog.connect("destroy", lambda widget: cancellation.cancel())
            area = dialog.get_content_area()
            area.set_border_width(14)
            area.set_spacing(10)
            status = Gtk.Label(label="Запрашиваю снимки по SMB…", xalign=0, wrap=True)
            area.pack_start(status, False, False, 0)
            dialog.show_all()

            def loaded(future):
                if cancellation.is_cancelled():
                    return
                try:
                    versions = future.result()
                except (OSError, RuntimeError) as error:
                    status.set_text(str(error))
                    return
                if not versions:
                    status.set_text("Для этого объекта предыдущих версий не найдено.")
                    return
                status.set_text(f"Доступных снимков: {len(versions)}. Время указано по настройкам АРМ.")
                choices = Gtk.ComboBoxText()
                for version in versions:
                    choices.append(version, snapshot_time(version).astimezone().strftime("%d.%m.%Y %H:%M:%S %Z"))
                choices.set_active(0)
                area.pack_start(choices, False, False, 0)
                buttons = Gtk.Box(spacing=8)
                area.pack_start(buttons, False, False, 0)
                open_button = Gtk.Button(label="Открыть")
                open_button.connect("clicked", lambda _button: self._open(dialog, target, choices.get_active_id()))
                buttons.pack_start(open_button, False, False, 0)
                if not directory and target.parts:
                    copy_button = Gtk.Button(label="Скопировать рядом")
                    copy_button.connect("clicked", lambda button: self._copy(
                        dialog, target, choices.get_active_id(), button, cancellation))
                    buttons.pack_start(copy_button, False, False, 0)
                area.show_all()

            future = EXECUTOR.submit(list_versions, target)
            future.add_done_callback(lambda result: GLib.idle_add(loaded, result))
            dialog.connect("destroy", lambda _widget: future.cancel())

        def _open(self, dialog, target, snapshot):
            try:
                Gio.AppInfo.launch_default_for_uri(target.uri(snapshot), None)
            except GLib.Error as error:
                self._message(dialog, error.message, error=True)

        def _copy(self, dialog, target, snapshot, button, cancellation):
            original = target.parts[-1]
            stem, suffix = os.path.splitext(original)
            stamp = snapshot_time(snapshot).strftime("%Y-%m-%d_%H-%M-%SZ")
            name = f"{stem} ({stamp}){suffix}"
            source = Gio.File.new_for_uri(target.uri(snapshot))
            destination = Gio.File.new_for_uri(target.uri(parts=target.parts[:-1])).get_child(name)
            button.set_sensitive(False)

            def done(file, result, *_user_data):
                try:
                    file.copy_finish(result)
                except GLib.Error as error:
                    if not cancellation.is_cancelled():
                        self._message(dialog, error.message, error=True)
                else:
                    if not cancellation.is_cancelled():
                        self._message(dialog, f"Создана копия «{name}».")
                finally:
                    if not cancellation.is_cancelled():
                        button.set_sensitive(True)

            source.copy_async(destination, Gio.FileCopyFlags.NONE, GLib.PRIORITY_DEFAULT,
                              cancellation, None, None, done)
