#!/usr/bin/env python3
"""
PortMan — Port Manager for Sahil's ThinkPad (Linux Mint / GTK3).

Manage ALL ports from one GUI:
  Tab 1  Listening Ports   — every TCP/UDP port open on this machine,
                             who owns it (PID / process / user), kill it,
                             block or allow it in the firewall.
  Tab 2  All Connections   — live TCP/UDP connections (ESTAB, TIME_WAIT, …).
  Tab 3  Firewall          — UFW status + rules, add allow/deny, delete rule.
  Tab 4  USB / Serial      — lsusb devices + /dev/ttyUSB*, ttyACM*, serial.

No third-party deps: python3 + GTK3 + iproute2 (`ss`) which Mint ships.
Privileged actions go through `pkexec` (graphical sudo prompt), never
a password typed into this app.
"""
import os
import re
import sys
import pwd
import signal
import socket
import threading
import subprocess

try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, GLib, Gdk  # noqa: E402
    HAVE_GTK = True
except Exception:  # headless / CLI / tests — parser + --cli still work
    Gtk = GLib = Gdk = None
    HAVE_GTK = False

# ---------------------------------------------------------------- services
WELL_KNOWN = {
    22: 'SSH', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    587: 'SMTP-TLS', 631: 'CUPS Printing', 993: 'IMAPS', 995: 'POP3S',
    3000: 'Dev (Grafana/Node)', 3001: 'Dev (Node)', 3306: 'MySQL',
    5000: 'Dev (Flask)', 5173: 'Vite dev', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8000: 'Dev (Django)', 8080: 'HTTP-alt',
    8443: 'HTTPS-alt', 9090: 'Prometheus', 9200: 'Elasticsearch',
    27017: 'MongoDB', 5353: 'mDNS', 139: 'NetBIOS', 123: 'NTP',
}

CSS = b"""
/* App-specific rules only; backgrounds come from the system GTK theme. */
.summary-num { font-size: 20px; font-weight: bold; }
.summary-lbl { font-size: 11px; opacity: 0.7; }
.pill-listen { background-color: #2ec27e; color: #fff; border-radius: 10px; padding: 2px 10px; font-weight: bold; }
.pill-udp { background-color: #3584e4; color: #fff; border-radius: 10px; padding: 2px 10px; font-weight: bold; }
.mono { font-family: monospace; }
#danger-btn { color: #e01b24; font-weight: bold; }
#action-btn { font-weight: bold; padding: 6px 14px; }
"""


# ---------------------------------------------------------------- parsing
def split_addr_port(text):
    """'127.0.0.53%lo:53' / '[::]:8080' / '0.0.0.0:*' -> (addr, port_str)"""
    text = text.strip()
    if ':' not in text:
        return text, ''
    addr, _, port = text.rpartition(':')
    return addr.strip('[]'), port


def parse_process_field(text):
    """users:((\"node\",pid=1234,fd=20)) -> (name, pid) ; '' -> ('', None)"""
    m = re.search(r'"([^"]+)",pid=(\d+)', text or '')
    if m:
        return m.group(1), int(m.group(2))
    return '', None


def user_for_pid(pid):
    if not pid:
        return ''
    try:
        with open(f'/proc/{pid}/status') as f:
            for line in f:
                if line.startswith('Uid:'):
                    uid = int(line.split()[1])
                    try:
                        return pwd.getpwuid(uid).pw_name
                    except KeyError:
                        return str(uid)
    except OSError:
        pass
    return ''


def cmdline_for_pid(pid):
    if not pid:
        return ''
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            return f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
    except OSError:
        return ''


def parse_ss(output):
    """Parse `ss -tulnp` / `ss -tunap` output into row dicts."""
    rows = []
    for line in (output or '').splitlines():
        line = line.strip()
        if not line or line.startswith('Netid'):
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        netid, state, _rq, _sq, local, peer = parts[:6]
        rest = parts[6] if len(parts) > 6 else ''
        proc_name, pid = parse_process_field(rest)
        laddr, lport = split_addr_port(local)
        paddr, pport = split_addr_port(peer)
        try:
            port_num = int(lport)
        except ValueError:
            port_num = 0
        rows.append({
            'proto': netid.upper(), 'state': state,
            'local_addr': laddr, 'local_port': lport, 'port_num': port_num,
            'peer_addr': paddr, 'peer_port': pport,
            'process': proc_name, 'pid': pid,
            'user': user_for_pid(pid),
            'service': WELL_KNOWN.get(port_num, ''),
        })
    return rows


def run_cmd(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def get_listening():
    _, out = run_cmd(['ss', '-tulnp'])
    rows = parse_ss(out)
    # UDP sockets show state UNCONN; TCP listeners show LISTEN. Keep both.
    return [r for r in rows if r['state'] in ('LISTEN', 'UNCONN')]


def get_connections():
    _, out = run_cmd(['ss', '-tunap'])
    rows = parse_ss(out)
    return [r for r in rows if r['state'] not in ('LISTEN', 'UNCONN')]


def get_usb_serial():
    devices = []
    _, out = run_cmd(['lsusb'])
    for line in out.splitlines():
        if line.strip():
            devices.append({'kind': 'USB', 'device': line.strip(), 'detail': ''})
    for pat, kind in (('/dev/ttyUSB*', 'Serial-USB'), ('/dev/ttyACM*', 'Serial-ACM'),
                      ('/dev/ttyS*', 'Serial'), ('/dev/ttyAMA*', 'Serial')):
        import glob
        for dev in sorted(glob.glob(pat)):
            detail = ''
            try:
                detail = os.readlink(f'/dev/serial/by-id/{os.path.basename(dev)}')
            except OSError:
                pass
            devices.append({'kind': kind, 'device': dev, 'detail': detail})
    return devices


def get_firewall():
    """Return (status_text, [(num, action, port/proto, from), ...])"""
    if not _which('ufw'):
        # fall back to nftables listing, read-only
        if _which('nft'):
            _, out = run_cmd(['nft', 'list', 'ruleset'])
            return ('UFW not installed — showing nftables (read-only)\n\n' + out[:4000], [])
        return ('No ufw / nft found on this machine.', [])
    rc, out = run_cmd(['ufw', 'status', 'numbered'])
    if rc != 0 and 'root' in out.lower():
        return ('__NEEDS_ROOT__', [])
    rules = []
    for line in out.splitlines():
        m = re.match(r'\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*(.*)', line.strip())
        if m:
            rules.append({'num': int(m.group(1)), 'to': m.group(2).strip(),
                          'action': m.group(3), 'from': m.group(5).strip()})
    status = '\n'.join(l for l in out.splitlines() if not re.match(r'\[\s*\d+\]', l.strip()))
    return (status.strip(), rules)


def _which(name):
    from shutil import which
    return which(name)


# ---------------------------------------------------------------- GUI
_WindowBase = Gtk.Window if HAVE_GTK else object


class PortMan(_WindowBase):
    def __init__(self):
        super().__init__(title='Port Manager')
        self.set_default_size(1060, 640)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.listening = []
        self.connections = []
        self.fw_rules = []
        self.auto_timer = None

        style = Gtk.CssProvider()
        style.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), style, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(root)

        # ---- summary strip
        summary = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=28)
        summary.set_margin_top(12); summary.set_margin_bottom(6)
        summary.set_margin_start(16); summary.set_margin_end(16)
        self.sum_listen = self._summary_box(summary, '0', 'LISTENING')
        self.sum_conn = self._summary_box(summary, '0', 'CONNECTIONS')
        self.sum_procs = self._summary_box(summary, '0', 'PROCESSES')
        self.sum_fw = self._summary_box(summary, '—', 'FIREWALL')
        root.pack_start(summary, False, False, 0)

        # ---- toolbar: search + port check + refresh
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        bar.set_margin_start(16); bar.set_margin_end(16); bar.set_margin_bottom(8)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text('Filter by port, process, address…  (e.g. 3001, node, ssh)')
        self.search.connect('search-changed', lambda *_: self._apply_filter())
        bar.pack_start(self.search, True, True, 0)

        self.port_entry = Gtk.Entry()
        self.port_entry.set_placeholder_text('Check a port…')
        self.port_entry.set_width_chars(13)
        self.port_entry.connect('activate', lambda *_: self.on_check_port())
        bar.pack_start(self.port_entry, False, False, 0)
        chk = Gtk.Button(label='Check Port')
        chk.connect('clicked', lambda *_: self.on_check_port())
        bar.pack_start(chk, False, False, 0)

        self.auto_switch = Gtk.Switch()
        self.auto_switch.connect('state-set', self._on_auto)
        bar.pack_start(Gtk.Label(label='Auto-refresh'), False, False, 0)
        bar.pack_start(self.auto_switch, False, False, 0)
        refresh = Gtk.Button(label='↻  Refresh')
        refresh.set_name('action-btn')
        refresh.connect('clicked', lambda *_: self.refresh_all())
        bar.pack_start(refresh, False, False, 0)
        root.pack_start(bar, False, False, 0)

        # ---- tabs
        self.notebook = Gtk.Notebook()
        self.notebook.set_margin_start(10); self.notebook.set_margin_end(10)
        root.pack_start(self.notebook, True, True, 0)

        self.listen_store, self.listen_tree = self._make_tree([
            ('Proto', 70), ('Port', 70), ('Service', 130), ('Local Address', 170),
            ('State', 80), ('PID', 70), ('Process', 150), ('User', 100)])
        self.notebook.append_page(self._scroll(self.listen_tree), Gtk.Label(label='Listening Ports'))

        self.conn_store, self.conn_tree = self._make_tree([
            ('Proto', 70), ('Local', 200), ('Remote', 200), ('State', 110),
            ('PID', 70), ('Process', 150), ('User', 100)], conn=True)
        self.notebook.append_page(self._scroll(self.conn_tree), Gtk.Label(label='All Connections'))

        # firewall tab
        fw_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        fw_page.set_margin_top(8); fw_page.set_margin_start(8); fw_page.set_margin_end(8)
        self.fw_status = Gtk.Label(label='Loading firewall…', xalign=0)
        self.fw_status.set_line_wrap(True)
        self.fw_status.get_style_context().add_class('mono')
        fw_page.pack_start(self.fw_status, False, False, 0)
        self.fw_store, self.fw_tree = self._make_fw_tree()
        fw_page.pack_start(self._scroll(self.fw_tree), True, True, 0)
        fw_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for label, fn in (('Load Rules (sudo)', self.on_fw_load_root),
                          ('Delete Selected Rule', self.on_fw_delete)):
            b = Gtk.Button(label=label); b.connect('clicked', lambda *_ , f=fn: f())
            fw_btns.pack_start(b, False, False, 0)
        fw_page.pack_start(fw_btns, False, False, 4)
        self.notebook.append_page(fw_page, Gtk.Label(label='Firewall (UFW)'))

        # usb tab
        self.usb_store, self.usb_tree = self._make_usb_tree()
        self.notebook.append_page(self._scroll(self.usb_tree), Gtk.Label(label='USB / Serial Ports'))

        # ---- action bar (acts on selected listening/connection row)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_margin_start(16); actions.set_margin_end(16)
        actions.set_margin_top(8); actions.set_margin_bottom(4)
        kill = Gtk.Button(label='✕  Kill Process')
        kill.set_name('danger-btn')
        kill.connect('clicked', lambda *_: self.on_kill())
        actions.pack_start(kill, False, False, 0)
        block = Gtk.Button(label='⛔  Block Port (firewall)')
        block.connect('clicked', lambda *_: self.on_fw_port(deny=True))
        actions.pack_start(block, False, False, 0)
        allow = Gtk.Button(label='✓  Allow Port (firewall)')
        allow.connect('clicked', lambda *_: self.on_fw_port(deny=False))
        actions.pack_start(allow, False, False, 0)
        copyb = Gtk.Button(label='Copy Address')
        copyb.connect('clicked', lambda *_: self.on_copy())
        actions.pack_start(copyb, False, False, 0)
        root.pack_start(actions, False, False, 0)

        self.status = Gtk.Label(label='Loading…', xalign=0)
        self.status.set_margin_start(16); self.status.set_margin_bottom(10)
        root.pack_start(self.status, False, False, 0)

        self.connect('destroy', Gtk.main_quit)
        self.refresh_all()

    # ---------- builders
    def _summary_box(self, parent, num, lbl):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        n = Gtk.Label(label=num, xalign=0); n.get_style_context().add_class('summary-num')
        l = Gtk.Label(label=lbl, xalign=0); l.get_style_context().add_class('summary-lbl')
        box.pack_start(n, False, False, 0); box.pack_start(l, False, False, 0)
        parent.pack_start(box, False, False, 0)
        return n

    def _scroll(self, widget):
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.add(widget)
        return sw

    def _make_tree(self, cols, conn=False):
        types = [str] * len(cols)
        store = Gtk.ListStore(*types)
        tree = Gtk.TreeView(model=store)
        tree.set_search_column(1)
        for i, (title, width) in enumerate(cols):
            r = Gtk.CellRendererText()
            c = Gtk.TreeViewColumn(title, r, text=i)
            c.set_min_width(width); c.set_sort_column_id(i); c.set_resizable(True)
            tree.append_column(c)
        tree.connect('row-activated', lambda *_: self.on_row_detail())
        return store, tree

    def _make_fw_tree(self):
        store = Gtk.ListStore(str, str, str, str)
        tree = Gtk.TreeView(model=store)
        for i, (t, w) in enumerate((('#', 50), ('To', 220), ('Action', 110), ('From', 300))):
            c = Gtk.TreeViewColumn(t, Gtk.CellRendererText(), text=i)
            c.set_min_width(w); tree.append_column(c)
        return store, tree

    def _make_usb_tree(self):
        store = Gtk.ListStore(str, str, str)
        tree = Gtk.TreeView(model=store)
        for i, (t, w) in enumerate((('Type', 120), ('Device', 560), ('Detail', 260))):
            c = Gtk.TreeViewColumn(t, Gtk.CellRendererText(), text=i)
            c.set_min_width(w); tree.append_column(c)
        return store, tree

    # ---------- data
    def refresh_all(self):
        self.status.set_text('Refreshing…')
        def work():
            listening = get_listening()
            conns = get_connections()
            usb = get_usb_serial()
            fw_status, fw_rules = get_firewall()
            GLib.idle_add(self._fill, listening, conns, usb, fw_status, fw_rules)
        threading.Thread(target=work, daemon=True).start()

    def _fill(self, listening, conns, usb, fw_status, fw_rules):
        self.listening, self.connections, self.fw_rules = listening, conns, fw_rules
        self._apply_filter()
        self.conn_store.clear()
        for r in conns:
            self.conn_store.append([r['proto'], f"{r['local_addr']}:{r['local_port']}",
                                     f"{r['peer_addr']}:{r['peer_port']}", r['state'],
                                     str(r['pid'] or ''), r['process'], r['user']])
        self.usb_store.clear()
        for d in usb:
            self.usb_store.append([d['kind'], d['device'], d['detail']])
        if fw_status == '__NEEDS_ROOT__':
            self.fw_status.set_text('UFW needs sudo to show rules — click “Load Rules (sudo)” below.')
            self.sum_fw.set_text('sudo?')
        else:
            first = fw_status.splitlines()[0] if fw_status else 'unknown'
            self.fw_status.set_text(fw_status[:1500])
            self.sum_fw.set_text('ON' if 'active' in fw_status.lower() else 'OFF')
            self.fw_store.clear()
            for r in fw_rules:
                self.fw_store.append([str(r['num']), r['to'], r['action'], r['from']])
        self.sum_listen.set_text(str(len(listening)))
        self.sum_conn.set_text(str(len(conns)))
        self.sum_procs.set_text(str(len({r['pid'] for r in listening if r['pid']})))
        self.status.set_text(f"{len(listening)} listening ports • {len(conns)} connections • "
                             f"{len(usb)} USB/serial devices — double-click a row for full process details")
        return False

    def _apply_filter(self):
        q = (self.search.get_text() or '').lower().strip()
        self.listen_store.clear()
        for r in self.listening:
            hay = f"{r['port_num']} {r['process']} {r['local_addr']} {r['proto']} {r['service']} {r['user']}".lower()
            if q and q not in hay:
                continue
            self.listen_store.append([r['proto'], str(r['port_num']), r['service'],
                                      r['local_addr'], r['state'], str(r['pid'] or ''),
                                      r['process'], r['user']])

    def _on_auto(self, _switch, state):
        if state:
            self.auto_timer = GLib.timeout_add_seconds(3, self._auto_tick)
        elif self.auto_timer:
            GLib.source_remove(self.auto_timer); self.auto_timer = None
        return False

    def _auto_tick(self):
        self.refresh_all()
        return True

    # ---------- selection helpers
    def _selected_listen_row(self):
        page = self.notebook.get_current_page()
        tree = self.conn_tree if page == 1 else self.listen_tree
        model, it = tree.get_selection().get_selected()
        if not it:
            return None
        vals = [model.get_value(it, i) for i in range(model.get_n_columns())]
        return (page, vals)

    def _sel_info(self):
        """Normalised info for the selected row, whichever tab is active.
        Listening cols: Proto,Port,Service,Addr,State,PID,Process,User
        Conn cols:      Proto,Local,Remote,State,PID,Process,User"""
        sel = self._selected_listen_row()
        if not sel:
            return None
        page, vals = sel
        if page == 1:
            return {'page': page, 'proto': vals[0], 'local': vals[1],
                    'pid': vals[4], 'process': vals[5], 'port': '',
                    'addr': vals[1]}
        return {'page': page, 'proto': vals[0], 'port': vals[1],
                'addr': vals[3], 'pid': vals[5], 'process': vals[6],
                'local': f"{vals[3]}:{vals[1]}"}

    # ---------- actions
    def on_check_port(self):
        text = (self.port_entry.get_text() or '').strip()
        if not text.isdigit():
            self._msg('Type a port number first, e.g. 3001'); return
        port = int(text)
        owners = [r for r in self.listening if r['port_num'] == port]
        if owners:
            o = owners[0]
            self._msg(f"Port {port} is IN USE — {o['proto']} by "
                      f"{o['process'] or '?'} (PID {o['pid'] or '?'}, user {o['user'] or '?'})"
                      + (f" • {o['service']}" if o['service'] else ''))
        else:
            # double-check with a bind test on TCP
            s = socket.socket()
            try:
                s.bind(('0.0.0.0', port)); free = True
            except OSError:
                free = False
            finally:
                s.close()
            self._msg(f"Port {port} is FREE ✅" if free else
                      f"Port {port} shows no listener but bind failed — likely reserved/in TIME_WAIT")

    def on_row_detail(self):
        info = self._sel_info()
        if not info:
            return
        page, vals = self._selected_listen_row()
        pid = int(info['pid']) if (info['pid'] or '').isdigit() else None
        detail = cmdline_for_pid(pid) if pid else ''
        dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO, Gtk.ButtonsType.OK,
                                'Process details')
        dlg.format_secondary_text(f"Row: {'  '.join(v for v in vals if v)}\n\n"
                                  f"PID: {pid or '— (owned by another user / kernel — run app checks with ss)'}\n"
                                  f"Command line:\n{detail or '—'}")
        dlg.run(); dlg.destroy()

    def on_copy(self):
        info = self._sel_info()
        if not info:
            self._msg('Select a row first'); return
        text = info['local']
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(text, -1)
        self._msg(f'Copied: {text}')

    def on_kill(self):
        info = self._sel_info()
        if not info:
            self._msg('Select a listening port / connection first'); return
        pid_s = info['pid'] or ''
        if not pid_s.isdigit():
            self._msg('No PID on that row — process belongs to another user or the kernel'); return
        pid = int(pid_s)
        proc = info['process']
        if pid <= 1:
            self._msg('Refusing to kill PID 1 / kernel — that would crash the session'); return
        dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.WARNING, Gtk.ButtonsType.OK_CANCEL,
                                f'Kill {proc or "process"} (PID {pid})?')
        dlg.format_secondary_text('The port frees up as soon as the process exits. '
                                  'Unsaved work in that app is lost.')
        if dlg.run() == Gtk.ResponseType.OK:
            try:
                os.kill(pid, signal.SIGTERM)
                self._msg(f'Sent SIGTERM to PID {pid} ({proc}) — refreshing…')
            except PermissionError:
                rc, out = run_cmd(['pkexec', 'kill', str(pid)])
                self._msg('Killed via sudo prompt' if rc == 0 else f'Kill failed: {out.strip()[:200]}')
            except ProcessLookupError:
                self._msg('Process already gone')
            GLib.timeout_add(700, lambda *_: (self.refresh_all(), False)[1])
        dlg.destroy()

    def _fw_cmd_pkexec(self, args, done_msg):
        def work():
            rc, out = run_cmd(['pkexec'] + args, timeout=60)
            GLib.idle_add(self._msg, done_msg if rc == 0 else f'Failed ({rc}): {out.strip()[:300]}')
            GLib.idle_add(self.refresh_all)
        threading.Thread(target=work, daemon=True).start()

    def on_fw_port(self, deny):
        info = self._sel_info()
        if not info:
            self._msg('Select a listening port first'); return
        if info['page'] == 1:
            self._msg('Switch to Listening Ports tab to block/allow a port'); return
        port, proto = info['port'], info['proto'].lower()
        if port == '22':
            dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.WARNING, Gtk.ButtonsType.OK_CANCEL,
                                    'Port 22 is SSH')
            dlg.format_secondary_text('Blocking it can lock you out of remote access. Continue?')
            ok = dlg.run() == Gtk.ResponseType.OK; dlg.destroy()
            if not ok:
                return
        action = 'deny' if deny else 'allow'
        self._fw_cmd_pkexec(['ufw', action, f'{port}/{proto}'],
                            f'Firewall: {action} {port}/{proto} applied')

    def on_fw_load_root(self):
        def work():
            rc, out = run_cmd(['pkexec', 'ufw', 'status', 'numbered'], timeout=60)
            if rc == 0:
                rules = []
                for line in out.splitlines():
                    m = re.match(r'\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*(.*)', line.strip())
                    if m:
                        rules.append({'num': int(m.group(1)), 'to': m.group(2).strip(),
                                      'action': m.group(3), 'from': m.group(5).strip()})
                status = '\n'.join(l for l in out.splitlines() if not re.match(r'\[\s*\d+\]', l.strip()))
                GLib.idle_add(self._fill_fw_root, status.strip(), rules)
            else:
                GLib.idle_add(self._msg, f'Could not load firewall: {out.strip()[:250]}')
        threading.Thread(target=work, daemon=True).start()

    def _fill_fw_root(self, status, rules):
        self.fw_rules = rules
        self.fw_status.set_text(status[:1500])
        self.sum_fw.set_text('ON' if 'active' in status.lower() else 'OFF')
        self.fw_store.clear()
        for r in rules:
            self.fw_store.append([str(r['num']), r['to'], r['action'], r['from']])
        return False

    def on_fw_delete(self):
        model, it = self.fw_tree.get_selection().get_selected()
        if not it:
            self._msg('Select a firewall rule first (load rules with sudo)'); return
        num = model.get_value(it, 0)
        self._fw_cmd_pkexec(['ufw', '--force', 'delete', num],
                            f'Firewall rule {num} deleted')

    def _msg(self, text):
        self.status.set_text(text)
        return False


def main():
    if '--cli' in sys.argv:
        rows = get_listening()
        print(f"{'PROTO':6} {'PORT':7} {'SERVICE':16} {'ADDRESS':18} {'PID':7} PROCESS")
        for r in sorted(rows, key=lambda x: x['port_num']):
            print(f"{r['proto']:6} {r['local_port']:7} {r['service']:16} "
                  f"{r['local_addr']:18} {str(r['pid'] or '-'):7} {r['process']}")
        print(f"\n{len(rows)} listening ports")
        return
    if not HAVE_GTK:
        print("GTK3 not available on this machine — install python3-gi / gir1.2-gtk-3.0, "
              "or use --cli mode.")
        return
    win = PortMan()
    win.show_all()
    Gtk.main()


if __name__ == '__main__':
    main()
