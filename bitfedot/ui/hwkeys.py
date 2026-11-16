"""Hardware keys page: the staged YubiKey setup from hardware_keys.py.

This page refreshes every few seconds, so nothing it polls may open a
connection to a key (that would reset the key under a running script). Serial
numbers are read only when the user presses a confirm button.

Each stage shows its script or runs it in a terminal window; this page only
tracks progress and enforces the order. EXPERIMENTAL — see hardware_keys.py.
"""
from gi.repository import Adw, GLib, Gtk

from .. import hardware_keys as hk
from .widgets import error_text, run_async, toast


class HardwareKeysPage(Gtk.Box):
    title = "Hardware keys"
    icon = "dialog-password-symbolic"

    def __init__(self, demo=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.demo = demo
        self.facts = None
        self.loading = False
        banner = Adw.Banner(revealed=True, title="Experimental: run end to end on one computer so far (Fedora 45, two "
                                                 "YubiKey 5C NFC). Read every script before running it.")
        self.append(banner)
        page = Adw.PreferencesPage(
            vexpand=True,
            description="Move disk encryption, login, administrator prompts and release signing onto two "
                        "YubiKeys — a main key and a backup. Every step runs as a visible script in a "
                        "terminal. Steps 1–5 only add the keys next to your password; step 6 changes how "
                        "the keyring is opened, and only the last step removes the password.")
        self.append(page)
        self.rows = {}
        self.g_health = Adw.PreferencesGroup(title="Needs attention", visible=False)
        self.health_rows = []
        page.add(self.g_health)

        g = Adw.PreferencesGroup(title="1 · Prepare",
                                 description="Optional — every step below installs what it is missing itself.")
        self._stage(g, "prepare", "Install the YubiKey tools", "Fedora packages: " + ", ".join(hk.PACKAGES),
                    lambda: hk.prepare_script())
        page.add(g)

        g = Adw.PreferencesGroup(title="2 · The two keys",
                                 description="Sets the FIDO2 PIN and the OpenPGP PINs, and requires a touch "
                                             "for every signature.")
        self.reset = Adw.SwitchRow(title="Offer a factory reset first", active=True,
                                   subtitle="For keys that were used before. The script still asks you to "
                                            "type RESET for each key; new keys can skip it.")
        g.add(self.reset)
        for role in hk.ROLES:
            self._stage(g, f"key-{role}", f"Set up the {role} key", "",
                        lambda r=role: hk.key_script(r, self.reset.get_active()))
        page.add(g)

        g = Adw.PreferencesGroup(
            title="3 · Signing key",
            description="An OpenPGP key for signing BitFedot releases (and your git tags). Nothing leaves "
                        "this computer.")
        self.pgp_mode = Adw.ComboRow(title="How", model=Gtk.StringList.new([
            "Same key on both YubiKeys (created in memory, copied to both, then destroyed)",
            "A separate key on each YubiKey (never exists outside a key — stronger)"]))
        self.pgp_name = Adw.EntryRow(title="Name on the key", text="BitFedot release signing")
        self.pgp_email = Adw.EntryRow(title="E-mail on the key")
        for w in (self.pgp_mode, self.pgp_name, self.pgp_email):
            g.add(w)
        self._stage(g, "pgp", "Create the signing key", "Public key(s) are written to ~/bitfedot-release-keys",
                    lambda: hk.pgp_script("clone" if self.pgp_mode.get_selected() == 0 else "separate",
                                          self.pgp_name.get_text().strip(), self.pgp_email.get_text().strip(),
                                          GLib.get_home_dir() + "/bitfedot-release-keys"))
        page.add(g)

        g = Adw.PreferencesGroup(
            title="4 · Disk encryption",
            description="Adds both keys to every encrypted volume and rebuilds the boot image with drivers "
                        "for any keyboard and display. At boot the graphical screen asks for the key's "
                        "PIN once and the key blinks for one touch. Your password keeps working.")
        self.plain_boot = Adw.SwitchRow(title="Plain-text boot prompts instead", active=False,
                                        subtitle="Only for displays where the graphical boot screen does not "
                                                 "work: the PIN question then appears between boot messages.")
        g.add(self.plain_boot)
        self._stage(g, "disk", "Enroll both keys", "", lambda: hk.disk_script(self.facts["luks"],
                                                                              self.plain_boot.get_active()))
        self._stage(g, "boot", "Tidy the boot prompt",
                    "For keys enrolled with an earlier version: graphical screen, one PIN, one touch.",
                    lambda: hk.boot_script(self.facts["luks"], self.plain_boot.get_active()))
        self.boot_row = Adw.ActionRow(title="Confirm a boot", subtitle="Restart, unlock with ONE key, then "
                                                                        "confirm here. Repeat with the other key.")
        confirm = Gtk.Button(label="This key unlocked the disk", valign=Gtk.Align.CENTER)
        confirm.connect("clicked", lambda *_: self._confirm_boot())
        self.boot_row.add_suffix(confirm)
        g.add(self.boot_row)
        page.add(g)

        g = Adw.PreferencesGroup(
            title="5 · Login and administrator prompts",
            description="Registers both keys for login, sudo and password dialogs (PIN + touch). Your "
                        "password keeps working until the last step.")
        self._stage(g, "login", "Register both keys", "", lambda: hk.login_script(self.facts["user"]))
        self.login_row = Adw.ActionRow(title="Confirm sudo", subtitle="Run “sudo -k &amp;&amp; sudo true” with ONE "
                                                                       "key plugged in. Repeat with the other.")
        ok = Gtk.Button(label="sudo asked for this key", valign=Gtk.Align.CENTER)
        ok.connect("clicked", lambda *_: self._confirm_login())
        self.login_row.add_suffix(ok)
        g.add(self.login_row)
        page.add(g)

        g = Adw.PreferencesGroup(
            title="6 · Keyring",
            description="Saved Wi-Fi and app passwords live in the desktop keyring, which is opened by the "
                        "login password you type. After a key login nothing is typed, so the keyring is "
                        "switched to open by itself: its password becomes a long random one, stored "
                        "encrypted for your user on this installation — so it is as safe as the disk it "
                        "sits on, the one your keys unlock. What it costs: from then on a login with a "
                        "typed password no longer opens the keyring, and after a reinstall (or, with a "
                        "TPM chip, after that chip is cleared or replaced) the saved passwords have to "
                        "be entered again.")
        self._stage(g, "keyring", "Open the keyring automatically", hk.KEYRING_HINT,
                    lambda: hk.keyring_script(self.facts.get("keyring_encrypted", True)))
        page.add(g)

        g = Adw.PreferencesGroup(
            title="7 · Remove the password",
            description="Irreversible. Available only when both keys have unlocked the disk at boot and "
                        "have been confirmed for sudo, and the keyring opens by itself (step 6).")
        self.recovery = Adw.SwitchRow(
            title="Also create a paper recovery key (optional)", active=False,
            subtitle="A long code, shown once, to write down and store away. It is the only way in "
                     "besides the two keys. Off: there is no text password of any kind.")
        self.recovery.connect("notify::active", lambda *_: self._recovery_warning())
        g.add(self.recovery)
        self.lost_warning = Adw.ActionRow()
        self.lost_warning.add_css_class("error")
        icon = Gtk.Image(icon_name="dialog-warning-symbolic")
        icon.add_css_class("error")
        self.lost_warning.add_prefix(icon)
        g.add(self.lost_warning)
        self._recovery_warning()
        self._stage(g, "finalize", "Remove the password everywhere", "",
                    lambda: hk.finalize_script(self.facts["luks"], self.facts["user"], self.recovery.get_active()))
        self.gate = Adw.ActionRow(title="Still missing", subtitle="…")
        g.add(self.gate)
        page.add(g)

    def _recovery_warning(self):
        """The red line under the recovery-key switch."""
        if self.recovery.get_active():
            self.lost_warning.set_title("If both keys AND the paper recovery key are lost, the data on "
                                        "this computer is lost forever.")
        else:
            self.lost_warning.set_title("No paper recovery key: if both keys are lost or broken, the data "
                                        "on this computer is lost forever. Nobody can recover it.")

    def _stage(self, group, key, title, subtitle, make_script):
        row = Adw.ActionRow(title=title, subtitle=subtitle)
        show = Gtk.Button(label="Show script", valign=Gtk.Align.CENTER)
        show.connect("clicked", lambda *_: self._show(title, make_script))
        go = Gtk.Button(label="Run in terminal", valign=Gtk.Align.CENTER)
        go.add_css_class("suggested-action" if key != "finalize" else "destructive-action")
        go.connect("clicked", lambda *_: self._run(key, make_script))
        row.add_suffix(show)
        row.add_suffix(go)
        group.add(row)
        self.rows[key] = (row, go, subtitle)

    # --------------------------------------------------------------- state --
    def update(self, snap):
        if self.get_mapped() and not self.loading:
            self.refresh()

    def refresh(self):
        if self.demo:
            return self._render({"user": "you", "missing_tools": list(hk.PACKAGES), "pgp": [], "present": 0,
                                 "luks": [], "fido2_boot": False,
                                 "pam_u2f": False, "password_locked": False, "terminal": True}, {})
        self.loading = True

        def work():
            f, hw = hk.facts(), hk.adopt_serials()
            return f, hw, hk.health(f, hw)
        run_async(work, lambda r: (setattr(self, "loading", False), self._render(*r)),
                  lambda e: setattr(self, "loading", False))

    def _render(self, facts, hw, problems=()):
        self.facts = facts
        for row in self.health_rows:
            self.g_health.remove(row)
        self.health_rows = []
        for severity, text in problems:
            row = Adw.ActionRow(title="Do this before restarting" if severity == "critical" else "Check",
                                subtitle=text, subtitle_selectable=True)
            icon = Gtk.Image(icon_name="dialog-warning-symbolic")
            icon.add_css_class("error" if severity == "critical" else "warning")
            row.add_prefix(icon)
            self.g_health.add(row)
            self.health_rows.append(row)
        self.g_health.set_visible(bool(problems))
        hw = {"boot_ok": [], "login_ok": [], **hw}
        have_keys = all(hw.get(r) for r in hk.ROLES)
        n = facts["present"]
        plugged = "no key" if n == 0 else "one key" if n == 1 else f"{n} keys — unplug all but one"
        missing = facts["missing_tools"]
        self.rows["prepare"][0].set_subtitle("Installed ✓" if not missing else
                                             "Still missing: " + ", ".join(missing))
        for role in hk.ROLES:
            row, go, _ = self.rows[f"key-{role}"]
            row.set_subtitle(f"Done ✓ — serial {hw[role]} · running it again keeps PINs that are already set"
                             if hw.get(role) else f"Plugged in now: {plugged}")
        self.rows["pgp"][1].set_sensitive(have_keys)
        self.pgp_done = bool(facts["pgp"])
        if facts["pgp"]:
            self.rows["pgp"][0].set_subtitle("Created ✓ — " + ", ".join(
                " ".join(f[i:i + 4] for i in range(0, 40, 4)) for f in facts["pgp"]))
        disks = ", ".join(d["device"] for d in facts["luks"]) or "no encrypted volume found"
        self.rows["disk"][0].set_subtitle(("Enrolled ✓ · " if hw.get("disk") else "") + f"Volumes: {disks}")
        self.rows["disk"][1].set_sensitive(have_keys and bool(facts["luks"]))
        self.rows["boot"][0].set_visible(bool(hw.get("disk")))
        self.rows["boot"][1].set_sensitive(have_keys and bool(facts["luks"]))
        self.boot_row.set_subtitle(
            f"Confirmed for: {', '.join(hw['boot_ok']) or 'no key yet'} · this boot "
            + ("was unlocked with a key" if facts["fido2_boot"] else "shows no key unlock in the journal"))
        self.rows["login"][0].set_subtitle("Registered ✓" if facts["pam_u2f"] else "")
        keyring_text, keyring_runs = hk.keyring_stage(hw, facts)
        self.rows["keyring"][0].set_subtitle(keyring_text)
        self.rows["keyring"][1].set_sensitive(keyring_runs)
        self.rows["login"][1].set_sensitive(have_keys)
        self.login_row.set_subtitle(f"Confirmed for: {', '.join(hw['login_ok']) or 'no key yet'}")
        ok, missing = hk.ready_to_finalize(hw, facts.get("keyring_supported", True))
        self.rows["finalize"][1].set_sensitive(ok and not hw.get("final"))
        self.gate.set_visible(not ok)
        self.gate.set_subtitle("\n".join(missing))
        if facts["password_locked"]:
            self.rows["finalize"][0].set_subtitle("Done — the login password is locked ✓")

    # ------------------------------------------------------------- actions --
    def _guard(self):
        if self.demo:
            toast(self, "Demo mode — nothing is changed")
        return self.demo or self.facts is None

    def _show(self, title, make_script):
        try:
            text = make_script() if self.facts else "Still reading the system state…"
        except (ValueError, KeyError) as e:
            return toast(self, error_text(e))
        view = Gtk.TextView(editable=False, monospace=True, top_margin=12, bottom_margin=12,
                            left_margin=12, right_margin=12)
        view.get_buffer().set_text(text)
        dlg = Adw.Dialog(title=title, content_width=820, content_height=620)
        box = Adw.ToolbarView(content=Gtk.ScrolledWindow(child=view))
        box.add_top_bar(Adw.HeaderBar())
        dlg.set_child(box)
        dlg.present(self.get_root())

    def _run(self, key, make_script, confirmed=False):
        if self._guard():
            return
        if key == "pgp" and getattr(self, "pgp_done", False) and not confirmed:
            dlg = Adw.AlertDialog(
                heading="Create a new signing key?",
                body="A signing key already exists on your YubiKeys. Creating another one REPLACES it "
                     "on both keys: releases signed with the old key can no longer be made, and copies "
                     "of BitFedot that trust only the old key will refuse updates signed with the new one.")
            dlg.add_response("cancel", "Keep the existing key")
            dlg.add_response("new", "Replace it")
            dlg.set_response_appearance("new", Adw.ResponseAppearance.DESTRUCTIVE)
            dlg.connect("response", lambda _d, r: r == "new" and self._run(key, make_script, confirmed=True))
            return dlg.present(self.get_root())
        try:
            hk.run_in_terminal(make_script(), key)
        except (ValueError, RuntimeError, OSError) as e:
            return toast(self, error_text(e))
        toast(self, "Follow the steps in the terminal window")

    def _credit(self, field):
        hw = hk.state()
        known = [hw.get(r) for r in hk.ROLES if hw.get(r)]
        present = [s for s in hk.plugged_serials() if s in known]
        if len(present) != 1:
            return toast(self, "Plug in exactly one of your two keys")
        hk.record(**{field: sorted(set(hw[field]) | {present[0]})})
        toast(self, f"Recorded for key {present[0]}")
        self.refresh()

    def _confirm_login(self):
        if not self._guard():
            self._credit("login_ok")

    def _confirm_boot(self):
        if self._guard():
            return
        serial, message = hk.confirm_boot(hk.state(), {**hk.facts(), "plugged": hk.plugged_serials()})
        if serial:
            hw = hk.state()
            hk.record(boot_ok=sorted(set(hw["boot_ok"]) | {serial}))
            toast(self, message)
            return self.refresh()
        if "journal" not in message:
            return toast(self, message)
        dlg = Adw.AlertDialog(heading="No key unlock found in the log",
                              body="BitFedot could not see a hardware-key unlock for this boot. If you are "
                                   "certain you entered the key's PIN and touched it at the boot prompt — "
                                   "and did NOT type your password — you can confirm it yourself.")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("vouch", "I unlocked with this key")

        def answer(_d, response):
            if response == "vouch":
                serial2, msg = hk.confirm_boot(hk.state(), {**hk.facts(), "plugged": hk.plugged_serials()},
                                               user_vouches=True)
                if serial2:
                    hk.record(boot_ok=sorted(set(hk.state()["boot_ok"]) | {serial2}))
                toast(self, msg)
                self.refresh()
        dlg.connect("response", answer)
        dlg.present(self.get_root())
