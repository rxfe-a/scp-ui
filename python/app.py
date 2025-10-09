#!/usr/bin/env python3
"""
SCP GUI (system scp) with optional password support and saved settings.

- Uses system `scp` for transfers.
- If "Use password" is checked, the app will attempt to send the password automatically:
    - Preferred: uses pexpect (pip install pexpect).
    - Fallback: uses sshpass if available (less secure).
- Saves settings (NOT password) to ~/.scp_gui_config.json.

Save as scp_gui_scp_password.py and run: python scp_gui_scp_password.py
"""
import os
import json
import threading
import queue
import shlex
import shutil
import subprocess
import time
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import pexpect
except Exception:
    pexpect = None

CONFIG_PATH = Path.home() / ".scp_gui_config.json"
APP_TITLE = "SCP-UI v1.0.0 - Beta"

class SCPGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x650")
        self.minsize(720, 520)

        self.proc_thread = None
        self.output_queue = queue.Queue()
        self._build_ui()
        self._poll_output_queue()
        self._load_config()

        # runtime handles
        self._running_proc = None
        self._pexpect_child = None

    def _build_ui(self):
        pad = 6
        frm = ttk.Frame(self, padding=pad)
        frm.pack(fill="both", expand=True)

        top = ttk.LabelFrame(frm, text="Connection & Options", padding=pad)
        top.pack(fill="x", pady=(0, pad))

        row = 0
        ttk.Label(top, text="User@Host:").grid(row=row, column=0, sticky="e")
        self.userhost_entry = ttk.Entry(top)
        self.userhost_entry.grid(row=row, column=1, sticky="we", padx=(4,8))
        self.userhost_entry.insert(0, "user@example.com")

        ttk.Label(top, text="Port:").grid(row=row, column=2, sticky="e")
        self.port_entry = ttk.Entry(top, width=8)
        self.port_entry.grid(row=row, column=3, sticky="w", padx=(4,0))
        self.port_entry.insert(0, "22")

        row += 1
        ttk.Label(top, text="Identity (key):").grid(row=row, column=0, sticky="e")
        idfrm = ttk.Frame(top)
        idfrm.grid(row=row, column=1, columnspan=3, sticky="we")
        self.identity_entry = ttk.Entry(idfrm)
        self.identity_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(idfrm, text="Browse", command=self._browse_identity).pack(side="left", padx=(6,0))

        row += 1
        pwfrm = ttk.Frame(top)
        pwfrm.grid(row=row, column=0, columnspan=4, sticky="we", pady=(6,0))
        self.use_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pwfrm, text="Use password auth", variable=self.use_password_var, command=self._on_auth_change).pack(side="left", padx=(0,8))
        ttk.Label(pwfrm, text="Password:").pack(side="left")
        self.password_entry = ttk.Entry(pwfrm, show="*")
        self.password_entry.pack(side="left", padx=(6,0))
        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pwfrm, text="show", variable=self.show_pw_var, command=self._toggle_show_pw).pack(side="left", padx=(6,0))

        row += 1
        ttk.Label(top, text="Local Path (file/dir):").grid(row=row, column=0, sticky="e")
        lpfrm = ttk.Frame(top)
        lpfrm.grid(row=row, column=1, sticky="we", padx=(4,8))
        self.local_entry = ttk.Entry(lpfrm)
        self.local_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(lpfrm, text="Browse", command=self._browse_local).pack(side="left", padx=(6,0))

        ttk.Label(top, text="Remote Path:").grid(row=row, column=2, sticky="e")
        self.remote_entry = ttk.Entry(top)
        self.remote_entry.grid(row=row, column=3, sticky="we", padx=(4,0))

        row += 1
        dfrm = ttk.Frame(top)
        dfrm.grid(row=row, column=0, columnspan=4, sticky="w", pady=(8,0))
        self.direction = tk.StringVar(value="upload")
        ttk.Radiobutton(dfrm, text="Upload (local → remote)", variable=self.direction, value="upload").pack(side="left", padx=(0,8))
        ttk.Radiobutton(dfrm, text="Download (remote → local)", variable=self.direction, value="download").pack(side="left", padx=(0,8))

        self.recursive_var = tk.BooleanVar(value=True)
        self.preserve_var = tk.BooleanVar(value=True)
        self.dryrun_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(dfrm, text="Recursive (-r)", variable=self.recursive_var).pack(side="left", padx=(10,6))
        ttk.Checkbutton(dfrm, text="Preserve timestamps (-p)", variable=self.preserve_var).pack(side="left", padx=(6,6))
        ttk.Checkbutton(dfrm, text="Dry run (don't execute)", variable=self.dryrun_var).pack(side="left", padx=(6,6))

        row += 1
        sf = ttk.Frame(top)
        sf.grid(row=row, column=0, columnspan=4, sticky="we", pady=(8,0))
        ttk.Button(sf, text="Save settings", command=self._save_config).pack(side="left")
        ttk.Button(sf, text="Load settings", command=self._load_config).pack(side="left", padx=(6,0))
        ttk.Button(sf, text="Clear saved settings", command=self._clear_saved_config).pack(side="left", padx=(6,0))
        ttk.Label(sf, text=" (saved to ~/.scp_gui_config.json)").pack(side="left", padx=(8,0))

        top.columnconfigure(1, weight=1)
        top.columnconfigure(3, weight=1)
        mid = ttk.LabelFrame(frm, text="Controls", padding=pad)
        mid.pack(fill="x", pady=(0, pad))

        ctlfrm = ttk.Frame(mid)
        ctlfrm.pack(fill="x")
        self.start_btn = ttk.Button(ctlfrm, text="Start Transfer (system scp)", command=self._start_transfer)
        self.start_btn.pack(side="left")
        self.cancel_btn = ttk.Button(ctlfrm, text="Cancel", command=self._cancel_transfer, state="disabled")
        self.cancel_btn.pack(side="left", padx=(8,0))
        ttk.Button(ctlfrm, text="Clear Output", command=self._clear_output).pack(side="left", padx=(8,0))
        ttk.Label(ctlfrm, text=" ").pack(side="left", padx=8)
        ttk.Button(ctlfrm, text="Show generated command", command=self._show_command).pack(side="left")
#output section
        out = ttk.LabelFrame(frm, text="Output", padding=pad)
        out.pack(fill="both", expand=True)
        self.output_text = tk.Text(out, wrap="none", height=20)
        self.output_text.pack(side="left", fill="both", expand=True)
        scr_y = ttk.Scrollbar(out, orient="vertical", command=self.output_text.yview)
        scr_y.pack(side="right", fill="y")
        self.output_text.config(yscrollcommand=scr_y.set)
        scr_x = ttk.Scrollbar(out, orient="horizontal", command=self.output_text.xview)
        scr_x.pack(side="bottom", fill="x")
        self.output_text.config(xscrollcommand=scr_x.set)
        self.output_text.bind("<Double-1>", lambda e: self._copy_output_selection())
        
        self._on_auth_change()
        self._toggle_show_pw()

    def _toggle_show_pw(self):
        if self.show_pw_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def _on_auth_change(self):
        if self.use_password_var.get():
            # pass
            pass

    def _browse_identity(self):
        p = filedialog.askopenfilename(title="Select identity (private key) file")
        if p:
            self.identity_entry.delete(0, tk.END)
            self.identity_entry.insert(0, p)

    def _browse_local(self):
        if self.direction.get() == "upload":
            paths = filedialog.askopenfilenames(title="Select file(s) to upload (Cancel to choose directory)")
            if paths:
                self.local_entry.delete(0, tk.END)
                # use '|' as internal multi-file separator
                self.local_entry.insert(0, "|".join(paths))
            else:
                d = filedialog.askdirectory(title="Select directory to upload")
                if d:
                    self.local_entry.delete(0, tk.END)
                    self.local_entry.insert(0, d)
        else:
            d = filedialog.askdirectory(title="Select destination directory (download)")
            if d:
                self.local_entry.delete(0, tk.END)
                self.local_entry.insert(0, d)

    def _copy_output_selection(self):
        try:
            sel = self.output_text.get("sel.first", "sel.last")
            self.clipboard_clear()
            self.clipboard_append(sel)
            messagebox.showinfo("Copied", "Selected text copied to clipboard.")
        except tk.TclError:
            pass
#conf
    def _load_config(self):
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                self.userhost_entry.delete(0, tk.END)
                self.userhost_entry.insert(0, cfg.get("userhost", ""))
                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, str(cfg.get("port", "22")))
                self.identity_entry.delete(0, tk.END)
                self.identity_entry.insert(0, cfg.get("identity", ""))
                self.local_entry.delete(0, tk.END)
                self.local_entry.insert(0, cfg.get("last_local", ""))
                self.remote_entry.delete(0, tk.END)
                self.remote_entry.insert(0, cfg.get("last_remote", ""))
                self.recursive_var.set(cfg.get("recursive", True))
                self.preserve_var.set(cfg.get("preserve", True))
                self.use_password_var.set(cfg.get("use_password", False))
                # Do NOT load password
                self.password_entry.delete(0, tk.END)
                self._append_output("Loaded settings from ~/.scp_gui_config.json\n")
                self._on_auth_change()
                return
            except Exception as e:
                self._append_output(f"Failed to load config: {e}\n")
                traceback.print_exc()
        else:
            self._append_output("No saved settings found (~/.scp_gui_config.json)\n")

    def _save_config(self):
        try:
            cfg = {
                "userhost": self.userhost_entry.get().strip(),
                "port": int(self.port_entry.get().strip() or 22),
                "identity": self.identity_entry.get().strip(),
                "last_local": self.local_entry.get().strip(),
                "last_remote": self.remote_entry.get().strip(),
                "recursive": bool(self.recursive_var.get()),
                "preserve": bool(self.preserve_var.get()),
                "use_password": bool(self.use_password_var.get())
            }
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            self._append_output(f"Saved settings to {CONFIG_PATH}\n")
            messagebox.showinfo("Saved", f"Settings saved to {CONFIG_PATH}")
        except Exception as e:
            self._append_output(f"Failed to save config: {e}\n")
            messagebox.showerror("Save failed", str(e))

    def _clear_saved_config(self):
        try:
            if CONFIG_PATH.exists():
                CONFIG_PATH.unlink()
                self._append_output("Cleared saved settings.\n")
                messagebox.showinfo("Cleared", "Saved settings cleared (~/.scp_gui_config.json removed).")
            else:
                messagebox.showinfo("No saved settings", "No saved settings file to remove.")
        except Exception as e:
            messagebox.showerror("Failed", str(e))
#scp gen fun 
    def _parse_userhost(self):
        txt = self.userhost_entry.get().strip()
        if "@" in txt:
            user, host = txt.split("@", 1)
        else:
            user = ""
            host = txt
        return user, host

    def _build_scp_parts(self):
        user, host = self._parse_userhost()
        if not host:
            return None
        port = self.port_entry.get().strip()
        identity = self.identity_entry.get().strip()
        local = self.local_entry.get().strip()
        remote = self.remote_entry.get().strip()
        if not local or not remote:
            return None

        parts = ["scp"]
        if self.recursive_var.get():
            parts.append("-r")
        if self.preserve_var.get():
            parts.append("-p")
        if port:
            parts += ["-P", port]
        if identity and not self.use_password_var.get():
            parts += ["-i", os.path.expanduser(identity)]

        if self.direction.get() == "upload":
            locals_list = local.split("|")
            locals_list = [os.path.expanduser(p) for p in locals_list]
            remote_spec = f"{user+'@' if user else ''}{host}:{remote}"
            parts += locals_list + [remote_spec]
        else:
            remote_spec = f"{user+'@' if user else ''}{host}:{remote}"
            parts += [remote_spec, os.path.expanduser(local)]

        return parts

    def _show_command(self):
        parts = self._build_scp_parts()
        if not parts:
            messagebox.showinfo("Incomplete", "Fill host/local/remote fields to show command.")
            return
        cmd = " ".join(shlex.quote(p) for p in parts)
        messagebox.showinfo("scp command", cmd)

    def _start_transfer(self):
        # dry run????
        if self.dryrun_var.get():
            parts = self._build_scp_parts()
            if not parts:
                messagebox.showinfo("Incomplete", "Fill host/local/remote fields first.")
                return
            self._append_output("Dry run: " + " ".join(shlex.quote(p) for p in parts) + "\n")
            messagebox.showinfo("Dry run", "Dry run: command shown in output.")
            return

        parts = self._build_scp_parts()
        if not parts:
            messagebox.showerror("Incomplete", "Make sure host, local and remote fields are filled.")
            return

        # ensure scp exists
        if not shutil.which("scp"):
            messagebox.showerror("scp not found", "`scp` not found on PATH. Install OpenSSH scp.")
            return

        # save settings
        try:
            self._save_config()
        except Exception:
            pass

        self.start_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self._append_output("Starting transfer...\n")

        use_password = bool(self.use_password_var.get())
        password = self.password_entry.get() if use_password else None
        self.proc_thread = threading.Thread(target=self._run_scp_thread, args=(parts, use_password, password), daemon=True)
        self.proc_thread.start()

    def _run_scp_thread(self, parts, use_password, password):
        try:
            if use_password:
                if pexpect is not None:
                    self._append_output("Using pexpect to automate password prompt.\n")
                    self._run_with_pexpect(parts, password)
                    return
                elif shutil.which("sshpass"):
                    # fallback to sshpass
                    self._append_output("pexpect not installed — falling back to sshpass (insecure). Recommend `pip install pexpect`.\n")
                    cmd = ["sshpass", "-p", password] + parts
                    self._run_with_subprocess(cmd)
                    return
                else:
                    self.output_queue.put(("line", "Password automation requested but neither pexpect (python) nor sshpass (system) are available.\n"))
                    self.output_queue.put(("line", "Install pexpect (`pip install pexpect`) or sshpass (system package) and try again.\n"))
                    self.output_queue.put(("done", None))
                    return
            else:
                self._run_with_subprocess(parts)
        except Exception as e:
            self.output_queue.put(("line", f"Error running scp: {e}\n"))
            tb = traceback.format_exc()
            self.output_queue.put(("line", tb))
        finally:
            self.output_queue.put(("done", None))

    def _run_with_subprocess(self, cmd_parts):
        """Run a command via subprocess and stream stdout/stderr."""
        try:
            # use Popen so we can kill later
            self._append_output("Running: " + " ".join(shlex.quote(p) for p in cmd_parts) + "\n")
            proc = subprocess.Popen(cmd_parts, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, bufsize=1)
            self._running_proc = proc
            # stream lines
            for line in proc.stdout:
                self.output_queue.put(("line", line))
            proc.wait()
            self.output_queue.put(("line", f"\nProcess exited with code {proc.returncode}\n"))
        except Exception as e:
            self.output_queue.put(("line", f"Subprocess error: {e}\n"))
        finally:
            self._running_proc = None

    def _run_with_pexpect(self, parts, password):
        try:
            cmd_str = " ".join(shlex.quote(p) for p in parts)
            child = pexpect.spawn(cmd_str, encoding='utf-8', timeout=None)
            self._pexpect_child = child
            password_sent = False
            self._append_output("Spawned: " + cmd_str + "\n")
            while True:
                try:
                    # try to read any available chunk (non-blocking-ish)
                    chunk = child.read_nonblocking(size=1024, timeout=0.5)
                    if chunk:
                        # check for password prompt in chunk
                        if (not password_sent) and ("assword:" in chunk):
                            child.sendline(password)
                            password_sent = True
                            self.output_queue.put(("line", "[Sent password]\n"))
                        self.output_queue.put(("line", chunk))
                except pexpect.TIMEOUT:
                    # TIMEOUT is ok; check if lil kid is alive
                    if not child.isalive():
                        # leftovers??? no ok
                        try:
                            rem = child.read_nonblocking(size=1024, timeout=0.1)
                            if rem:
                                self.output_queue.put(("line", rem))
                        except Exception:
                            pass
                        break
                    else:
                        # still alive; continue loop
                        continue
                except pexpect.EOF:
                    # EOF: grab any remaining text
                    try:
                        rem = child.before or ""
                        if rem:
                            self.output_queue.put(("line", rem))
                    except Exception:
                        pass
                    break
                except Exception as e:
                    self.output_queue.put(("line", f"Pexpect read error: {e}\n"))
                    break
            # ensure he dead or atleast exited
            try:
                rc = child.exitstatus if hasattr(child, "exitstatus") else None
            except Exception:
                rc = None
            self.output_queue.put(("line", f"\npexpect process finished (exitstatus={rc})\n"))
        except Exception as e:
            self.output_queue.put(("line", f"Pexpect spawn error: {e}\n"))
            tb = traceback.format_exc()
            self.output_queue.put(("line", tb))
        finally:
            try:
                if self._pexpect_child:
                    try:
                        self._pexpect_child.close(force=True)
                    except Exception:
                        pass
            except Exception:
                pass
            self._pexpect_child = None

    def _cancel_transfer(self):
        self._append_output("Cancelling transfer...\n")
        try:
            if self._running_proc:
                try:
                    self._running_proc.kill()
                    self._append_output("Killed subprocess.\n")
                except Exception as e:
                    self._append_output(f"Failed to kill subprocess: {e}\n")
                self._running_proc = None
            if self._pexpect_child:
                try:
                    self._pexpect_child.close(force=True)
                    self._append_output("Closed pexpect child.\n")
                except Exception as e:
                    self._append_output(f"Failed to close pexpect child: {e}\n")
                self._pexpect_child = None
        except Exception as e:
            self._append_output(f"Error while cancelling: {e}\n")
        finally:
            self.cancel_btn.config(state="disabled")
            self.start_btn.config(state="normal")
            self.output_queue.put(("done", None))

    # output-shitter
    def _append_output(self, text):
        self.output_text.insert("end", text)
        self.output_text.see("end")

    def _poll_output_queue(self):
        try:
            while True:
                typ, data = self.output_queue.get_nowait()
                if typ == "line":
                    self._append_output(data)
                elif typ == "done":
                    self.cancel_btn.config(state="disabled")
                    self.start_btn.config(state="normal")
                self.output_queue.task_done()
        except queue.Empty:
            pass
        self.after(150, self._poll_output_queue)

    def _clear_output(self):
        self.output_text.delete("1.0", "end")

def main():
    app = SCPGui()
    app.mainloop()

if __name__ == "__main__":
    main()
