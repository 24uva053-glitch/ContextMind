"""ContextMind - workflow context recovery tracker (Windows desktop app).

Sections:
  1. Config and Windows API helpers
  2. Database (SQLite, password hashing)
  3. Text helpers (break type, TF-IDF keywords, cosine similarity)
  4. Tracker thread (usage, idle, breaks, last-active snapshot)
  5. Lock screen (password, lockout countdown, last activity)
  6. Main window (dashboard, checkpoints, history, files, settings)
  7. Startup (single instance, logging, crash report)
Data folder: %APPDATA%\\ContextMind
"""
import os, sys, re, csv, json, math, time, sqlite3, hashlib, logging, secrets, threading, traceback, ctypes
from ctypes import wintypes as wt
from collections import Counter, deque
from datetime import datetime, date
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    from PIL import Image, ImageGrab, ImageFilter, ImageTk   # optional: blurred lock background
except ImportError:
    Image = None

# ---------------------------------------------------------------- 1. Config and Windows API
IS_WIN = sys.platform.startswith("win")
APP = "ContextMind"
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP)
DB_PATH = os.path.join(DATA_DIR, "contextmind.db")
LOG_PATH = os.path.join(DATA_DIR, "contextmind.log")
BG, ACCENT, DARK, LIGHT, PINK = "#f3eefc", "#6c3fc5", "#2e1a5c", "#e4d9f7", "#ff9aa2"
IDLE = "idle"                       # idle time is stored in its own bucket
OWN_APPS = {"contextmind.exe", "python.exe", "pythonw.exe", "py.exe"}
SYSTEM_APPS = ("helpandtips.exe", "werfault.exe", "rundll32.exe", "unknown", "taskmgr.exe",
               "systemsettings.exe", "py.exe", "python.exe", "pythonw.exe", "contextmind.exe", IDLE)
SYS_CLAUSE = "LOWER(app) NOT IN (%s)" % ",".join("?" * len(SYSTEM_APPS))
MAX_FAILS, LOCK_SECS = 5, 60
PRIVACY_NOTE = "\nThis file contains window titles. Keep it private."

if IS_WIN:
    user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
    user32.GetForegroundWindow.restype = wt.HWND
    user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.GetTickCount.restype = wt.DWORD

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", wt.UINT), ("dwTime", wt.DWORD)]

    def foreground():
        """(process_exe, window_title, pid) of the active window, or None."""
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        title_buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title_buf, 512)
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        exe = "unknown"
        handle = kernel32.OpenProcess(0x1000, False, pid.value)   # QUERY_LIMITED_INFORMATION
        if handle:
            name, size = ctypes.create_unicode_buffer(1024), wt.DWORD(1024)
            if kernel32.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)):
                exe = os.path.basename(name.value)
            kernel32.CloseHandle(handle)
        return exe, title_buf.value, pid.value

    def idle_seconds():
        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if user32.GetLastInputInfo(ctypes.byref(info)):
            return ((kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF) / 1000.0
        return 0.0

    def lock_windows():
        user32.LockWorkStation()
else:  # lets the file be tested on other systems
    def foreground():
        return "demo.exe", "Demo window", 0

    def idle_seconds():
        return 0.0

    def lock_windows():
        pass


def fmt_secs(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return "%dh %02dm" % (h, m)
    if m:
        return "%dm %02ds" % (m, s)
    return "%ds" % s


def ago(iso):
    try:
        secs = int((datetime.now() - datetime.fromisoformat(iso)).total_seconds())
    except ValueError:
        return ""
    if secs < 90:
        return "just now"
    if secs < 3600:
        return "%d min ago" % (secs // 60)
    if secs < 86400:
        return "%dh %02dm ago" % (secs // 3600, secs % 3600 // 60)
    return "%d days ago" % (secs // 86400)


def clear_tree(tree):
    tree.delete(*tree.get_children())


# ---------------------------------------------------------------- 2. Database
class DB:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.lock = threading.Lock()
        self.con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
        self.con.execute("PRAGMA journal_mode=WAL")          # readers do not block the tracker
        self.con.execute("PRAGMA busy_timeout=15000")
        self.con.executescript("""
            CREATE TABLE IF NOT EXISTS usage(day TEXT, app TEXT, seconds REAL, PRIMARY KEY(day, app));
            CREATE TABLE IF NOT EXISTS titles(day TEXT, app TEXT, title TEXT, seconds REAL,
                                              PRIMARY KEY(day, app, title));
            CREATE TABLE IF NOT EXISTS checkpoints(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
                project TEXT, note TEXT, next_step TEXT, context TEXT);
            CREATE TABLE IF NOT EXISTS breaks(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
                idle_secs REAL, kind TEXT);
            CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
        """)

    def query(self, sql, args=()):
        with self.lock:
            return self.con.execute(sql, args).fetchall()

    def run(self, sql, args=()):
        with self.lock:
            self.con.execute(sql, args)
            self.con.commit()

    def get(self, key, default=""):
        rows = self.query("SELECT v FROM settings WHERE k=?", (key,))
        return rows[0][0] if rows else default

    def set(self, key, value):
        self.run("INSERT OR REPLACE INTO settings(k, v) VALUES(?, ?)", (key, str(value)))

    def add_usage(self, day, app, secs):
        self.run("""INSERT INTO usage VALUES(?, ?, ?) ON CONFLICT(day, app)
                    DO UPDATE SET seconds = seconds + excluded.seconds""", (day, app, secs))

    def add_title(self, day, app, title, secs):
        self.run("""INSERT INTO titles VALUES(?, ?, ?, ?) ON CONFLICT(day, app, title)
                    DO UPDATE SET seconds = seconds + excluded.seconds""", (day, app, title, secs))

    def backup(self, path):
        with self.lock:
            out = sqlite3.connect(path)
            self.con.backup(out)
            out.close()

    @staticmethod
    def _hash(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()

    def has_password(self):
        return bool(self.get("pw_hash"))

    def set_password(self, password):
        if not password:
            self.run("DELETE FROM settings WHERE k IN ('pw_hash', 'pw_salt')")
            return
        salt = secrets.token_hex(16)
        self.set("pw_salt", salt)
        self.set("pw_hash", self._hash(password, salt))

    def check_password(self, password):
        return secrets.compare_digest(self._hash(password, self.get("pw_salt")), self.get("pw_hash"))


# ---------------------------------------------------------------- 3. Text helpers
STOP = {"the", "and", "for", "with", "new", "open", "file", "untitled", "google", "chrome",
        "window", "tab", "page", "http", "https", "www", "com"}


def tokenize(text):
    return [w for w in re.findall(r"[a-z][a-z0-9_+#]{2,}", (text or "").lower()) if w not in STOP]


def break_type(idle_secs):
    """Idle time-ah label pannum: short interruption / real break / end of session."""
    if idle_secs < 5 * 60:
        return "short interruption"
    if idle_secs <= 30 * 60:
        return "real break"
    return "end of session"


def keywords(titles, k=5):
    """Top TF-IDF words across window titles."""
    docs = [Counter(tokenize(t)) for t in titles if t]
    n, df, score = len(docs), Counter(), Counter()
    for doc in docs:
        df.update(doc.keys())
    for doc in docs:
        total = sum(doc.values()) or 1
        for word, count in doc.items():
            score[word] += (count / total) * (math.log((1 + n) / (1 + df[word])) + 1)
    return [w for w, _ in score.most_common(k)]


def similarity(titles_a, titles_b):
    """Cosine similarity (0-100%) between two sets of window titles."""
    a = Counter(w for t in titles_a for w in tokenize(t))
    b = Counter(w for t in titles_b for w in tokenize(t))
    dot = sum(a[w] * b[w] for w in a)
    norm = math.sqrt(sum(v * v for v in a.values())) * math.sqrt(sum(v * v for v in b.values()))
    return round(100 * dot / norm) if norm else 0


# ---------------------------------------------------------------- 4. Tracker thread
class Tracker(threading.Thread):
    STEP = 2.0  # seconds between samples

    def __init__(self, db):
        super().__init__(daemon=True)
        self.db = db
        self.paused = db.get("paused") == "1"
        self.idle_limit = int(db.get("idle_minutes", "3")) * 60
        self.track_titles = db.get("track_titles", "1") == "1"
        self.stop_flag = threading.Event()
        self.current = ("-", "-")
        self.is_idle = False
        self.recent = deque(maxlen=60)          # recent (app, title) pairs
        self.last_active = None
        self.was_idle, self.idle_started = False, 0.0
        self.unsaved = 0.0

    def stop(self):
        self.stop_flag.set()

    def run(self):
        last = time.time()
        while not self.stop_flag.is_set():
            time.sleep(self.STEP)
            now = time.time()
            dt, last = min(now - last, self.STEP * 2.5), now  # cap dt after sleep/hibernate
            if self.paused:
                continue
            try:
                self.step(dt, now)
            except Exception:
                logging.exception("tracker step")

    def step(self, dt, now):
        day = date.today().isoformat()
        idle = idle_seconds()
        self.is_idle = idle > self.idle_limit
        if self.is_idle:
            self.was_idle, self.idle_started = True, idle
            self.db.add_usage(day, IDLE, dt)
            return
        if self.was_idle:                        # user came back: store the break
            self.was_idle = False
            self.db.run("INSERT INTO breaks(ts, idle_secs, kind) VALUES(?, ?, ?)",
                        (datetime.now().isoformat(timespec="seconds"), self.idle_started,
                         break_type(self.idle_started)))
        fg = foreground()
        if not fg or fg[2] == os.getpid() or fg[0].lower() in OWN_APPS:
            return
        app, title, _ = fg
        self.current, self.last_active = (app, title), now
        if not self.recent or self.recent[-1] != (app, title):
            self.recent.append((app, title))
        self.db.add_usage(day, app, dt)
        if self.track_titles and title.strip():
            self.db.add_title(day, app, title.strip()[:150], dt)
        self.unsaved += dt
        if self.unsaved >= 10:
            self.unsaved = 0.0
            self.save_snapshot()

    def context(self, n=6):
        """Most recent distinct apps, newest first. Saved with checkpoints."""
        seen, out = set(), []
        for app, title in reversed(self.recent):
            if app not in seen:
                seen.add(app)
                out.append({"app": app, "title": title})
            if len(out) == n:
                break
        return out

    def snapshot(self):
        if self.last_active is None:
            return None
        return {"ts": datetime.fromtimestamp(self.last_active).isoformat(timespec="seconds"),
                "apps": self.context(5)}

    def save_snapshot(self):
        snap = self.snapshot()
        if snap:
            self.db.set("last_active", json.dumps(snap))


# ---------------------------------------------------------------- 5. Lock screen
class LockScreen(tk.Toplevel):
    REASONS = {"startup": "Welcome back - ContextMind is locked",
               "idle": "No activity detected - screen locked",
               "manual": "Locked"}

    def __init__(self, app, reason, snapshot):
        super().__init__(app)
        self.withdraw()
        self.app, self.db, self.reason, self.snapshot = app, app.db, reason, snapshot
        self.timer_id = None
        self.entry = self.msg = self.button = None
        self.configure(bg=DARK)
        self.protocol("WM_DELETE_WINDOW", lambda: None)   # ignore Alt+F4
        self.background = self.make_background()
        self.canvas = tk.Canvas(self, highlightthickness=0, bg=DARK)
        self.canvas.pack(fill="both", expand=True)
        if self.background:
            self.canvas.create_image(0, 0, anchor="nw", image=self.background)
        self.card = tk.Frame(self.canvas, bg=DARK, padx=36, pady=28,
                             highlightthickness=2, highlightbackground=ACCENT)
        self.canvas.create_window(self.winfo_screenwidth() // 2, self.winfo_screenheight() // 2,
                                  window=self.card)
        self.show_login()
        self.attributes("-fullscreen", True)
        self.attributes("-topmost", True)
        self.deiconify()
        self.after(250, self.grab_focus)

    def make_background(self):
        if Image is None:
            return None
        try:
            w, h = self.winfo_screenwidth(), self.winfo_screenheight()
            shot = ImageGrab.grab().convert("RGB").resize((w // 8, h // 8)).filter(ImageFilter.GaussianBlur(2.5))
            tinted = Image.blend(shot.resize((w, h)), Image.new("RGB", (w, h), (46, 26, 92)), 0.5)
            return ImageTk.PhotoImage(tinted, master=self)
        except Exception:
            logging.exception("lock background")
            return None

    def grab_focus(self):
        try:
            self.focus_force()
            if self.entry is not None:
                self.entry.focus_force()
            self.grab_set()
        except tk.TclError:
            pass

    def clear(self):
        self.cancel_timer()
        for widget in self.card.winfo_children():
            widget.destroy()

    def cancel_timer(self):
        if self.timer_id:
            self.after_cancel(self.timer_id)
            self.timer_id = None

    def show_login(self):
        self.clear()
        c = self.card
        tk.Label(c, text=APP, bg=DARK, fg="white", font=("Segoe UI", 24, "bold")).pack()
        tk.Label(c, text=self.REASONS[self.reason], bg=DARK, fg=LIGHT,
                 font=("Segoe UI", 11)).pack(pady=(2, 14))
        tk.Label(c, text="Enter password to see your last activity", bg=DARK, fg="white",
                 font=("Segoe UI", 11)).pack(pady=(0, 6))
        self.entry = tk.Entry(c, show="*", width=26, font=("Segoe UI", 14), justify="center")
        self.entry.pack(pady=4)
        self.entry.bind("<Return>", lambda e: self.try_unlock())
        self.msg = tk.Label(c, text="", bg=DARK, fg=PINK, font=("Segoe UI", 10))
        self.msg.pack(pady=2)
        self.button = tk.Button(c, text="Unlock", width=14, bg=ACCENT, fg="white", relief="flat",
                                font=("Segoe UI", 11, "bold"), command=self.try_unlock)
        self.button.pack(pady=(8, 0))
        self.entry.focus_set()
        self.update_countdown()

    def update_countdown(self):
        """Lockout-la every second refresh. Mudinjadhum field thirumba enable aagum."""
        self.timer_id = None
        left = self.app.seconds_left()
        if left > 0:
            self.entry.delete(0, "end")
            self.entry.config(state="disabled")
            self.button.config(state="disabled")
            self.msg.config(text="Too many wrong attempts. Try again in %ds" % left)
            self.timer_id = self.after(1000, self.update_countdown)
        elif str(self.entry.cget("state")) == "disabled":
            self.entry.config(state="normal")
            self.button.config(state="normal")
            self.msg.config(text="You can try again now")
            self.entry.focus_set()

    def try_unlock(self):
        if self.app.seconds_left() > 0:
            return self.update_countdown()
        if self.db.check_password(self.entry.get()):
            self.app.fails = 0
            return self.show_details()
        self.app.fails += 1
        self.entry.delete(0, "end")
        if self.app.fails >= MAX_FAILS:
            self.app.fails = 0
            self.app.locked_until = time.time() + LOCK_SECS
            self.update_countdown()
        else:
            self.msg.config(text="Wrong password (%d/%d)" % (self.app.fails, MAX_FAILS))

    def show_details(self):
        self.clear()
        c, db, today = self.card, self.db, date.today().isoformat()
        tk.Label(c, text="Your last activity", bg=DARK, fg="white",
                 font=("Segoe UI", 20, "bold")).pack(pady=(0, 10))
        lines = []
        if self.snapshot and self.snapshot.get("apps"):
            lines += ["Last active: %s  (%s)" % (self.snapshot["ts"].replace("T", " "), ago(self.snapshot["ts"])),
                      "", "You were using:"]
            lines += ["   %s  -  %s" % (a["app"], a["title"][:70]) for a in self.snapshot["apps"]]
        else:
            lines.append("No earlier activity recorded yet.")
        cp = db.query("SELECT ts, project, note, next_step FROM checkpoints ORDER BY id DESC LIMIT 1")
        if cp:
            ts, project, note, nxt = cp[0]
            lines += ["", "Last checkpoint (%s)" % ts,
                      "   Project   : %s" % (project or "-"),
                      "   Note      : %s" % (note or "-").replace("\n", " ")[:120],
                      "   Next step : %s" % (nxt or "-").replace("\n", " ")[:120]]
        files = db.query("SELECT app, title, seconds FROM titles WHERE day=? AND " + SYS_CLAUSE +
                         " ORDER BY seconds DESC LIMIT 5", (today,) + SYSTEM_APPS)
        if files:
            lines += ["", "Files / windows used today"]
            lines += ["   %s  -  %s  (%s)" % (a, t[:55], fmt_secs(s)) for a, t, s in files]
        total = db.query("SELECT SUM(seconds) FROM usage WHERE day=? AND " + SYS_CLAUSE,
                         (today,) + SYSTEM_APPS)[0][0]
        idle = db.query("SELECT seconds FROM usage WHERE day=? AND app=?", (today, IDLE))
        lines += ["", "Tracked today: %s" % fmt_secs(total or 0),
                  "Idle today: %s" % fmt_secs(idle[0][0] if idle else 0)]
        tk.Label(c, text="\n".join(lines), bg=DARK, fg="white", justify="left", anchor="w",
                 font=("Consolas", 11), wraplength=620).pack(anchor="w")
        tk.Button(c, text="Continue to ContextMind", width=22, bg=ACCENT, fg="white", relief="flat",
                  font=("Segoe UI", 11, "bold"), command=self.close).pack(pady=(16, 0))

    def close(self):
        self.cancel_timer()
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
        self.app.lock_closed(self.reason)


# ---------------------------------------------------------------- 6. Main window
class App(tk.Tk):
    def __init__(self, start_minimized=False):
        super().__init__()
        self.title(APP)
        self.geometry("920x680")
        self.minsize(820, 600)
        self.configure(bg=BG)
        self.start_minimized = start_minimized
        self.db = DB()
        self.prev_snapshot = self.load_json(self.db.get("last_active"))  # activity from last session
        self.tracker = Tracker(self.db)
        self.tracker.start()
        self.lock_win = None
        self.was_normal = True
        self.fails, self.locked_until = 0, 0.0
        self.tick_count = 0
        self.style()
        self.build()
        self.protocol("WM_DELETE_WINDOW", self.iconify)   # X = minimize, tracking continues
        self.refresh_dashboard()
        if self.db.has_password():
            self.withdraw()
            self.after(150, lambda: self.show_lock("startup"))
        elif start_minimized:
            self.iconify()
        else:
            self.after(900, self.first_run_prompt)
        self.after(2000, self.tick)

    @staticmethod
    def load_json(text):
        try:
            return json.loads(text) if text else None
        except ValueError:
            return None

    def style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", padding=(16, 7), font=("Segoe UI", 10, "bold"),
                    background=LIGHT, foreground=DARK)
        s.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=DARK, font=("Segoe UI", 10))
        s.configure("H.TLabel", font=("Segoe UI", 12, "bold"))
        s.configure("TButton", font=("Segoe UI", 10), padding=6)
        s.configure("Accent.TButton", background=ACCENT, foreground="white")
        s.map("Accent.TButton", background=[("active", DARK)])
        s.configure("TCheckbutton", background=BG, foreground=DARK)
        s.configure("Treeview", rowheight=26, font=("Segoe UI", 10))
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background=ACCENT, foreground="white")

    def build(self):
        top = tk.Frame(self, bg=ACCENT)
        top.pack(fill="x")
        tk.Label(top, text="  " + APP, bg=ACCENT, fg="white", font=("Segoe UI", 16, "bold")).pack(side="left", pady=10)
        self.status = tk.Label(top, bg=ACCENT, fg="white", font=("Segoe UI", 10))
        self.status.pack(side="right", padx=14)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabs = {}
        for name in ("Dashboard", "Checkpoints", "Usage History", "Files Used", "Settings"):
            self.tabs[name] = ttk.Frame(self.notebook)
            self.notebook.add(self.tabs[name], text=name)
        self.build_dashboard(self.tabs["Dashboard"])
        self.build_checkpoints(self.tabs["Checkpoints"])
        self.build_history(self.tabs["Usage History"])
        self.build_files(self.tabs["Files Used"])
        self.build_settings(self.tabs["Settings"])
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def on_tab_change(self, _=None):
        current = self.notebook.select()
        if current == str(self.tabs["Dashboard"]):
            self.refresh_dashboard()
        elif current == str(self.tabs["Checkpoints"]):
            self.load_checkpoints()
        elif current == str(self.tabs["Usage History"]):
            self.load_history()
        elif current == str(self.tabs["Files Used"]):
            self.load_files()

    # ---- dashboard
    def build_dashboard(self, f):
        cards = ttk.Frame(f)
        cards.pack(fill="x", padx=10, pady=10)
        self.stat = {}
        for key in ("Tracked today", "Idle today", "Apps used today", "Last active app"):
            box = tk.Frame(cards, bg="white", highlightthickness=1, highlightbackground=LIGHT)
            box.pack(side="left", expand=True, fill="both", padx=6)
            tk.Label(box, text=key, bg="white", fg=DARK, font=("Segoe UI", 10)).pack(pady=(10, 0))
            self.stat[key] = tk.Label(box, text="-", bg="white", fg=ACCENT,
                                      font=("Segoe UI", 18, "bold"), wraplength=240)
            self.stat[key].pack(pady=(2, 10))
        ttk.Label(f, text="Top apps today", style="H.TLabel").pack(anchor="w", padx=12)
        self.bars = tk.Canvas(f, bg="white", height=230, highlightthickness=1, highlightbackground=LIGHT)
        self.bars.pack(fill="x", padx=12, pady=6)
        ttk.Label(f, text="Recent checkpoints", style="H.TLabel").pack(anchor="w", padx=12)
        self.dash_cp = ttk.Treeview(f, columns=("time", "project", "note"), show="headings", height=4)
        for col, w in (("time", 140), ("project", 160), ("note", 500)):
            self.dash_cp.heading(col, text=col.title())
            self.dash_cp.column(col, width=w, anchor="w")
        self.dash_cp.pack(fill="x", padx=12, pady=6)

    def refresh_dashboard(self):
        day = date.today().isoformat()
        rows = self.db.query("SELECT app, seconds FROM usage WHERE day=? AND " + SYS_CLAUSE +
                             " ORDER BY seconds DESC", (day,) + SYSTEM_APPS)
        idle = self.db.query("SELECT seconds FROM usage WHERE day=? AND app=?", (day, IDLE))
        t = self.tracker
        self.stat["Tracked today"].config(text=fmt_secs(sum(r[1] for r in rows)))
        self.stat["Idle today"].config(text=fmt_secs(idle[0][0] if idle else 0))
        self.stat["Apps used today"].config(text=str(len(rows)))
        self.stat["Last active app"].config(
            text="Paused" if t.paused else ("Idle" if t.is_idle else t.current[0]))
        self.status.config(text="Tracking: " + ("PAUSED" if t.paused else "ON"))
        self.pause_btn.config(text="Start tracking" if t.paused else "Pause tracking")

        self.bars.delete("all")
        if not rows:
            self.bars.create_text(20, 20, anchor="nw", fill=DARK, text="No data yet - use some apps.")
        else:
            top = rows[0][1] or 1
            for i, (app, secs) in enumerate(rows[:8]):
                y = 10 + i * 27
                width = max(4, int(secs / top * 430))
                self.bars.create_text(10, y + 11, anchor="w", text=app, fill=DARK, font=("Segoe UI", 9))
                self.bars.create_rectangle(170, y, 170 + width, y + 22, fill=ACCENT, outline="")
                self.bars.create_text(178 + width, y + 11, anchor="w", text=fmt_secs(secs),
                                      fill=DARK, font=("Segoe UI", 9))
        clear_tree(self.dash_cp)
        cps = self.db.query("SELECT ts, project, note FROM checkpoints ORDER BY id DESC LIMIT 4")
        if not cps:
            self.dash_cp.insert("", "end", values=("", "", "No checkpoints yet. Use the Checkpoints tab."))
        for ts, project, note in cps:
            self.dash_cp.insert("", "end", values=(ts, project, (note or "").replace("\n", " ")[:90]))

    # ---- checkpoints
    def build_checkpoints(self, f):
        form = ttk.Frame(f)
        form.pack(fill="x", padx=12, pady=10)
        ttk.Label(form, text="Project / Work name").pack(anchor="w")
        self.cp_project = ttk.Entry(form, width=60)
        self.cp_project.pack(fill="x", pady=(0, 6))
        ttk.Label(form, text="Note (what you were doing)").pack(anchor="w")
        self.cp_note = tk.Text(form, height=3, font=("Segoe UI", 10))
        self.cp_note.pack(fill="x", pady=(0, 6))
        ttk.Label(form, text="Next step (to resume later)").pack(anchor="w")
        self.cp_next = tk.Text(form, height=2, font=("Segoe UI", 10))
        self.cp_next.pack(fill="x", pady=(0, 6))
        ttk.Button(form, text="Save checkpoint", style="Accent.TButton", command=self.save_checkpoint).pack(anchor="w")

        bar = ttk.Frame(f)
        bar.pack(fill="x", padx=12)
        ttk.Label(bar, text="Search:").pack(side="left")
        self.cp_search = tk.StringVar()
        self.cp_search.trace_add("write", lambda *a: self.load_checkpoints())
        ttk.Entry(bar, textvariable=self.cp_search, width=35).pack(side="left", padx=6)
        ttk.Button(bar, text="Open / Resume", command=self.open_checkpoint).pack(side="right")
        ttk.Button(bar, text="Delete", command=self.delete_checkpoint).pack(side="right", padx=6)

        self.cp_tree = ttk.Treeview(f, columns=("id", "time", "project", "note"), show="headings", height=9)
        for col, w in (("id", 40), ("time", 140), ("project", 160), ("note", 480)):
            self.cp_tree.heading(col, text=col.title())
            self.cp_tree.column(col, width=w, anchor="w")
        self.cp_tree.pack(fill="both", expand=True, padx=12, pady=8)
        self.cp_tree.bind("<Double-1>", lambda e: self.open_checkpoint())
        self.load_checkpoints()

    def save_checkpoint(self):
        project = self.cp_project.get().strip()
        note = self.cp_note.get("1.0", "end").strip()
        nxt = self.cp_next.get("1.0", "end").strip()
        if not project and not note:
            return messagebox.showwarning(APP, "Please enter a project name or a note.")
        self.db.run("INSERT INTO checkpoints(ts, project, note, next_step, context) VALUES(?, ?, ?, ?, ?)",
                    (datetime.now().strftime("%Y-%m-%d %H:%M"), project, note, nxt,
                     json.dumps(self.tracker.context())))
        self.cp_project.delete(0, "end")
        self.cp_note.delete("1.0", "end")
        self.cp_next.delete("1.0", "end")
        self.load_checkpoints()
        self.refresh_dashboard()
        messagebox.showinfo(APP, "Checkpoint saved.")

    def load_checkpoints(self):
        clear_tree(self.cp_tree)
        term = "%" + self.cp_search.get().strip() + "%"
        rows = self.db.query("""SELECT id, ts, project, note FROM checkpoints
                                WHERE project LIKE ? OR note LIKE ? OR next_step LIKE ?
                                   OR context LIKE ? OR ts LIKE ? ORDER BY id DESC""", (term,) * 5)
        if not rows:
            self.cp_tree.insert("", "end", values=("", "", "", "No checkpoints yet. Fill the form above and click Save."))
        for cid, ts, project, note in rows:
            self.cp_tree.insert("", "end", values=(cid, ts, project, (note or "").replace("\n", " ")[:100]))

    def selected_id(self):
        sel = self.cp_tree.selection()
        values = self.cp_tree.item(sel[0])["values"] if sel else []
        if not values or values[0] == "":
            messagebox.showinfo(APP, "Please select a checkpoint first.")
            return None
        return values[0]

    def open_checkpoint(self):
        cid = self.selected_id()
        if cid is None:
            return
        ts, project, note, nxt, context = self.db.query(
            "SELECT ts, project, note, next_step, context FROM checkpoints WHERE id=?", (cid,))[0]
        saved = json.loads(context or "[]")
        then_titles = [a.get("title", "") for a in saved]
        now_titles = [title for _, title in list(self.tracker.recent)]
        win = tk.Toplevel(self)
        win.title("Resume - " + (project or "checkpoint"))
        win.configure(bg=BG)
        win.geometry("600x520")
        text = tk.Text(win, wrap="word", font=("Segoe UI", 10), padx=10, pady=10)
        text.pack(fill="both", expand=True, padx=10, pady=10)
        body = ("Context only - apps are NOT reopened.\n\n"
                "Project : %s\nSaved   : %s\n\nNOTE\n%s\n\nNEXT STEP\n%s\n\n"
                "Keywords then : %s\nSimilarity with current windows: %d%%\n\nAPPS OPEN AT THAT TIME\n"
                % (project, ts, note or "-", nxt or "-", ", ".join(keywords(then_titles)) or "-",
                   similarity(then_titles, now_titles)))
        body += "".join("  - %s  |  %s\n" % (a.get("app"), a.get("title")) for a in saved) or "  (none recorded)\n"
        text.insert("1.0", body)
        text.config(state="disabled")

    def delete_checkpoint(self):
        cid = self.selected_id()
        if cid is not None and messagebox.askyesno(APP, "Delete this checkpoint?"):
            self.db.run("DELETE FROM checkpoints WHERE id=?", (cid,))
            self.load_checkpoints()
            self.refresh_dashboard()

    # ---- usage history and files used
    def filter_row(self, parent, fields, on_show):
        bar = ttk.Frame(parent)
        bar.pack(fill="x", padx=12, pady=10)
        for i, (label, var) in enumerate(fields):
            ttk.Label(bar, text=label).grid(row=0, column=i, sticky="w", padx=8)
            ttk.Entry(bar, textvariable=var, width=18).grid(row=1, column=i, padx=8)
        ttk.Button(bar, text="Show", style="Accent.TButton", command=on_show).grid(row=1, column=len(fields), padx=8)

    def build_history(self, f):
        today = date.today().isoformat()
        self.h_from, self.h_to, self.h_app = tk.StringVar(value=today), tk.StringVar(value=today), tk.StringVar()
        self.filter_row(f, [("From (YYYY-MM-DD)", self.h_from), ("To", self.h_to),
                            ("App contains", self.h_app)], self.load_history)
        self.h_total = ttk.Label(f, text="", style="H.TLabel")
        self.h_total.pack(anchor="w", padx=12)
        self.h_tree = ttk.Treeview(f, columns=("day", "app", "time"), show="headings")
        for col, w in (("day", 140), ("app", 360), ("time", 160)):
            self.h_tree.heading(col, text=col.title())
            self.h_tree.column(col, width=w, anchor="w")
        self.h_tree.pack(fill="both", expand=True, padx=12, pady=8)

    def load_history(self):
        clear_tree(self.h_tree)
        rows = self.db.query("SELECT day, app, seconds FROM usage WHERE day BETWEEN ? AND ? AND app LIKE ? "
                             "AND " + SYS_CLAUSE + " ORDER BY day DESC, seconds DESC",
                             (self.h_from.get().strip(), self.h_to.get().strip(),
                              "%" + self.h_app.get().strip() + "%") + SYSTEM_APPS)
        for day, app, secs in rows:
            self.h_tree.insert("", "end", values=(day, app, fmt_secs(secs)))
        self.h_total.config(text="Total: " + fmt_secs(sum(r[2] for r in rows)))

    def build_files(self, f):
        today = date.today().isoformat()
        self.f_from, self.f_to, self.f_text = tk.StringVar(value=today), tk.StringVar(value=today), tk.StringVar()
        self.filter_row(f, [("From (YYYY-MM-DD)", self.f_from), ("To", self.f_to),
                            ("App or file name contains", self.f_text)], self.load_files)
        self.f_total = ttk.Label(f, text="", style="H.TLabel")
        self.f_total.pack(anchor="w", padx=12)
        self.f_warn = ttk.Label(f, text="", foreground="#b03040")
        self.f_warn.pack(anchor="w", padx=12)
        self.f_tree = ttk.Treeview(f, columns=("day", "app", "file", "time"), show="headings")
        for col, w, text in (("day", 100, "Day"), ("app", 140, "App"),
                             ("file", 470, "File / window name"), ("time", 90, "Time")):
            self.f_tree.heading(col, text=text)
            self.f_tree.column(col, width=w, anchor="w")
        self.f_tree.pack(fill="both", expand=True, padx=12, pady=8)

    def load_files(self):
        clear_tree(self.f_tree)
        on = self.db.get("track_titles", "1") == "1"
        self.f_warn.config(text="" if on else "File names recording is OFF. Turn it on in Settings.")
        term = "%" + self.f_text.get().strip() + "%"
        rows = self.db.query("SELECT day, app, title, seconds FROM titles WHERE day BETWEEN ? AND ? "
                             "AND (app LIKE ? OR title LIKE ?) AND " + SYS_CLAUSE +
                             " ORDER BY day DESC, seconds DESC LIMIT 1000",
                             (self.f_from.get().strip(), self.f_to.get().strip(), term, term) + SYSTEM_APPS)
        for day, app, title, secs in rows:
            self.f_tree.insert("", "end", values=(day, app, title, fmt_secs(secs)))
        self.f_total.config(text="%d files / windows" % len(rows))

    # ---- settings
    def build_settings(self, f):
        pad = dict(padx=14, pady=4, anchor="w")
        ttk.Label(f, text="Tracking", style="H.TLabel").pack(**pad)
        row = ttk.Frame(f)
        row.pack(**pad)
        self.pause_btn = ttk.Button(row, text="Pause tracking", style="Accent.TButton", command=self.toggle_tracking)
        self.pause_btn.pack(side="left")
        ttk.Label(row, text="   Mark as idle after (minutes):").pack(side="left")
        self.idle_var = tk.IntVar(value=int(self.db.get("idle_minutes", "3")))
        ttk.Spinbox(row, from_=1, to=60, width=4, textvariable=self.idle_var,
                    command=self.set_idle).pack(side="left", padx=4)
        self.idle_var.trace_add("write", lambda *a: self.set_idle())
        self.autostart_var = tk.BooleanVar(value=self.db.get("autostart") == "1")
        ttk.Checkbutton(f, text="Start ContextMind when Windows starts", variable=self.autostart_var,
                        command=self.toggle_autostart).pack(**pad)
        self.titles_var = tk.BooleanVar(value=self.db.get("track_titles", "1") == "1")
        ttk.Checkbutton(f, text="Record file / window names (Files Used tab)", variable=self.titles_var,
                        command=self.toggle_titles).pack(**pad)

        ttk.Label(f, text="Password & lock screen", style="H.TLabel").pack(**pad)
        row = ttk.Frame(f)
        row.pack(**pad)
        ttk.Button(row, text="Set / Change password", command=self.change_password).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Remove password", command=self.remove_password).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Lock now", command=lambda: self.show_lock("manual")).pack(side="left")
        row = ttk.Frame(f)
        row.pack(**pad)
        self.lock_var = tk.BooleanVar(value=self.db.get("lock_idle", "1") == "1")
        ttk.Checkbutton(row, text="Lock screen when no mouse/keyboard activity for", variable=self.lock_var,
                        command=self.save_lock_settings).pack(side="left")
        self.lock_min = tk.IntVar(value=int(self.db.get("lock_idle_minutes", "2")))
        ttk.Spinbox(row, from_=1, to=120, width=4, textvariable=self.lock_min,
                    command=self.save_lock_settings).pack(side="left", padx=4)
        self.lock_min.trace_add("write", lambda *a: self.save_lock_settings())
        ttk.Label(row, text="minutes").pack(side="left")
        self.oslock_var = tk.BooleanVar(value=self.db.get("os_lock") == "1")
        ttk.Checkbutton(f, text="Also lock Windows when idle (stronger)", variable=self.oslock_var,
                        command=lambda: self.db.set("os_lock", int(self.oslock_var.get()))).pack(**pad)

        ttk.Label(f, text="Export / Backup", style="H.TLabel").pack(**pad)
        row = ttk.Frame(f)
        row.pack(**pad)
        for text, cmd in (("Export usage (CSV)", self.export_usage),
                          ("Export checkpoints (CSV)", self.export_checkpoints),
                          ("Export files (CSV)", self.export_files),
                          ("Export all (JSON)", self.export_json),
                          ("Backup database", self.backup_database)):
            ttk.Button(row, text=text, command=cmd).pack(side="left", padx=(0, 6))
        ttk.Label(f, text="Exports and backups contain window titles. Keep them private.",
                  foreground="#b03040").pack(**pad)
        ttk.Label(f, text="Window X button minimizes the app (tracking continues).",
                  foreground="#7a6a9a").pack(**pad)
        ttk.Button(f, text="Exit ContextMind completely", command=self.quit_app).pack(**pad)
        ttk.Label(f, text="Data folder: " + DATA_DIR, foreground="#7a6a9a").pack(**pad)

    def toggle_tracking(self):
        self.tracker.paused = not self.tracker.paused
        self.db.set("paused", int(self.tracker.paused))
        self.refresh_dashboard()

    def set_idle(self):
        try:
            minutes = max(1, int(self.idle_var.get()))
        except (ValueError, tk.TclError):
            return
        self.db.set("idle_minutes", minutes)
        self.tracker.idle_limit = minutes * 60

    def save_lock_settings(self):
        try:
            minutes = max(1, int(self.lock_min.get()))
        except (ValueError, tk.TclError):
            return
        self.db.set("lock_idle_minutes", minutes)
        self.db.set("lock_idle", int(self.lock_var.get()))

    def toggle_titles(self):
        on = self.titles_var.get()
        self.db.set("track_titles", int(on))
        self.tracker.track_titles = on
        self.load_files()

    def toggle_autostart(self):
        on = self.autostart_var.get()
        if not IS_WIN:
            messagebox.showinfo(APP, "This option works on Windows only.")
            self.autostart_var.set(False)
            return
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            if on:
                if getattr(sys, "frozen", False):
                    cmd = '"%s" --minimized' % sys.executable
                else:
                    pyw = sys.executable.replace("python.exe", "pythonw.exe")
                    cmd = '"%s" "%s" --minimized' % (pyw, os.path.abspath(__file__))
                winreg.SetValueEx(key, APP, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, APP)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
            self.db.set("autostart", int(on))
        except OSError as ex:
            logging.exception("autostart")
            messagebox.showerror(APP, "Startup setting failed: %s" % ex)
            self.autostart_var.set(not on)

    # ---- password
    def ask_secret(self, prompt):
        """Modal password box. Returns the typed text, or None if cancelled."""
        result = {"value": None}
        win = tk.Toplevel(self)
        win.title(APP)
        win.configure(bg=BG)
        win.resizable(False, False)
        tk.Label(win, text=prompt, bg=BG, fg=DARK, font=("Segoe UI", 10)).pack(padx=20, pady=(16, 6))
        entry = tk.Entry(win, show="*", width=28, font=("Segoe UI", 11))
        entry.pack(padx=20, pady=4)

        def ok(_=None):
            result["value"] = entry.get()
            win.destroy()

        row = tk.Frame(win, bg=BG)
        row.pack(pady=12)
        tk.Button(row, text="OK", width=9, bg=ACCENT, fg="white", command=ok).pack(side="left", padx=5)
        tk.Button(row, text="Cancel", width=9, command=win.destroy).pack(side="left", padx=5)
        win.bind("<Return>", ok)
        win.bind("<Escape>", lambda e: win.destroy())
        win.attributes("-topmost", True)
        win.grab_set()
        entry.focus_force()
        self.wait_window(win)
        return result["value"]

    def change_password(self):
        if self.db.has_password():
            current = self.ask_secret("Current password:")
            if current is None or not self.db.check_password(current):
                return messagebox.showerror(APP, "Wrong password.")
        first = self.ask_secret("New password:")
        if not first:
            return
        if self.ask_secret("Confirm new password:") != first:
            return messagebox.showerror(APP, "Passwords do not match.")
        self.db.set_password(first)
        messagebox.showinfo(APP, "Password set.")

    def remove_password(self):
        if not self.db.has_password():
            return
        current = self.ask_secret("Current password:")
        if current is not None and self.db.check_password(current):
            self.db.set_password("")
            messagebox.showinfo(APP, "Password removed.")
        else:
            messagebox.showerror(APP, "Wrong password.")

    def first_run_prompt(self):
        if self.db.get("asked_pw") == "1" or self.db.has_password():
            return
        self.db.set("asked_pw", "1")
        if messagebox.askyesno(APP, "A password is needed for the lock screen.\nSet one now?"):
            self.change_password()

    # ---- lock flow
    def seconds_left(self):
        return max(0, int(self.locked_until - time.time() + 0.999))

    def show_lock(self, reason):
        if self.lock_win is not None:
            return
        if not self.db.has_password():
            if reason == "manual":
                messagebox.showinfo(APP, "Please set a password first.")
            return
        snapshot = self.prev_snapshot if reason == "startup" else (self.tracker.snapshot() or self.prev_snapshot)
        self.was_normal = self.state() == "normal"
        self.withdraw()
        try:
            self.lock_win = LockScreen(self, reason, snapshot)
        except tk.TclError:
            logging.exception("lock screen")
            self.lock_win = None
            self.deiconify()

    def lock_closed(self, reason):
        self.lock_win = None
        if reason == "startup":
            self.deiconify()
            if self.start_minimized:
                self.iconify()
        elif self.was_normal:
            self.deiconify()

    # ---- export and backup
    def export_csv(self, name, header, query):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=name,
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(header)
            writer.writerows(self.db.query(query))
        messagebox.showinfo(APP, "Exported." + PRIVACY_NOTE)

    def export_usage(self):
        self.export_csv("contextmind_usage.csv", ["day", "app", "seconds"],
                        "SELECT day, app, seconds FROM usage ORDER BY day, app")

    def export_checkpoints(self):
        self.export_csv("contextmind_checkpoints.csv",
                        ["id", "time", "project", "note", "next_step", "context"],
                        "SELECT id, ts, project, note, next_step, context FROM checkpoints")

    def export_files(self):
        self.export_csv("contextmind_files.csv", ["day", "app", "file_or_window", "seconds"],
                        "SELECT day, app, title, seconds FROM titles ORDER BY day, app")

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile="contextmind_all.json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        data = {
            "usage": [dict(day=d, app=a, seconds=s) for d, a, s in self.db.query("SELECT day, app, seconds FROM usage")],
            "checkpoints": [dict(id=i, time=t, project=p, note=n, next_step=x, context=c) for i, t, p, n, x, c in
                            self.db.query("SELECT id, ts, project, note, next_step, context FROM checkpoints")],
            "files": [dict(day=d, app=a, title=t, seconds=s) for d, a, t, s in
                      self.db.query("SELECT day, app, title, seconds FROM titles")],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        messagebox.showinfo(APP, "Exported." + PRIVACY_NOTE)

    def backup_database(self):
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("SQLite", "*.db")],
                                            initialfile="contextmind_backup_%s.db" % date.today().isoformat())
        if path:
            self.db.backup(path)
            messagebox.showinfo(APP, "Backup saved." + PRIVACY_NOTE)

    # ---- loop and quit
    def tick(self):
        """Every 2 seconds: check idle lock, keep lock screen on top, refresh dashboard."""
        try:
            self.tick_count += 1
            if self.lock_win is not None:
                try:
                    self.lock_win.lift()
                except tk.TclError:
                    self.lock_win = None
            elif (self.db.get("lock_idle", "1") == "1" and self.db.has_password()
                  and idle_seconds() > int(self.db.get("lock_idle_minutes", "2")) * 60):
                if self.db.get("os_lock") == "1":
                    lock_windows()
                self.show_lock("idle")
            if self.tick_count % 3 == 0 and self.lock_win is None and self.state() == "normal":
                self.refresh_dashboard()
        except tk.TclError:
            pass  # window is closing
        except Exception:
            logging.exception("tick")
        finally:
            self.after(2000, self.tick)

    def quit_app(self):
        if messagebox.askyesno(APP, "Exit ContextMind? Tracking will stop."):
            self.tracker.save_snapshot()
            self.tracker.stop()
            self.destroy()


# ---------------------------------------------------------------- 7. Startup
def setup_logging():
    os.makedirs(DATA_DIR, exist_ok=True)
    logging.basicConfig(filename=LOG_PATH, level=logging.ERROR, format="%(asctime)s %(message)s")


def acquire_single_instance():
    """True if this is the only running ContextMind (named Windows mutex)."""
    if not IS_WIN:
        return True
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.restype = wt.HANDLE
    k32.CreateMutexW.argtypes = [wt.LPVOID, wt.BOOL, wt.LPCWSTR]
    k32.CreateMutexW(None, False, "Local\\ContextMindSingleInstance")
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


def report_crash(text):
    """Save the traceback to crash.txt and show it in a message box."""
    path = os.path.join(DATA_DIR, "crash.txt")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n=== %s ===\n%s" % (datetime.now().isoformat(), text))
    except OSError:
        path = "(could not save)"
    if IS_WIN:
        ctypes.windll.user32.MessageBoxW(None, "ContextMind crashed.\n\n%s\n\nDetails: %s" % (text[-600:], path),
                                         APP, 0x10)
    else:
        print(text)


def main():
    setup_logging()
    if not acquire_single_instance():
        if IS_WIN and "--minimized" not in sys.argv:
            ctypes.windll.user32.MessageBoxW(None, "ContextMind is already running.", APP, 0x40)
        return
    App(start_minimized="--minimized" in sys.argv).mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        report_crash(traceback.format_exc())
        sys.exit(1)
