"""ContextMind - workflow context recovery tracker (Windows desktop app).

Sections:
  1. Config and Windows API helpers
  2. Database (SQLite, password hashing)
  3. Text helpers (break type, TF-IDF keywords, cosine similarity)
  4. Tracker thread (usage, idle, breaks, last-active snapshot)
  5. Lock screen (password, lockout countdown, last activity)
  6. Main window (dashboard, checkpoints, history, files, settings)
  7. Startup (single instance, logging, crash report)
Extra features: dark mode, usage chart, break reminder, history search, resume popup, auto-restore.
Data folder: %APPDATA%\\ContextMind
"""
import os, sys, re, csv, json, math, time, sqlite3, hashlib, logging, secrets, threading, traceback, ctypes, subprocess
# Windows data types (HWND, DWORD, ...) needed for calling the Windows API.
from ctypes import wintypes as wt
# Counter counts words for TF-IDF; deque keeps a fixed-size list of recent windows.
from collections import Counter, deque
from datetime import datetime, date, timedelta
# Tkinter is the GUI library used for every window, button and label.
import tkinter as tk
# ttk gives themed widgets, messagebox gives popups, filedialog gives the save dialog.
from tkinter import ttk, messagebox, filedialog

# Pillow is optional. It is only used for the blurred lock screen background.
try:
    from PIL import Image, ImageGrab, ImageFilter, ImageTk
except ImportError:
    # Without Pillow the lock screen simply uses a plain color.
    Image = None

# ---------------------------------------------------------------- 1. Config and Windows API
# True when the program is running on Windows.
IS_WIN = sys.platform.startswith("win")
APP = "ContextMind"
# Data folder is C:\Users\<name>\AppData\Roaming\ContextMind (falls back to the home folder).
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP)
# SQLite database file.
DB_PATH = os.path.join(DATA_DIR, "contextmind.db")
# Error log file.
LOG_PATH = os.path.join(DATA_DIR, "contextmind.log")
# Purple UI color theme: background, accent, dark, light, pink.
BG, ACCENT, DARK, LIGHT, PINK = "#f3eefc", "#6c3fc5", "#2e1a5c", "#e4d9f7", "#ff9aa2"
# Main window colors in light and dark mode. T always holds the active palette.
# (The lock screen keeps the fixed purple colors above.)
LIGHT_T = dict(bg="#f3eefc", fg="#2e1a5c", card="#ffffff", light="#e4d9f7", btn="#dcdad5",
               accent_fg="#6c3fc5", accent_active="#2e1a5c")
DARK_T = dict(bg="#1c1630", fg="#ece6fa", card="#2a2145", light="#3a2f5c", btn="#3a2f5c",
              accent_fg="#b79cf2", accent_active="#8a63e0")
T = dict(LIGHT_T)
# Idle time is stored in its own bucket with this name.
IDLE = "idle"
# The app itself must never be tracked as user activity.
OWN_APPS = {"contextmind.exe", "python.exe", "pythonw.exe", "py.exe"}
# System apps that are hidden from every report.
SYSTEM_APPS = ("helpandtips.exe", "werfault.exe", "rundll32.exe", "unknown", "taskmgr.exe",
               "systemsettings.exe", "py.exe", "python.exe", "pythonw.exe", "contextmind.exe", IDLE)
# Reusable SQL snippet "LOWER(app) NOT IN (?,?,?,...)" that excludes the system apps above.
SYS_CLAUSE = "LOWER(app) NOT IN (%s)" % ",".join("?" * len(SYSTEM_APPS))
# Programs that are never offered for restore (Windows shell, system helpers and this app).
RESTORE_SKIP = {"explorer.exe", "applicationframehost.exe", "textinputhost.exe", "searchhost.exe",
                "startmenuexperiencehost.exe", "shellexperiencehost.exe", "lockapp.exe", "snippingtool.exe",
                "systemsettings.exe", "taskmgr.exe", "cmd.exe", "conhost.exe", "widgets.exe"}
NO_RESTORE = OWN_APPS | RESTORE_SKIP | set(SYSTEM_APPS)
# After 5 wrong passwords the lock screen is blocked for 60 seconds.
MAX_FAILS, LOCK_SECS = 5, 60
# Name of the Windows event used to signal the running app when a second copy is launched.
SHOW_EVENT_NAME = "Local\\ContextMindShowWindow"
# Windows event handle for the second launch signal. It is set in acquire_single_instance.
_show_event = None
# WaitForSingleObject function. It is also set in acquire_single_instance.
_wait_fn = None
PRIVACY_NOTE = "\nThis file contains window titles. Keep it private."

if IS_WIN:
    # Load the Windows system libraries used to read the active window and the idle time.
    user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
    # Declare argument and return types so the calls are safe on 64-bit Windows.
    user32.GetForegroundWindow.restype = wt.HWND
    user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.GetTickCount.restype = wt.DWORD
    # Extra declarations used to list the open program windows (auto-restore feature).
    WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
    user32.IsWindowVisible.argtypes = [wt.HWND]
    user32.GetWindowTextLengthW.argtypes = [wt.HWND]
    user32.GetWindowLongW.argtypes = [wt.HWND, ctypes.c_int]
    user32.GetWindowLongW.restype = ctypes.c_long
    user32.GetWindow.argtypes = [wt.HWND, wt.UINT]
    user32.GetWindow.restype = wt.HWND
    try:
        # Used to ignore hidden (cloaked) windows such as suspended Store apps.
        dwmapi = ctypes.windll.dwmapi
        dwmapi.DwmGetWindowAttribute.argtypes = [wt.HWND, wt.DWORD, ctypes.c_void_p, wt.DWORD]
    except (OSError, AttributeError):
        dwmapi = None

    # C structure expected by Windows. It holds the time of the last keyboard or mouse input.
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", wt.UINT), ("dwTime", wt.DWORD)]

    def foreground():
        """(process_exe, window_title, pid) of the active window, or None."""
        # Handle of the window that currently has focus.
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        # Buffer that receives the window title text.
        title_buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title_buf, 512)
        # Find the process id that owns this window.
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        exe = "unknown"
        # 0x1000 is PROCESS_QUERY_LIMITED_INFORMATION, the lowest permission needed.
        handle = kernel32.OpenProcess(0x1000, False, pid.value)
        if handle:
            name, size = ctypes.create_unicode_buffer(1024), wt.DWORD(1024)
            if kernel32.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)):
                # Keep only the file name (for example chrome.exe) from the full path.
                exe = os.path.basename(name.value)
            kernel32.CloseHandle(handle)
        return exe, title_buf.value, pid.value

    def idle_seconds():
        """Seconds since the last keyboard or mouse input."""
        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if user32.GetLastInputInfo(ctypes.byref(info)):
            # The mask handles the 32-bit tick counter wrapping around after about 49 days.
            return ((kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF) / 1000.0
        return 0.0

    def lock_windows():
        # Locks the Windows session, same as pressing Win + L.
        user32.LockWorkStation()

    def exe_path(pid):
        """Full path of the program file that owns a process id, or an empty string."""
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return ""
        name, size = ctypes.create_unicode_buffer(1024), wt.DWORD(1024)
        ok = kernel32.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size))
        kernel32.CloseHandle(handle)
        return name.value if ok else ""

    def visible_apps():
        """Open program windows as [{exe, app, title}], one entry per program, with the full exe path."""
        found, seen = [], set()

        def callback(hwnd, _):
            try:
                if not user32.IsWindowVisible(hwnd) or user32.GetWindowTextLengthW(hwnd) == 0:
                    return True
                # Skip tool windows (0x80) and windows that belong to another window.
                if user32.GetWindowLongW(hwnd, -20) & 0x80 or user32.GetWindow(hwnd, 4):
                    return True
                if dwmapi is not None:
                    cloaked = wt.DWORD(0)
                    if dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked),
                                                    ctypes.sizeof(cloaked)) == 0 and cloaked.value:
                        return True
                title = ctypes.create_unicode_buffer(512)
                user32.GetWindowTextW(hwnd, title, 512)
                pid = wt.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                path = exe_path(pid.value)
                if path and path.lower() not in seen:
                    seen.add(path.lower())
                    found.append({"exe": path, "app": os.path.basename(path), "title": title.value})
            except Exception:
                logging.exception("visible_apps")
            return True

        user32.EnumWindows(WNDENUMPROC(callback), 0)
        return found
else:
    # Dummy versions so the file can be tested on non-Windows systems.
    def foreground():
        return "demo.exe", "Demo window", 0

    def idle_seconds():
        return 0.0

    def lock_windows():
        pass

    def visible_apps():
        return []


def fmt_secs(seconds):
    # Converts seconds to text such as "2h 05m", "4m 10s" or "30s" for display.
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return "%dh %02dm" % (h, m)
    if m:
        return "%dm %02ds" % (m, s)
    return "%ds" % s


def ago(iso):
    # Converts an ISO timestamp to text such as "just now", "5 min ago" or "2 days ago".
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
    # Removes every row from a Treeview table.
    tree.delete(*tree.get_children())


def pick_session(text):
    """From the saved list of recent snapshots, returns the one with the most programs.
    Windows closes programs one by one at shutdown, so the fullest recent snapshot is the best one."""
    try:
        ring = json.loads(text) if text else []
    except ValueError:
        return []
    ring = [s for s in ring if isinstance(s, list)] if isinstance(ring, list) else []
    return max(ring, key=len, default=[])


def restorable(session):
    """Programs from a saved session that are not running now and still exist on disk."""
    running = {a["exe"].lower() for a in visible_apps()}
    out, seen = [], set()
    for item in session:
        exe = item.get("exe", "")
        low = exe.lower()
        if not exe or low in running or low in seen or not os.path.isfile(exe):
            continue
        seen.add(low)
        out.append(item)
    return out


# ---------------------------------------------------------------- 2. Database
class DB:
    # SQLite wrapper shared by the tracker thread and the UI, protected by a lock.
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        # Only one thread may use the database connection at a time.
        self.lock = threading.Lock()
        # check_same_thread=False allows the tracker thread and the UI thread to share the connection.
        self.con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
        # WAL mode lets readers work without blocking the tracker.
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA busy_timeout=15000")
        # Create the tables if they do not exist yet.
        # usage: seconds per day per app.
        # titles: seconds per day per app per window title (Files Used tab).
        # checkpoints: saved work notes with the context of recent apps.
        # breaks: detected idle breaks and their type.
        # settings: key-value store (password hash, idle minutes, and so on).
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
        # Runs a SELECT and returns all rows.
        with self.lock:
            return self.con.execute(sql, args).fetchall()

    def run(self, sql, args=()):
        # Runs an INSERT, UPDATE or DELETE and commits it.
        with self.lock:
            self.con.execute(sql, args)
            self.con.commit()

    def get(self, key, default=""):
        # Reads one setting value, or the default if it does not exist.
        rows = self.query("SELECT v FROM settings WHERE k=?", (key,))
        return rows[0][0] if rows else default

    def set(self, key, value):
        # Saves one setting, replacing the old value if present.
        self.run("INSERT OR REPLACE INTO settings(k, v) VALUES(?, ?)", (key, str(value)))

    def add_usage(self, day, app, secs):
        # Upsert: adds seconds to the existing row, or creates the row for this day and app.
        self.run("""INSERT INTO usage VALUES(?, ?, ?) ON CONFLICT(day, app)
                    DO UPDATE SET seconds = seconds + excluded.seconds""", (day, app, secs))

    def add_title(self, day, app, title, secs):
        # Same upsert as add_usage, but at window title level.
        self.run("""INSERT INTO titles VALUES(?, ?, ?, ?) ON CONFLICT(day, app, title)
                    DO UPDATE SET seconds = seconds + excluded.seconds""", (day, app, title, secs))

    def backup(self, path):
        # Writes a safe copy of the whole database to another file.
        with self.lock:
            out = sqlite3.connect(path)
            self.con.backup(out)
            out.close()

    @staticmethod
    def _hash(password, salt):
        # PBKDF2 with SHA-256 and 100000 iterations. The plain password is never stored.
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()

    def has_password(self):
        return bool(self.get("pw_hash"))

    def set_password(self, password):
        # An empty password means the password is removed.
        if not password:
            self.run("DELETE FROM settings WHERE k IN ('pw_hash', 'pw_salt')")
            return
        # A random salt makes the same password produce a different hash each time.
        salt = secrets.token_hex(16)
        self.set("pw_salt", salt)
        self.set("pw_hash", self._hash(password, salt))

    def check_password(self, password):
        # compare_digest gives a constant-time comparison that resists timing attacks.
        return secrets.compare_digest(self._hash(password, self.get("pw_salt")), self.get("pw_hash"))


# ---------------------------------------------------------------- 3. Text helpers
# Common words that must not appear in the keyword results.
STOP = {"the", "and", "for", "with", "new", "open", "file", "untitled", "google", "chrome",
        "window", "tab", "page", "http", "https", "www", "com"}


def tokenize(text):
    # Splits text into lowercase words of 3 or more characters and removes the stop words.
    return [w for w in re.findall(r"[a-z][a-z0-9_+#]{2,}", (text or "").lower()) if w not in STOP]


def break_type(idle_secs):
    """Labels an idle period as short interruption, real break or end of session."""
    # Under 5 minutes.
    if idle_secs < 5 * 60:
        return "short interruption"
    # Between 5 and 30 minutes.
    if idle_secs <= 30 * 60:
        return "real break"
    # Over 30 minutes.
    return "end of session"


def keywords(titles, k=5):
    """Top TF-IDF words across window titles."""
    # Each title is treated as one document made of word counts.
    docs = [Counter(tokenize(t)) for t in titles if t]
    # n is the number of documents and df is the document frequency of each word.
    n, df, score = len(docs), Counter(), Counter()
    for doc in docs:
        df.update(doc.keys())
    for doc in docs:
        total = sum(doc.values()) or 1
        for word, count in doc.items():
            # Score = TF * IDF, where TF = count / total and IDF = log((1 + n) / (1 + df)) + 1.
            score[word] += (count / total) * (math.log((1 + n) / (1 + df[word])) + 1)
    # Return the k words with the highest score.
    return [w for w, _ in score.most_common(k)]


def similarity(titles_a, titles_b):
    """Cosine similarity (0-100%) between two sets of window titles."""
    # Build one word-count vector for each set of titles.
    a = Counter(w for t in titles_a for w in tokenize(t))
    b = Counter(w for t in titles_b for w in tokenize(t))
    # Dot product of the two vectors.
    dot = sum(a[w] * b[w] for w in a)
    # Product of the vector lengths.
    norm = math.sqrt(sum(v * v for v in a.values())) * math.sqrt(sum(v * v for v in b.values()))
    # Cosine similarity = dot / norm, converted to a percentage.
    return round(100 * dot / norm) if norm else 0


# ---------------------------------------------------------------- 4. Tracker thread
class Tracker(threading.Thread):
    # Background thread that samples the active window without freezing the UI.
    # Seconds between samples.
    STEP = 2.0

    def __init__(self, db):
        # daemon=True makes the thread stop automatically when the app closes.
        super().__init__(daemon=True)
        self.db = db
        # Pause state is restored from the saved settings.
        self.paused = db.get("paused") == "1"
        # Seconds without input before the user is considered idle.
        self.idle_limit = int(db.get("idle_minutes", "3")) * 60
        # Whether window titles should be recorded.
        self.track_titles = db.get("track_titles", "1") == "1"
        # Event used to ask the thread to stop.
        self.stop_flag = threading.Event()
        # The (app, title) that is in use right now.
        self.current = ("-", "-")
        self.is_idle = False
        # The last 60 distinct (app, title) pairs.
        self.recent = deque(maxlen=60)
        # Epoch time of the last active sample.
        self.last_active = None
        # Used to detect when an idle period ends so the break can be stored.
        self.was_idle, self.idle_started = False, 0.0
        # Seconds collected since the last snapshot save.
        self.unsaved = 0.0
        # Break reminder: seconds of continuous work, the limit, and a flag the UI reads.
        self.work_secs = 0.0
        self.remind_on = db.get("remind_on", "1") == "1"
        self.remind_secs = int(db.get("remind_minutes", "60")) * 60
        self.remind_due = False
        # Set when the user returns from a real break: (kind, idle_seconds). The UI shows the resume popup.
        self.resume_event = None
        # The last 3 snapshots of the open programs (about 30 seconds), used by auto-restore.
        self.session_ring = deque(maxlen=3)

    def stop(self):
        self.stop_flag.set()

    def run(self):
        # Main loop of the thread. It starts when start() is called.
        last = time.time()
        while not self.stop_flag.is_set():
            # Wait for the next sample.
            time.sleep(self.STEP)
            now = time.time()
            # Elapsed time since the last sample, capped so sleep or hibernate does not add a huge value.
            dt, last = min(now - last, self.STEP * 2.5), now
            if self.paused:
                continue
            try:
                self.step(dt, now)
            except Exception:
                # An error in one step is logged and the thread keeps running.
                logging.exception("tracker step")

    def step(self, dt, now):
        # One sample: check idle, store a finished break, then record the active window.
        day = date.today().isoformat()
        idle = idle_seconds()
        self.is_idle = idle > self.idle_limit
        if self.is_idle:
            self.was_idle, self.idle_started = True, idle
            # Idle time goes into its own bucket.
            self.db.add_usage(day, IDLE, dt)
            return
        # The user just came back from idle, so store the break that ended.
        if self.was_idle:
            self.was_idle = False
            kind = break_type(self.idle_started)
            self.db.run("INSERT INTO breaks(ts, idle_secs, kind) VALUES(?, ?, ?)",
                        (datetime.now().isoformat(timespec="seconds"), self.idle_started, kind))
            # A real break (5 minutes or more) restarts the work counter and asks for the resume popup.
            if kind != "short interruption":
                self.work_secs = 0.0
                self.remind_due = False
                self.resume_event = (kind, self.idle_started)
        # Read the active window.
        fg = foreground()
        # Skip when there is no window, or when it belongs to this app.
        if not fg or fg[2] == os.getpid() or fg[0].lower() in OWN_APPS:
            return
        app, title, _ = fg
        self.current, self.last_active = (app, title), now
        # Add to the recent list only when the window changed.
        if not self.recent or self.recent[-1] != (app, title):
            self.recent.append((app, title))
        self.db.add_usage(day, app, dt)
        # Count continuous work for the break reminder.
        self.work_secs += dt
        if self.remind_on and self.work_secs >= self.remind_secs:
            self.remind_due = True
        if self.track_titles and title.strip():
            self.db.add_title(day, app, title.strip()[:150], dt)
        self.unsaved += dt
        # Save a snapshot roughly every 10 seconds.
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
        # Summary of the last activity. The lock screen shows this after unlocking.
        if self.last_active is None:
            return None
        return {"ts": datetime.fromtimestamp(self.last_active).isoformat(timespec="seconds"),
                "apps": self.context(5)}

    def save_snapshot(self):
        # Stores the snapshot as JSON so the next launch can show the last activity.
        snap = self.snapshot()
        if snap:
            self.db.set("last_active", json.dumps(snap))
            self.save_session()

    def save_session(self):
        # Remembers which programs are open (full exe path) so they can be offered back after a restart.
        apps = [a for a in visible_apps() if a["app"].lower() not in NO_RESTORE]
        if apps:
            self.session_ring.append(apps)
            self.db.set("session_ring", json.dumps(list(self.session_ring)))


# ---------------------------------------------------------------- 5. Lock screen
class LockScreen(tk.Toplevel):
    # Fullscreen password screen. After unlocking it shows the last activity.
    REASONS = {"startup": "Welcome back - ContextMind is locked",
               "idle": "No activity detected - screen locked",
               "manual": "Locked"}

    def __init__(self, app, reason, snapshot):
        super().__init__(app)
        # Stay hidden until the screen is fully built.
        self.withdraw()
        self.app, self.db, self.reason, self.snapshot = app, app.db, reason, snapshot
        # Id of the countdown timer, so it can be cancelled.
        self.timer_id = None
        self.entry = self.msg = self.button = None
        self.configure(bg=DARK)
        # Ignore the close request so Alt+F4 cannot dismiss the lock screen.
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        # Blurred screenshot used as the background.
        self.background = self.make_background()
        self.canvas = tk.Canvas(self, highlightthickness=0, bg=DARK)
        self.canvas.pack(fill="both", expand=True)
        if self.background:
            self.canvas.create_image(0, 0, anchor="nw", image=self.background)
        # Card in the center of the screen that holds the password form.
        self.card = tk.Frame(self.canvas, bg=DARK, padx=36, pady=28,
                             highlightthickness=2, highlightbackground=ACCENT)
        self.canvas.create_window(self.winfo_screenwidth() // 2, self.winfo_screenheight() // 2,
                                  window=self.card)
        self.show_login()
        self.attributes("-fullscreen", True)
        # Keep this window above every other window.
        self.attributes("-topmost", True)
        self.deiconify()
        # Take keyboard focus shortly after the window appears.
        self.after(250, self.grab_focus)

    def make_background(self):
        # Takes a screenshot, blurs it and blends a purple tint over it.
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
        # Forces keyboard and mouse input to go to the lock screen only.
        try:
            self.focus_force()
            if self.entry is not None:
                self.entry.focus_force()
            self.grab_set()
        except tk.TclError:
            pass

    def clear(self):
        # Removes every widget from the card so a different screen can be drawn.
        self.cancel_timer()
        for widget in self.card.winfo_children():
            widget.destroy()

    def cancel_timer(self):
        if self.timer_id:
            self.after_cancel(self.timer_id)
            self.timer_id = None

    def show_login(self):
        # Builds the password entry screen.
        self.clear()
        c = self.card
        tk.Label(c, text=APP, bg=DARK, fg="white", font=("Segoe UI", 24, "bold")).pack()
        tk.Label(c, text=self.REASONS[self.reason], bg=DARK, fg=LIGHT,
                 font=("Segoe UI", 11)).pack(pady=(2, 14))
        tk.Label(c, text="Enter password to see your last activity", bg=DARK, fg="white",
                 font=("Segoe UI", 11)).pack(pady=(0, 6))
        # show="*" hides the typed characters.
        self.entry = tk.Entry(c, show="*", width=26, font=("Segoe UI", 14), justify="center")
        self.entry.pack(pady=4)
        # Pressing Enter works the same as clicking Unlock.
        self.entry.bind("<Return>", lambda e: self.try_unlock())
        self.msg = tk.Label(c, text="", bg=DARK, fg=PINK, font=("Segoe UI", 10))
        self.msg.pack(pady=2)
        self.button = tk.Button(c, text="Unlock", width=14, bg=ACCENT, fg="white", relief="flat",
                                font=("Segoe UI", 11, "bold"), command=self.try_unlock)
        self.button.pack(pady=(8, 0))
        self.entry.focus_set()
        self.update_countdown()

    def update_countdown(self):
        """Refreshes the lockout countdown every second and re-enables the field when it ends."""
        self.timer_id = None
        left = self.app.seconds_left()
        # Lockout is still active: disable the inputs and show the remaining time.
        if left > 0:
            self.entry.delete(0, "end")
            self.entry.config(state="disabled")
            self.button.config(state="disabled")
            self.msg.config(text="Too many wrong attempts. Try again in %ds" % left)
            self.timer_id = self.after(1000, self.update_countdown)
        # Lockout just ended: enable the inputs again.
        elif str(self.entry.cget("state")) == "disabled":
            self.entry.config(state="normal")
            self.button.config(state="normal")
            self.msg.config(text="You can try again now")
            self.entry.focus_set()

    def try_unlock(self):
        # Checks the password. Five wrong attempts cause a 60 second lockout.
        if self.app.seconds_left() > 0:
            return self.update_countdown()
        # Correct password: reset the counter and show the activity details.
        if self.db.check_password(self.entry.get()):
            self.app.fails = 0
            return self.show_details()
        # Wrong password.
        self.app.fails += 1
        self.entry.delete(0, "end")
        if self.app.fails >= MAX_FAILS:
            self.app.fails = 0
            self.app.locked_until = time.time() + LOCK_SECS
            self.update_countdown()
        else:
            self.msg.config(text="Wrong password (%d/%d)" % (self.app.fails, MAX_FAILS))

    def show_details(self):
        # Shown after unlocking: last activity, last checkpoint and today's top files.
        self.clear()
        c, db, today = self.card, self.db, date.today().isoformat()
        tk.Label(c, text="Your last activity", bg=DARK, fg="white",
                 font=("Segoe UI", 20, "bold")).pack(pady=(0, 10))
        lines = []
        # Part 1: the apps that were in use at the last active moment.
        if self.snapshot and self.snapshot.get("apps"):
            lines += ["Last active: %s  (%s)" % (self.snapshot["ts"].replace("T", " "), ago(self.snapshot["ts"])),
                      "", "You were using:"]
            lines += ["   %s  -  %s" % (a["app"], a["title"][:70]) for a in self.snapshot["apps"]]
        else:
            lines.append("No earlier activity recorded yet.")
        # Part 2: the most recent checkpoint.
        cp = db.query("SELECT ts, project, note, next_step FROM checkpoints ORDER BY id DESC LIMIT 1")
        if cp:
            ts, project, note, nxt = cp[0]
            lines += ["", "Last checkpoint (%s)" % ts,
                      "   Project   : %s" % (project or "-"),
                      "   Note      : %s" % (note or "-").replace("\n", " ")[:120],
                      "   Next step : %s" % (nxt or "-").replace("\n", " ")[:120]]
        # Part 3: the five most used files or windows today.
        files = db.query("SELECT app, title, seconds FROM titles WHERE day=? AND " + SYS_CLAUSE +
                         " ORDER BY seconds DESC LIMIT 5", (today,) + SYSTEM_APPS)
        if files:
            lines += ["", "Files / windows used today"]
            lines += ["   %s  -  %s  (%s)" % (a, t[:55], fmt_secs(s)) for a, t, s in files]
        # Part 4: total tracked time and idle time for today.
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
        # Closes the lock screen and tells the main window to show itself again.
        self.cancel_timer()
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
        self.app.lock_closed(self.reason)


# ---------------------------------------------------------------- 6. Main window
class App(tk.Tk):
    # Main application window. It creates the database and tracker, then shows the UI.
    def __init__(self, start_minimized=False):
        super().__init__()
        self.title(APP)
        self.geometry("920x680")
        self.minsize(820, 600)
        self.configure(bg=BG)
        self.start_minimized = start_minimized
        # Backend: database.
        self.db = DB()
        # Activity saved by the previous session, shown on the startup lock screen.
        self.prev_snapshot = self.load_json(self.db.get("last_active"))
        # Programs that were open in the previous session (read before the tracker overwrites them).
        self.prev_session = pick_session(self.db.get("session_ring"))
        # Dark or light palette from the saved setting.
        T.update(DARK_T if self.db.get("dark_mode") == "1" else LIGHT_T)
        self.configure(bg=T["bg"])
        # References to the break reminder, resume and restore popups while they are open.
        self.remind_win = self.resume_win = self.restore_win = None
        # Backend: tracker thread.
        self.tracker = Tracker(self.db)
        self.tracker.start()
        # Reference to the lock screen while it is open.
        self.lock_win = None
        self.was_normal = True
        # Wrong password counter and the time when the lockout ends.
        self.fails, self.locked_until = 0, 0.0
        self.tick_count = 0
        self.style()
        self.build()
        # The window close button only minimizes, so tracking continues in the background.
        self.protocol("WM_DELETE_WINDOW", self.iconify)
        self.refresh_dashboard()
        # If a password exists, show the lock screen on startup.
        if self.db.has_password():
            self.withdraw()
            self.after(150, lambda: self.show_lock("startup"))
        elif start_minimized:
            self.iconify()
        else:
            # First launch without a password: offer to set one.
            self.after(900, self.first_run_prompt)
        # Without a password there is no unlock step, so offer the restore shortly after startup.
        if not self.db.has_password():
            self.after(2500, self.offer_restore)
        # Start the periodic loops.
        self.after(2000, self.tick)
        self.after(500, self.poll_show)

    @staticmethod
    def load_json(text):
        # Safe JSON parsing that returns None for empty or invalid text.
        try:
            return json.loads(text) if text else None
        except ValueError:
            return None

    def style(self):
        # Sets the ttk theme, colors and fonts from the active palette T (light or dark).
        s = ttk.Style(self)
        s.theme_use("clam")
        bg, fg, card, light = T["bg"], T["fg"], T["card"], T["light"]
        s.configure("TNotebook", background=bg, borderwidth=0)
        s.configure("TNotebook.Tab", padding=(16, 7), font=("Segoe UI", 10, "bold"), background=light, foreground=fg)
        s.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        s.configure("TFrame", background=bg)
        s.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        s.configure("H.TLabel", font=("Segoe UI", 12, "bold"))
        s.configure("TButton", font=("Segoe UI", 10), padding=6, background=T["btn"], foreground=fg)
        s.map("TButton", background=[("active", T["accent_active"])], foreground=[("active", "white")])
        s.configure("Accent.TButton", background=ACCENT, foreground="white")
        s.map("Accent.TButton", background=[("active", T["accent_active"])], foreground=[("active", "white")])
        s.configure("TCheckbutton", background=bg, foreground=fg)
        s.configure("TRadiobutton", background=bg, foreground=fg)
        s.configure("TEntry", fieldbackground=card, foreground=fg)
        s.configure("TSpinbox", fieldbackground=card, foreground=fg)
        s.configure("Treeview", rowheight=26, font=("Segoe UI", 10), background=card, fieldbackground=card, foreground=fg)
        s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background=ACCENT, foreground="white")

    def build(self):
        # Builds the purple header bar and the five tabs.
        top = tk.Frame(self, bg=ACCENT)
        top.pack(fill="x")
        tk.Label(top, text="  " + APP, bg=ACCENT, fg="white", font=("Segoe UI", 16, "bold")).pack(side="left", pady=10)
        # Shows "Tracking: ON" or "Tracking: PAUSED".
        self.status = tk.Label(top, bg=ACCENT, fg="white", font=("Segoe UI", 10))
        self.status.pack(side="right", padx=14)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabs = {}
        for name in ("Dashboard", "Checkpoints", "Usage History", "Files Used", "Settings", "Features"):
            self.tabs[name] = ttk.Frame(self.notebook)
            self.notebook.add(self.tabs[name], text=name)
        self.build_dashboard(self.tabs["Dashboard"])
        self.build_checkpoints(self.tabs["Checkpoints"])
        self.build_history(self.tabs["Usage History"])
        self.build_files(self.tabs["Files Used"])
        self.build_settings(self.tabs["Settings"])
        self.build_features(self.tabs["Features"])
        # Reload the data whenever the user switches tabs.
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def on_tab_change(self, _=None):
        # Loads fresh data for the tab that was just opened.
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
        # Four stat cards, a chart canvas (today / 7 days / 4 weeks) and a table of recent checkpoints.
        cards = ttk.Frame(f)
        cards.pack(fill="x", padx=10, pady=10)
        self.stat, self.stat_boxes = {}, []
        for key in ("Tracked today", "Idle today", "Apps used today", "Last active app"):
            box = tk.Frame(cards, bg=T["card"], highlightthickness=1, highlightbackground=T["light"])
            box.pack(side="left", expand=True, fill="both", padx=6)
            title = tk.Label(box, text=key, bg=T["card"], fg=T["fg"], font=("Segoe UI", 10))
            title.pack(pady=(10, 0))
            self.stat[key] = tk.Label(box, text="-", bg=T["card"], fg=T["accent_fg"],
                                      font=("Segoe UI", 18, "bold"), wraplength=240)
            self.stat[key].pack(pady=(2, 10))
            self.stat_boxes.append((box, title))
        # Chart title on the left and the chart switch on the right.
        head = ttk.Frame(f)
        head.pack(fill="x", padx=12)
        self.chart_title = ttk.Label(head, text="Top apps today", style="H.TLabel")
        self.chart_title.pack(side="left")
        self.chart_mode = tk.StringVar(value="apps")
        for text, value in (("Last 4 weeks", "weekly"), ("Last 7 days", "daily"), ("Today", "apps")):
            ttk.Radiobutton(head, text=text, value=value, variable=self.chart_mode,
                            command=self.refresh_dashboard).pack(side="right", padx=6)
        # The bar chart is drawn by hand on this canvas.
        self.bars = tk.Canvas(f, bg=T["card"], height=230, highlightthickness=1, highlightbackground=T["light"])
        self.bars.pack(fill="x", padx=12, pady=6)
        ttk.Label(f, text="Recent checkpoints", style="H.TLabel").pack(anchor="w", padx=12)
        self.dash_cp = ttk.Treeview(f, columns=("time", "project", "note"), show="headings", height=4)
        for col, w in (("time", 140), ("project", 160), ("note", 500)):
            self.dash_cp.heading(col, text=col.title())
            self.dash_cp.column(col, width=w, anchor="w")
        self.dash_cp.pack(fill="x", padx=12, pady=6)

    def refresh_dashboard(self):
        # Reads today's data from the database and updates the cards, chart and table.
        day = date.today().isoformat()
        rows = self.db.query("SELECT app, seconds FROM usage WHERE day=? AND " + SYS_CLAUSE +
                             " ORDER BY seconds DESC", (day,) + SYSTEM_APPS)
        idle = self.db.query("SELECT seconds FROM usage WHERE day=? AND app=?", (day, IDLE))
        t = self.tracker
        self.stat["Tracked today"].config(text=fmt_secs(sum(r[1] for r in rows)))
        self.stat["Idle today"].config(text=fmt_secs(idle[0][0] if idle else 0))
        self.stat["Apps used today"].config(text=str(len(rows)))
        self.stat["Last active app"].config(text="Paused" if t.paused else ("Idle" if t.is_idle else t.current[0]))
        self.status.config(text="Tracking: " + ("PAUSED" if t.paused else "ON"))
        self.pause_btn.config(text="Start tracking" if t.paused else "Pause tracking")

        self.draw_chart(rows)
        clear_tree(self.dash_cp)
        cps = self.db.query("SELECT ts, project, note FROM checkpoints ORDER BY id DESC LIMIT 4")
        if not cps:
            self.dash_cp.insert("", "end", values=("", "", "No checkpoints yet. Use the Checkpoints tab."))
        for ts, project, note in cps:
            self.dash_cp.insert("", "end", values=(ts, project, (note or "").replace("\n", " ")[:90]))

    def draw_chart(self, rows):
        # Draws the dashboard chart: top apps today, daily usage (7 days) or weekly usage (4 weeks).
        c, mode, fg = self.bars, self.chart_mode.get(), T["fg"]
        c.delete("all")
        if mode == "apps":
            self.chart_title.config(text="Top apps today")
            if not rows:
                c.create_text(20, 20, anchor="nw", fill=fg, text="No data yet - use some apps.")
                return
            # The app with the most seconds gets the full bar width.
            top = rows[0][1] or 1
            # Show only the top 8 apps.
            for i, (app, secs) in enumerate(rows[:8]):
                y = 10 + i * 27
                # Bar width is proportional to the seconds.
                width = max(4, int(secs / top * 430))
                c.create_text(10, y + 11, anchor="w", text=app, fill=fg, font=("Segoe UI", 9))
                c.create_rectangle(170, y, 170 + width, y + 22, fill=ACCENT, outline="")
                c.create_text(178 + width, y + 11, anchor="w", text=fmt_secs(secs), fill=fg, font=("Segoe UI", 9))
            return
        days = 7 if mode == "daily" else 28
        start = date.today() - timedelta(days=days - 1)
        # Seconds per day over the period, with system apps and idle time left out.
        data = dict(self.db.query("SELECT day, SUM(seconds) FROM usage WHERE day >= ? AND " + SYS_CLAUSE +
                                  " GROUP BY day", (start.isoformat(),) + SYSTEM_APPS))
        if mode == "daily":
            self.chart_title.config(text="Daily usage - last 7 days")
            cols = []
            for i in range(7):
                d = start + timedelta(days=i)
                cols.append((d.strftime("%a %d"), data.get(d.isoformat(), 0)))
        else:
            self.chart_title.config(text="Weekly usage - last 4 weeks")
            cols = []
            for w in range(4):
                first = start + timedelta(days=7 * w)
                last = first + timedelta(days=6)
                total = sum(data.get((first + timedelta(days=i)).isoformat(), 0) for i in range(7))
                cols.append(("%s - %s" % (first.strftime("%d %b"), last.strftime("%d %b")), total))
        peak = max(v for _, v in cols)
        if peak <= 0:
            c.create_text(20, 20, anchor="nw", fill=fg, text="No data in this period yet.")
            return
        width, base = max(c.winfo_width(), 640), 200
        slot = (width - 40) / len(cols)
        c.create_line(20, base, width - 20, base, fill=T["light"])
        for i, (label, secs) in enumerate(cols):
            x0, x1 = 30 + i * slot + slot * 0.18, 30 + i * slot + slot * 0.82
            top = base - max(2, int(secs / peak * 150)) if secs else base - 2
            c.create_rectangle(x0, top, x1, base, fill=ACCENT, outline="")
            c.create_text((x0 + x1) / 2, top - 9, text=fmt_secs(secs) if secs else "0", fill=fg, font=("Segoe UI", 9))
            c.create_text((x0 + x1) / 2, base + 14, text=label, fill=fg, font=("Segoe UI", 9))
        total = sum(v for _, v in cols)
        c.create_text(10, 6, anchor="nw", fill=fg, font=("Segoe UI", 9),
                      text="Total %s    Average per day %s" % (fmt_secs(total), fmt_secs(total / days)))

    # ---- checkpoints
    def build_checkpoints(self, f):
        # Entry form, search bar and the table of saved checkpoints.
        form = ttk.Frame(f)
        form.pack(fill="x", padx=12, pady=10)
        ttk.Label(form, text="Project / Work name").pack(anchor="w")
        self.cp_project = ttk.Entry(form, width=60)
        self.cp_project.pack(fill="x", pady=(0, 6))
        ttk.Label(form, text="Note (what you were doing)").pack(anchor="w")
        self.cp_note = tk.Text(form, height=3, font=("Segoe UI", 10), bg=T["card"], fg=T["fg"], insertbackground=T["fg"])
        self.cp_note.pack(fill="x", pady=(0, 6))
        ttk.Label(form, text="Next step (to resume later)").pack(anchor="w")
        self.cp_next = tk.Text(form, height=2, font=("Segoe UI", 10), bg=T["card"], fg=T["fg"], insertbackground=T["fg"])
        self.cp_next.pack(fill="x", pady=(0, 6))
        ttk.Button(form, text="Save checkpoint", style="Accent.TButton", command=self.save_checkpoint).pack(anchor="w")

        bar = ttk.Frame(f)
        bar.pack(fill="x", padx=12)
        ttk.Label(bar, text="Search:").pack(side="left")
        self.cp_search = tk.StringVar()
        # The table is filtered live while the user types.
        self.cp_search.trace_add("write", lambda *a: self.load_checkpoints())
        ttk.Entry(bar, textvariable=self.cp_search, width=35).pack(side="left", padx=6)
        ttk.Button(bar, text="Open / Resume", command=self.open_checkpoint).pack(side="right")
        ttk.Button(bar, text="Delete", command=self.delete_checkpoint).pack(side="right", padx=6)

        self.cp_tree = ttk.Treeview(f, columns=("id", "time", "project", "note"), show="headings", height=9)
        for col, w in (("id", 40), ("time", 140), ("project", 160), ("note", 480)):
            self.cp_tree.heading(col, text=col.title())
            self.cp_tree.column(col, width=w, anchor="w")
        self.cp_tree.pack(fill="both", expand=True, padx=12, pady=8)
        # Double-clicking a row opens it.
        self.cp_tree.bind("<Double-1>", lambda e: self.open_checkpoint())
        self.load_checkpoints()

    def save_checkpoint(self):
        # Saves the form values together with the current context (recent apps).
        project = self.cp_project.get().strip()
        note = self.cp_note.get("1.0", "end").strip()
        nxt = self.cp_next.get("1.0", "end").strip()
        if not project and not note:
            return messagebox.showwarning(APP, "Please enter a project name or a note.")
        self.db.run("INSERT INTO checkpoints(ts, project, note, next_step, context) VALUES(?, ?, ?, ?, ?)",
                    (datetime.now().strftime("%Y-%m-%d %H:%M"), project, note, nxt,
                     json.dumps(self.tracker.context())))
        # Clear the form after saving.
        self.cp_project.delete(0, "end")
        self.cp_note.delete("1.0", "end")
        self.cp_next.delete("1.0", "end")
        self.load_checkpoints()
        self.refresh_dashboard()
        messagebox.showinfo(APP, "Checkpoint saved.")

    def load_checkpoints(self):
        # Shows the checkpoints that match the search text.
        clear_tree(self.cp_tree)
        # SQL LIKE pattern built from the search box.
        term = "%" + self.cp_search.get().strip() + "%"
        rows = self.db.query("""SELECT id, ts, project, note FROM checkpoints
                                WHERE project LIKE ? OR note LIKE ? OR next_step LIKE ?
                                   OR context LIKE ? OR ts LIKE ? ORDER BY id DESC""", (term,) * 5)
        if not rows:
            self.cp_tree.insert("", "end", values=("", "", "", "No checkpoints yet. Fill the form above and click Save."))
        for cid, ts, project, note in rows:
            self.cp_tree.insert("", "end", values=(cid, ts, project, (note or "").replace("\n", " ")[:100]))

    def selected_id(self):
        # Returns the id of the selected row, or None if nothing valid is selected.
        sel = self.cp_tree.selection()
        values = self.cp_tree.item(sel[0])["values"] if sel else []
        if not values or values[0] == "":
            messagebox.showinfo(APP, "Please select a checkpoint first.")
            return None
        return values[0]

    def open_checkpoint(self):
        # Opens the resume window with the note, next step, keywords and similarity.
        cid = self.selected_id()
        if cid is None:
            return
        ts, project, note, nxt, context = self.db.query(
            "SELECT ts, project, note, next_step, context FROM checkpoints WHERE id=?", (cid,))[0]
        # Apps that were open when the checkpoint was saved.
        saved = json.loads(context or "[]")
        then_titles = [a.get("title", "") for a in saved]
        # Windows that are open right now.
        now_titles = [title for _, title in list(self.tracker.recent)]
        win = tk.Toplevel(self)
        win.title("Resume - " + (project or "checkpoint"))
        win.configure(bg=T["bg"])
        win.geometry("600x520")
        text = tk.Text(win, wrap="word", font=("Segoe UI", 10), padx=10, pady=10,
                       bg=T["card"], fg=T["fg"])
        text.pack(fill="both", expand=True, padx=10, pady=10)
        # The keywords (TF-IDF) and similarity (cosine) helpers are used here.
        body = ("Context only - apps are NOT reopened.\n\n"
                "Project : %s\nSaved   : %s\n\nNOTE\n%s\n\nNEXT STEP\n%s\n\n"
                "Keywords then : %s\nSimilarity with current windows: %d%%\n\nAPPS OPEN AT THAT TIME\n"
                % (project, ts, note or "-", nxt or "-", ", ".join(keywords(then_titles)) or "-",
                   similarity(then_titles, now_titles)))
        body += "".join("  - %s  |  %s\n" % (a.get("app"), a.get("title")) for a in saved) or "  (none recorded)\n"
        text.insert("1.0", body)
        # Make the text read-only.
        text.config(state="disabled")

    def delete_checkpoint(self):
        # Deletes the selected checkpoint after confirmation.
        cid = self.selected_id()
        if cid is not None and messagebox.askyesno(APP, "Delete this checkpoint?"):
            self.db.run("DELETE FROM checkpoints WHERE id=?", (cid,))
            self.load_checkpoints()
            self.refresh_dashboard()

    # ---- usage history and files used
    def filter_row(self, parent, fields, on_show, extra=()):
        # Reusable filter bar with labeled entry boxes, a Show button and optional extra buttons.
        bar = ttk.Frame(parent)
        bar.pack(fill="x", padx=12, pady=10)
        for i, (label, var) in enumerate(fields):
            ttk.Label(bar, text=label).grid(row=0, column=i, sticky="w", padx=8)
            entry = ttk.Entry(bar, textvariable=var, width=18)
            entry.grid(row=1, column=i, padx=8)
            # Pressing Enter works the same as clicking Show.
            entry.bind("<Return>", lambda e: on_show())
        ttk.Button(bar, text="Show", style="Accent.TButton", command=on_show).grid(row=1, column=len(fields), padx=8)
        for j, (text, command) in enumerate(extra, start=1):
            ttk.Button(bar, text=text, command=command).grid(row=1, column=len(fields) + j, padx=4)

    def search_all_days(self, from_var, to_var, table, loader):
        # Sets the date range from the first recorded day to today and runs the search.
        first = self.db.query("SELECT MIN(day) FROM " + table)[0][0]
        from_var.set(first or date.today().isoformat())
        to_var.set(date.today().isoformat())
        loader()

    def history_all_days(self):
        self.search_all_days(self.h_from, self.h_to, "usage", self.load_history)

    def files_all_days(self):
        self.search_all_days(self.f_from, self.f_to, "titles", self.load_files)

    def build_history(self, f):
        # Usage History tab: date range and app filter above a results table.
        today = date.today().isoformat()
        self.h_from, self.h_to, self.h_app = tk.StringVar(value=today), tk.StringVar(value=today), tk.StringVar()
        self.filter_row(f, [("From (YYYY-MM-DD)", self.h_from), ("To", self.h_to), ("App contains", self.h_app)],
                        self.load_history, extra=[("All days", self.history_all_days)])
        self.h_total = ttk.Label(f, text="", style="H.TLabel")
        self.h_total.pack(anchor="w", padx=12)
        self.h_tree = ttk.Treeview(f, columns=("day", "app", "time"), show="headings")
        for col, w in (("day", 140), ("app", 360), ("time", 160)):
            self.h_tree.heading(col, text=col.title())
            self.h_tree.column(col, width=w, anchor="w")
        self.h_tree.pack(fill="both", expand=True, padx=12, pady=8)

    def load_history(self):
        # Shows the usage rows that match the date range and the app filter.
        clear_tree(self.h_tree)
        rows = self.db.query("SELECT day, app, seconds FROM usage WHERE day BETWEEN ? AND ? AND app LIKE ? "
                             "AND " + SYS_CLAUSE + " ORDER BY day DESC, seconds DESC",
                             (self.h_from.get().strip(), self.h_to.get().strip(),
                              "%" + self.h_app.get().strip() + "%") + SYSTEM_APPS)
        for day, app, secs in rows:
            self.h_tree.insert("", "end", values=(day, app, fmt_secs(secs)))
        self.h_total.config(text="Total: " + fmt_secs(sum(r[2] for r in rows)))

    def build_files(self, f):
        # Files Used tab: date range and text filter above a results table.
        today = date.today().isoformat()
        self.f_from, self.f_to, self.f_text = tk.StringVar(value=today), tk.StringVar(value=today), tk.StringVar()
        self.filter_row(f, [("From (YYYY-MM-DD)", self.f_from), ("To", self.f_to),
                            ("App or file name contains", self.f_text)], self.load_files,
                        extra=[("Search all days", self.files_all_days)])
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
        # Shows window titles (files) that match the filters, up to 1000 rows.
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
        days = len({r[0] for r in rows})
        note = "  (first 1000 shown)" if len(rows) == 1000 else ""
        self.f_total.config(text="%d files / windows on %d day(s), total %s%s"
                            % (len(rows), days, fmt_secs(sum(r[3] for r in rows)), note))

    # ---- settings
    def build_settings(self, f):
        # Settings tab: tracking options, password and lock options, export and backup buttons.
        # Layout options shared by most widgets on this tab.
        pad = dict(padx=14, pady=4, anchor="w")
        ttk.Label(f, text="Tracking", style="H.TLabel").pack(**pad)
        row = ttk.Frame(f)
        row.pack(**pad)
        self.pause_btn = ttk.Button(row, text="Pause tracking", style="Accent.TButton", command=self.toggle_tracking)
        self.pause_btn.pack(side="left")
        ttk.Label(row, text="   Mark as idle after (minutes):").pack(side="left")
        self.idle_var = tk.IntVar(value=int(self.db.get("idle_minutes", "3")))
        ttk.Spinbox(row, from_=1, to=60, width=4, textvariable=self.idle_var, command=self.set_idle).pack(side="left", padx=4)
        self.idle_var.trace_add("write", lambda *a: self.set_idle())
        self.autostart_var = tk.BooleanVar(value=self.db.get("autostart") == "1")
        ttk.Checkbutton(f, text="Start ContextMind when Windows starts", variable=self.autostart_var,
                        command=self.toggle_autostart).pack(**pad)
        self.titles_var = tk.BooleanVar(value=self.db.get("track_titles", "1") == "1")
        ttk.Checkbutton(f, text="Record file / window names (Files Used tab)", variable=self.titles_var,
                        command=self.toggle_titles).pack(**pad)
        self.dark_var = tk.BooleanVar(value=self.db.get("dark_mode") == "1")
        ttk.Checkbutton(f, text="Dark mode", variable=self.dark_var, command=self.toggle_dark).pack(**pad)

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
        ttk.Label(f, text="Window X button minimizes the app (tracking continues).", foreground="#7a6a9a").pack(**pad)
        ttk.Button(f, text="Exit ContextMind completely", command=self.quit_app).pack(**pad)
        ttk.Label(f, text="Data folder: " + DATA_DIR, foreground="#7a6a9a").pack(**pad)

    def toggle_tracking(self):
        # Switches between paused and running, and saves the choice.
        self.tracker.paused = not self.tracker.paused
        self.db.set("paused", int(self.tracker.paused))
        self.refresh_dashboard()

    def set_idle(self):
        # Saves the idle minutes setting and applies it to the tracker immediately.
        try:
            minutes = max(1, int(self.idle_var.get()))
        except (ValueError, tk.TclError):
            return
        self.db.set("idle_minutes", minutes)
        self.tracker.idle_limit = minutes * 60

    def save_lock_settings(self):
        # Saves the auto-lock options.
        try:
            minutes = max(1, int(self.lock_min.get()))
        except (ValueError, tk.TclError):
            return
        self.db.set("lock_idle_minutes", minutes)
        self.db.set("lock_idle", int(self.lock_var.get()))

    def toggle_titles(self):
        # Turns window title recording on or off.
        on = self.titles_var.get()
        self.db.set("track_titles", int(on))
        self.tracker.track_titles = on
        self.load_files()

    def toggle_autostart(self):
        # Adds or removes the app from the Windows startup list in the registry.
        on = self.autostart_var.get()
        if not IS_WIN:
            messagebox.showinfo(APP, "This option works on Windows only.")
            self.autostart_var.set(False)
            return
        # Windows registry module, imported only when needed.
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            if on:
                # When packaged by PyInstaller the program is frozen and runs as an EXE.
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
        # A dict is used so the inner function can store the result.
        result = {"value": None}
        win = tk.Toplevel(self)
        win.title(APP)
        win.configure(bg=T["bg"])
        win.resizable(False, False)
        tk.Label(win, text=prompt, bg=T["bg"], fg=T["fg"], font=("Segoe UI", 10)).pack(padx=20, pady=(16, 6))
        entry = tk.Entry(win, show="*", width=28, font=("Segoe UI", 11))
        entry.pack(padx=20, pady=4)

        def ok(_=None):
            result["value"] = entry.get()
            win.destroy()

        row = tk.Frame(win, bg=T["bg"])
        row.pack(pady=12)
        tk.Button(row, text="OK", width=9, bg=ACCENT, fg="white", command=ok).pack(side="left", padx=5)
        tk.Button(row, text="Cancel", width=9, command=win.destroy).pack(side="left", padx=5)
        win.bind("<Return>", ok)
        win.bind("<Escape>", lambda e: win.destroy())
        win.attributes("-topmost", True)
        win.grab_set()
        entry.focus_force()
        # Block here until the dialog is closed.
        self.wait_window(win)
        return result["value"]

    def change_password(self):
        # Verifies the current password, then asks for a new one twice and saves it.
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
        # Removes the password after the current one is verified.
        if not self.db.has_password():
            return
        current = self.ask_secret("Current password:")
        if current is not None and self.db.check_password(current):
            self.db.set_password("")
            messagebox.showinfo(APP, "Password removed.")
        else:
            messagebox.showerror(APP, "Wrong password.")

    def first_run_prompt(self):
        # On the first launch only, offers to set a password.
        if self.db.get("asked_pw") == "1" or self.db.has_password():
            return
        self.db.set("asked_pw", "1")
        if messagebox.askyesno(APP, "A password is needed for the lock screen.\nSet one now?"):
            self.change_password()

    # ---- lock flow
    def seconds_left(self):
        # Seconds remaining in the current lockout, or 0 if there is none.
        return max(0, int(self.locked_until - time.time() + 0.999))

    def show_lock(self, reason):
        # Opens the lock screen, but only when a password exists.
        if self.lock_win is not None:
            return
        if not self.db.has_password():
            if reason == "manual":
                messagebox.showinfo(APP, "Please set a password first.")
            return
        snapshot = self.prev_snapshot if reason == "startup" else (self.tracker.snapshot() or self.prev_snapshot)
        # Remember whether the window was visible so it can be restored after unlocking.
        self.was_normal = self.state() == "normal"
        self.withdraw()
        try:
            self.lock_win = LockScreen(self, reason, snapshot)
        except tk.TclError:
            logging.exception("lock screen")
            self.lock_win = None
            self.deiconify()

    def lock_closed(self, reason):
        # Called after the lock screen is unlocked. Restores the main window.
        self.lock_win = None
        # The unlock screen already showed the last checkpoint, so no resume popup is needed now.
        self.tracker.resume_event = None
        if reason == "startup":
            self.deiconify()
            if self.start_minimized:
                self.iconify()
            # The user has unlocked, so offer to reopen the programs of the last session.
            self.after(400, self.offer_restore)
        elif self.was_normal:
            self.deiconify()

    # ---- export and backup
    def export_csv(self, name, header, query):
        # Generic CSV export: ask for a file path, write the header, then write the query rows.
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=name,
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        # utf-8-sig lets Excel open the file with the correct encoding.
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(header)
            writer.writerows(self.db.query(query))
        messagebox.showinfo(APP, "Exported." + PRIVACY_NOTE)

    def export_usage(self):
        self.export_csv("contextmind_usage.csv", ["day", "app", "seconds"],
                        "SELECT day, app, seconds FROM usage ORDER BY day, app")

    def export_checkpoints(self):
        self.export_csv("contextmind_checkpoints.csv", ["id", "time", "project", "note", "next_step", "context"],
                        "SELECT id, ts, project, note, next_step, context FROM checkpoints")

    def export_files(self):
        self.export_csv("contextmind_files.csv", ["day", "app", "file_or_window", "seconds"],
                        "SELECT day, app, title, seconds FROM titles ORDER BY day, app")

    def export_json(self):
        # Exports usage, checkpoints and files into one JSON file.
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
        # Saves a full copy of the SQLite database.
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("SQLite", "*.db")],
                                            initialfile="contextmind_backup_%s.db" % date.today().isoformat())
        if path:
            self.db.backup(path)
            messagebox.showinfo(APP, "Backup saved." + PRIVACY_NOTE)

    # ---- dark mode
    def toggle_dark(self):
        # Saves the dark mode choice and re-colors the window at once.
        self.db.set("dark_mode", int(self.dark_var.get()))
        self.apply_theme()

    def apply_theme(self):
        # Re-colors the whole main window after the dark mode switch changed.
        T.clear()
        T.update(DARK_T if self.db.get("dark_mode") == "1" else LIGHT_T)
        self.configure(bg=T["bg"])
        self.style()
        for box, title in self.stat_boxes:
            box.config(bg=T["card"], highlightbackground=T["light"])
            title.config(bg=T["card"], fg=T["fg"])
        for label in self.stat.values():
            label.config(bg=T["card"], fg=T["accent_fg"])
        self.bars.config(bg=T["card"], highlightbackground=T["light"])
        for box in (self.cp_note, self.cp_next):
            box.config(bg=T["card"], fg=T["fg"], insertbackground=T["fg"])
        self.refresh_dashboard()

    # ---- features tab (break reminder, resume popup, auto-restore)
    def build_features(self, f):
        pad = dict(padx=14, pady=6, anchor="w")
        self.remind_var = tk.BooleanVar(value=self.db.get("remind_on", "1") == "1")
        self.remind_min = tk.IntVar(value=int(self.db.get("remind_minutes", "60")))
        self.resume_var = tk.BooleanVar(value=self.db.get("resume_on", "1") == "1")
        self.restore_var = tk.BooleanVar(value=self.db.get("restore_on", "1") == "1")

        ttk.Label(f, text="Break reminder", style="H.TLabel").pack(**pad)
        row = ttk.Frame(f)
        row.pack(**pad)
        ttk.Checkbutton(row, text="Remind me to take a break after", variable=self.remind_var,
                        command=self.save_features).pack(side="left")
        ttk.Spinbox(row, from_=15, to=240, width=4, textvariable=self.remind_min,
                    command=self.save_features).pack(side="left", padx=4)
        self.remind_min.trace_add("write", lambda *a: self.save_features())
        ttk.Label(row, text="minutes of continuous work").pack(side="left")
        ttk.Label(f, text="A break of 5 minutes or more resets the counter.", foreground="#7a6a9a").pack(**pad)

        ttk.Label(f, text="Resume popup", style="H.TLabel").pack(**pad)
        ttk.Checkbutton(f, text="When I return from a break (5 min or more), show where I stopped and my next step",
                        variable=self.resume_var, command=self.save_features).pack(**pad)
        ttk.Label(f, text="Not shown when the lock screen is used, because the lock screen already shows it.",
                  foreground="#7a6a9a").pack(**pad)

        ttk.Label(f, text="Auto-restore last session", style="H.TLabel").pack(**pad)
        ttk.Checkbutton(f, text="After a restart, offer to reopen the programs I was using",
                        variable=self.restore_var, command=self.save_features).pack(**pad)
        ttk.Button(f, text="Restore previous session now", command=lambda: self.offer_restore(force=True)).pack(**pad)
        ttk.Label(f, text="Programs are reopened only after you unlock and approve them. File names and tabs are\n"
                          "not restored by ContextMind: VS Code and Chrome reopen their own last workspace and tabs.",
                  foreground="#7a6a9a", justify="left").pack(**pad)

    def save_features(self):
        # Saves the feature options and applies them to the tracker immediately.
        try:
            minutes = max(15, int(self.remind_min.get()))
        except (ValueError, tk.TclError):
            return
        self.db.set("remind_on", int(self.remind_var.get()))
        self.db.set("remind_minutes", minutes)
        self.db.set("resume_on", int(self.resume_var.get()))
        self.db.set("restore_on", int(self.restore_var.get()))
        self.tracker.remind_on = self.remind_var.get()
        self.tracker.remind_secs = minutes * 60

    def popup(self, title, attr):
        # Creates a small always-on-top popup window and remembers it in self.<attr> while it is open.
        win = tk.Toplevel(self)
        win.title(title)
        win.configure(bg=T["bg"])
        win.resizable(False, False)
        win.attributes("-topmost", True)
        setattr(self, attr, win)

        def close():
            setattr(self, attr, None)
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", close)
        return win, close

    def check_notices(self):
        """Shows the break reminder and the resume popup that the tracker asked for."""
        t = self.tracker
        # While the lock screen is open the user is away or unlocking, so nothing is shown.
        if self.lock_win is not None:
            t.resume_event = None
            return
        event, t.resume_event = t.resume_event, None
        if event and self.db.get("resume_on", "1") == "1" and self.resume_win is None:
            self.show_resume_popup(*event)
        if t.remind_due and t.remind_on and self.remind_win is None:
            t.remind_due = False
            self.show_break_reminder()

    # ---- break reminder
    def show_break_reminder(self):
        minutes = int(self.tracker.work_secs // 60)
        win, close = self.popup("Take a break", "remind_win")
        tk.Label(win, text="Time for a break", bg=ACCENT, fg="white", font=("Segoe UI", 13, "bold"),
                 padx=20, pady=10).pack(fill="x")
        tk.Label(win, text="You have worked for %d minutes without a real break.\n"
                           "Stand up, stretch and rest your eyes." % minutes,
                 bg=T["bg"], fg=T["fg"], font=("Segoe UI", 10), padx=20, pady=14).pack()

        def took_break():
            self.tracker.work_secs = 0.0
            close()

        def snooze():
            # Remind again in 10 minutes.
            self.tracker.work_secs = max(0.0, self.tracker.remind_secs - 600)
            close()

        row = tk.Frame(win, bg=T["bg"])
        row.pack(pady=(0, 14))
        ttk.Button(row, text="OK, taking a break", style="Accent.TButton", command=took_break).pack(side="left", padx=6)
        ttk.Button(row, text="Snooze 10 min", command=snooze).pack(side="left", padx=6)
        win.protocol("WM_DELETE_WINDOW", took_break)
        win.bell()

    # ---- resume popup
    def show_resume_popup(self, kind, idle_secs):
        cp = self.db.query("SELECT ts, project, note, next_step FROM checkpoints ORDER BY id DESC LIMIT 1")
        apps = self.tracker.context(4)
        win, close = self.popup("Welcome back", "resume_win")
        tk.Label(win, text="Welcome back - %s (%s away)" % (kind, fmt_secs(idle_secs)), bg=ACCENT, fg="white",
                 font=("Segoe UI", 12, "bold"), padx=20, pady=10).pack(fill="x")
        lines = []
        if cp:
            ts, project, note, nxt = cp[0]
            lines += ["Last time you were on: %s  (saved %s)" % (project or "-", ago(ts) or ts),
                      "Note: %s" % (note or "-").replace("\n", " ")[:160],
                      "Next step: %s" % (nxt or "-").replace("\n", " ")[:160]]
        else:
            lines.append("No checkpoint saved yet. Save one in the Checkpoints tab before your next break.")
        if apps:
            lines += ["", "Apps you were using:"] + ["   %s  -  %s" % (a["app"], a["title"][:55]) for a in apps]
        tk.Label(win, text="\n".join(lines), bg=T["bg"], fg=T["fg"], justify="left", anchor="w",
                 wraplength=480, font=("Segoe UI", 10), padx=20, pady=14).pack(anchor="w")

        def open_checkpoints():
            self.deiconify()
            self.notebook.select(self.tabs["Checkpoints"])
            close()

        row = tk.Frame(win, bg=T["bg"])
        row.pack(pady=(0, 14))
        ttk.Button(row, text="Continue", style="Accent.TButton", command=close).pack(side="left", padx=6)
        ttk.Button(row, text="Open checkpoints", command=open_checkpoints).pack(side="left", padx=6)

    # ---- auto-restore last session
    def offer_restore(self, force=False):
        """Asks the user which programs of the previous session to reopen. Nothing starts without approval."""
        if self.restore_win is not None:
            return
        if not force and self.db.get("restore_on", "1") != "1":
            return
        apps = restorable(self.prev_session)[:15]
        if not apps:
            if force:
                messagebox.showinfo(APP, "Nothing to restore. The programs of the previous session are already open "
                                         "or no session was saved.")
            return
        win, close = self.popup("Restore last session?", "restore_win")
        tk.Label(win, text="Restore your last session?", bg=ACCENT, fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(fill="x")
        tk.Label(win, text="These programs were open before. Tick the ones to reopen.", bg=T["bg"], fg=T["fg"],
                 font=("Segoe UI", 10), padx=20, pady=8).pack(anchor="w")
        picks = []
        for item in apps:
            var = tk.BooleanVar(value=True)
            ttk.Checkbutton(win, text="%s  -  %s" % (item["app"], item["title"][:50]), variable=var).pack(anchor="w", padx=24)
            picks.append((item, var))

        def restore():
            chosen = [item for item, var in picks if var.get()]
            started = self.launch_apps(chosen)
            close()
            messagebox.showinfo(APP, "Reopened %d of %d program(s)." % (started, len(chosen)))

        row = tk.Frame(win, bg=T["bg"])
        row.pack(pady=14)
        ttk.Button(row, text="Restore selected", style="Accent.TButton", command=restore).pack(side="left", padx=6)
        ttk.Button(row, text="Skip", command=close).pack(side="left", padx=6)

    @staticmethod
    def launch_apps(apps):
        # Starts each program file. A program that cannot start is logged and skipped.
        started = 0
        for item in apps:
            try:
                subprocess.Popen([item["exe"]], cwd=os.path.dirname(item["exe"]) or None)
                started += 1
            except (OSError, ValueError):
                logging.exception("restore %s", item.get("exe"))
        return started

    # ---- loop and quit
    def tick(self):
        """Every 2 seconds: check idle lock, keep lock screen on top, refresh dashboard."""
        try:
            self.tick_count += 1
            if self.lock_win is not None:
                try:
                    # Keep the lock screen above every other window.
                    self.lock_win.lift()
                except tk.TclError:
                    self.lock_win = None
            # No lock screen yet: lock automatically when the idle limit is crossed.
            elif (self.db.get("lock_idle", "1") == "1" and self.db.has_password()
                  and idle_seconds() > int(self.db.get("lock_idle_minutes", "2")) * 60):
                if self.db.get("os_lock") == "1":
                    # Also lock the Windows session itself.
                    lock_windows()
                self.show_lock("idle")
            self.check_notices()
            # Refresh the dashboard every third tick, only while the window is visible.
            if self.tick_count % 3 == 0 and self.lock_win is None and self.state() == "normal":
                self.refresh_dashboard()
        except tk.TclError:
            # The window is closing.
            pass
        except Exception:
            logging.exception("tick")
        finally:
            # Schedule the next tick.
            self.after(2000, self.tick)

    def poll_show(self):
        """Brings the window to the front when a second launch signals it, without bypassing the lock screen."""
        try:
            if _show_event is not None and _wait_fn is not None and _wait_fn(_show_event, 0) == 0:
                if self.lock_win is not None:
                    # The lock screen cannot be skipped without the password.
                    self.lock_win.lift()
                else:
                    self.deiconify()
                    self.lift()
                    self.focus_force()
        except tk.TclError:
            pass
        finally:
            self.after(500, self.poll_show)

    def quit_app(self):
        # Full exit: save the snapshot, stop the tracker and close the window.
        if messagebox.askyesno(APP, "Exit ContextMind? Tracking will stop."):
            self.tracker.save_snapshot()
            self.tracker.stop()
            self.destroy()


# ---------------------------------------------------------------- 7. Startup
def setup_logging():
    # Writes errors to contextmind.log in the data folder.
    os.makedirs(DATA_DIR, exist_ok=True)
    logging.basicConfig(filename=LOG_PATH, level=logging.ERROR, format="%(asctime)s %(message)s")


def acquire_single_instance(minimized=False):
    """Returns True if this is the first instance. If the app is already running, signals it to show its window."""
    global _show_event, _wait_fn
    if not IS_WIN:
        return True
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Declare the argument and return types of the Windows API functions used below.
    k32.CreateMutexW.restype = wt.HANDLE
    k32.CreateMutexW.argtypes = [wt.LPVOID, wt.BOOL, wt.LPCWSTR]
    k32.OpenEventW.restype = wt.HANDLE
    k32.OpenEventW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
    k32.CreateEventW.restype = wt.HANDLE
    k32.CreateEventW.argtypes = [wt.LPVOID, wt.BOOL, wt.BOOL, wt.LPCWSTR]
    k32.SetEvent.argtypes = [wt.HANDLE]
    k32.WaitForSingleObject.restype = wt.DWORD
    k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    k32.CloseHandle.argtypes = [wt.HANDLE]
    # A named mutex allows only one owner. A second instance gets the "already exists" error.
    k32.CreateMutexW(None, False, "Local\\ContextMindSingleInstance")
    # 183 is ERROR_ALREADY_EXISTS, which means the app is already running.
    if ctypes.get_last_error() == 183:
        # An autostart launch (--minimized) must not pop the window up.
        if not minimized:
            # 0x0002 is EVENT_MODIFY_STATE.
            ev = k32.OpenEventW(0x0002, False, SHOW_EVENT_NAME)
            if ev:
                # Signal the running app to show its window.
                k32.SetEvent(ev)
                k32.CloseHandle(ev)
        return False
    # This is the first instance: create the auto-reset event that second launches will signal.
    _show_event = k32.CreateEventW(None, False, False, SHOW_EVENT_NAME)
    _wait_fn = k32.WaitForSingleObject
    return True


def report_crash(text):
    """Save the traceback to crash.txt and show it in a message box."""
    path = os.path.join(DATA_DIR, "crash.txt")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n=== %s ===\n%s" % (datetime.now().isoformat(), text))
    except OSError:
        path = "(could not save)"
    if IS_WIN:
        # 0x10 shows the error icon in the message box.
        ctypes.windll.user32.MessageBoxW(None, "ContextMind crashed.\n\n%s\n\nDetails: %s" % (text[-600:], path),
                                         APP, 0x10)
    else:
        print(text)


def main():
    # Entry point: set up logging, make sure only one instance runs, then start the UI.
    setup_logging()
    # The running app has been signaled, so this new process does not open a second window.
    if not acquire_single_instance("--minimized" in sys.argv):
        return
    # mainloop runs the UI event loop until the app is closed.
    App(start_minimized="--minimized" in sys.argv).mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Any unexpected crash is saved to crash.txt and shown in a message box.
        report_crash(traceback.format_exc())
        sys.exit(1)
