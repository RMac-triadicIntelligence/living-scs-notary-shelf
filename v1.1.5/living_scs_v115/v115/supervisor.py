"""supervisor.py - launches the notary and the organism (Living SCS v1.1.5). Trust root.

Launch discipline:
  1. verify the pinned sha256 of every file the notary will execute;
  2. copy them into a fresh private run directory, then verify the copies again
     (closes the check-then-use gap against the originals);
  3. start the notary from the copies, owned by the notary's uid, mode 0700.

Isolation modes:
  local      notary runs as the current user (equivalence lane; no attacker code)
  same-uid   notary and organism both run as ORGANISM_USER (non-root)
  split-uid  notary runs as NOTARY_USER, organism as ORGANISM_USER (requires root)
"""
import hashlib
import json
import os
import pwd
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wire  # noqa: E402

NOTARY_USER, ORGANISM_USER = "lscs_notary", "lscs_organism"
SOURCES = {"core.py": "v114/living_scs_v114/core.py", "lscs_harness.py": "v114/lscs_harness.py",
           "wire.py": "v115/wire.py", "notary.py": "v115/notary.py"}
PINS = {
        'core.py': '23299fdc63361e632b0f30cc686b09eb3e2a3bb70daf66f51b7378fb5a26baa6',
        'lscs_harness.py': '746fc5ee009a62b0641611227a353706f5030f320f6b2f0c0bbced36ea0d91e6',
        'notary.py': '6b854cfabcd8b2e275f5d3d67fa9b71b3fa909eb6cea057ecb45b11536e645d8',
        'wire.py': '3c5e1600624ad6ce56d4fe5ee93b36e18ef0da1e43cab7ba20ad714c79ae23d2',
}


class PinMismatch(Exception):
    pass


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def pins_for(root):
    return {name: sha256_file(os.path.join(root, rel)) for name, rel in SOURCES.items()}


def verify(paths, pins):
    for name, path in paths.items():
        if name not in pins:
            raise PinMismatch("%s: no pin" % name)
        got = sha256_file(path)
        if got != pins[name]:
            raise PinMismatch("%s: %s... != pinned %s..." % (name, got[:12], pins[name][:12]))


def ids(user):
    pw = pwd.getpwnam(user)
    return pw.pw_uid, pw.pw_gid


def chown_tree(path, uid, gid):
    for d, dirs, files in os.walk(path):
        os.chown(d, uid, gid)
        for f in files:
            os.chown(os.path.join(d, f), uid, gid)


def run_as(isolation, role):
    """Popen kwargs that drop to the role's uid, or {} for local mode."""
    if isolation == "local":
        return {}
    user = NOTARY_USER if (role == "notary" and isolation == "split-uid") else ORGANISM_USER
    uid, gid = ids(user)
    return {"user": uid, "group": gid, "extra_groups": []}


def _read_frame(fd, fb, timeout):
    deadline = time.time() + timeout
    while True:
        left = deadline - time.time()
        if left <= 0:
            raise TimeoutError("no reply")
        r, _, _ = select.select([fd], [], [], left)
        if not r:
            continue
        data = os.read(fd, 65536)
        if not data:
            raise EOFError("peer closed")
        frames = fb.feed(data)
        if frames:
            return wire.decode(frames[0])


class NotaryHandle:
    def __init__(self, root, cfg, isolation="local", pins=None, check_pins=True):
        pins = PINS if pins is None else pins
        originals = {n: os.path.join(root, rel) for n, rel in SOURCES.items()}
        if check_pins:
            verify(originals, pins)
        self.run = tempfile.mkdtemp(prefix="lscs_notary_")
        copies = {n: os.path.join(self.run, n) for n in SOURCES}
        for n in SOURCES:
            shutil.copyfile(originals[n], copies[n])
        if check_pins:
            verify(copies, pins)
        cfg_path = os.path.join(self.run, "config.json")
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        os.chmod(cfg_path, 0o600)
        os.chmod(self.run, 0o700)
        kw = run_as(isolation, "notary")
        if kw:
            chown_tree(self.run, kw["user"], kw["group"])
        org_req, org_resp, j_req, j_resp = os.pipe(), os.pipe(), os.pipe(), os.pipe()
        child = [org_req[0], org_resp[1], j_req[0], j_resp[1]]
        self.proc = subprocess.Popen(
            [sys.executable, copies["notary.py"], cfg_path, *map(str, child)],
            pass_fds=child, cwd=self.run, start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}, **kw)
        for fd in child:
            os.close(fd)
        self.org_w, self.org_r = org_req[1], org_resp[0]      # ends for whoever plays organism
        self.j_w, self.j_r = j_req[1], j_resp[0]
        self._jb = wire.FrameBuffer()
        hello = _read_frame(self.j_r, self._jb, 30)
        self.pid = hello["pid"]

    def judge(self, obj, timeout=30):
        os.write(self.j_w, wire.frame(wire.encode(obj)))
        return _read_frame(self.j_r, self._jb, timeout)

    def head(self):
        if self.proc.poll() is not None:
            return None
        try:
            return self.judge({"op": "head"})
        except (EOFError, TimeoutError, OSError):
            return None

    def release_organism_ends(self):
        for fd in (self.org_w, self.org_r):
            try:
                os.close(fd)
            except OSError:
                pass

    def shutdown(self):
        try:
            os.write(self.j_w, wire.frame(wire.encode({"op": "shutdown"})))
        except OSError:
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for fd in (self.j_w, self.j_r):
            try:
                os.close(fd)
            except OSError:
                pass
        shutil.rmtree(self.run, ignore_errors=True)


class OrgClient:
    """The organism's view of the notary: send a frame, read a frame."""

    def __init__(self, w, r):
        self.w, self.r, self.fb = w, r, wire.FrameBuffer()

    def raw(self, payload: bytes, timeout=30):
        os.write(self.w, wire.frame(payload))
        return _read_frame(self.r, self.fb, timeout)

    def request(self, obj, timeout=30):
        return self.raw(wire.encode(obj), timeout)


def spawn_organism(root, handle, isolation, attack_path, material, timeout=120):
    """Run attacker code inside a separate organism process; return its self-report."""
    kw = run_as(isolation, "organism")
    home = tempfile.mkdtemp(prefix="lscs_organism_")
    mpath = os.path.join(home, "material.json")
    material = dict(material); material["_notary_pid"] = handle.pid
    with open(mpath, "w") as f:
        json.dump(material, f)
    if kw:
        chown_tree(home, kw["user"], kw["group"])
    fds = [handle.org_w, handle.org_r]
    proc = subprocess.Popen(
        [sys.executable, os.path.join(root, "v115", "organism_runner.py"), attack_path, mpath, *map(str, fds)],
        pass_fds=fds, cwd=home, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HOME": home}, **kw)
    handle.release_organism_ends()
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, err = proc.communicate()
    shutil.rmtree(home, ignore_errors=True)
    report = None
    for line in reversed(out.decode("utf-8", "replace").splitlines()):
        if line.startswith("{"):
            try:
                report = json.loads(line)
                break
            except ValueError:
                pass
    return {"exit": proc.returncode, "report": report, "stderr": err.decode("utf-8", "replace")[-600:]}
