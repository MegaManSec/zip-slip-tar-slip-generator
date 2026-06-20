# symlink / hard-link slip test corpus

Proof-of-concept archives that show link- and traversal-based path escapes
("zip slip" / "tar slip") in extractors. Inspired by
[justi.cz "Data exfiltration with CDNs"](https://justi.cz/security/2018/05/23/cdn-tar-oops.html).

Four archive formats, one per directory, with a compression layer on top:

- `zip/` holds the ZIP archives, built by `zip/build-zips.py` (stdlib `zipfile`).
- `tar/` holds the TAR archives, built by `tar/build-tars.py` (stdlib `tarfile`).
  It mirrors the ZIP corpus and adds the hard-link case.
- `7z/` holds the 7-Zip archives, built by `7z/build-7zs.py`, which needs
  `pip install py7zr`. Like ZIP, 7-Zip has no hard-link entry type, so this
  directory mirrors the ZIP corpus.
- `rar/` holds the RAR5 archives, built by `rar/build-rars.py`. That script
  writes the RAR5 format by hand, because the free RAR tools only read archives
  and cannot create them. RAR5 is the only format besides tar that can express
  the hard-link case, so this directory carries the full corpus.
- `compress/` holds the `tar/` corpus wrapped in gzip, bzip2, xz, and zstd, built
  by `compress/build-compressed.sh`. See [Compression wrappers](#compression-wrappers-compress).

Each case gives the attacker either a write outside the extraction root (land
`/tmp/PWNED.txt`, or overwrite an existing file) or a read of host files (a
symlink left in the output that leaks whatever is later served from it).

## These are live payloads: run them in a throwaway environment

Against a vulnerable extractor these archives write or read outside the
extraction directory. As shipped, every case targets a throwaway path, so on a
clean machine nothing of yours is destroyed: the write cases land
`/tmp/PWNED.txt`, and the hard-link case overwrites `/tmp/VICTIM.txt`, the file
you create to test it. The danger is the primitive, not the shipped payload.
Each write case is an arbitrary write, so repointing one at a real path (a
dotfile, an SSH key, a sibling package's file) overwrites that file. Run tests
in a container, a VM, or some other disposable environment so a vulnerable
extractor can't reach anything real.

- The traversal and symlink-collision cases (`dotdot`, `abs`, `backslash`,
  `toctou`, `case`, `unicode`, `unicode-nfkc`) create the target file if it's
  absent and overwrite it if it's already there.
- `hardlink-slip.{tar,rar}` can only overwrite a file that already exists, because
  the hard link won't resolve otherwise. That is the one real difference: it is
  purely an overwrite, never a create.
- `exfil-slip` writes nothing dangerous itself. It leaves symlinks pointing at
  host files like `/etc/passwd`, and anything that later reads through them leaks
  the target.

None of this is theoretical. The "Zip Slip" disclosure (Snyk, 2018) affected
hundreds of libraries. The case and Unicode collision cases here mirror node-tar
CVE-2021-37712; arbitrary overwrite via symlink is CVE-2018-20834; adm-zip's
`../` traversal is CVE-2018-1002204; and the RAR symlink-traversal case is
unrar's CVE-2022-30333, exploited in the wild against Zimbra.

## Read / exfiltration

Leave a path behind that leaks a host file when the output is later served or
read. The symlink version works in every format; the hard-link version is tar
and rar only, since ZIP and 7-Zip have no hard-link entry type.

| File | Technique |
|------|-----------|
| `exfil-slip` | (all four formats) Symlinks (`passwd` → `/etc/passwd`, `env` → `/proc/self/environ`, `root` → `/`) that survive extraction. No collision needed. Leaks through any consumer that follows the symlink. |
| `hardlink-exfil-slip` | (tar and rar) A lone hard link `passwd` → `/etc/passwd`, with no second entry and no overwrite. The extracted name shares the target's inode, so it leaks even where symlinks are refused, because it is the file rather than a pointer to follow. Links within one filesystem only, and on Linux with `protected_hardlinks` on it needs an extractor that owns or can write the target, in practice one running as root. |

## Write: baseline traversal (all four formats)

| File | Technique |
|------|-----------|
| `dotdot-slip` | Plain `../` path traversal: entry named `../../../../../../tmp/PWNED.txt`. |
| `abs-slip` | Absolute path `/tmp/PWNED.txt`, for an extractor that doesn't strip a leading `/`. |
| `backslash-slip` | Windows backslash traversal `..\..\..\tmp\PWNED.txt`, for a sanitizer that only splits on `/`. |

## Write: symlink collisions (all four formats)

A symlink points at `/tmp` and a `PWNED.txt` payload is written to a path that
collides with that symlink. An extractor that doesn't re-check the resolved path
writes through the symlink and lands `/tmp/PWNED.txt` outside the root.

| File | Technique |
|------|-----------|
| `toctou-slip` | TOCTOU cache poisoning. A real dir `d/sub/` is validated, then replaced by a symlink at `d/sub`, then written through. |
| `case-slip` | Case-insensitive collision: symlink `LINK` vs. path `link/`. |
| `unicode-slip` | Unicode NFC/NFD collision: `café` (composed) vs. `café` (decomposed). |
| `unicode-nfkc-slip` | Unicode NFKC compatibility collision: `ﬁle` (U+FB01 ligature) vs. `file`. |

## Write: hard-link overwrite (tar and rar)

| File | Technique |
|------|-----------|
| `hardlink-slip.{tar,rar}` | Hard-link `hl` → `/tmp/VICTIM.txt`, then a regular file `hl` whose bytes are written through the link into the target. |

A hard link can't point at a directory, so unlike the symlink cases this
overwrites an existing file rather than writing through a symlinked dir.
Vulnerable `tar-fs` and `node-tar` versions created the link and then wrote the
colliding regular entry, overwriting an arbitrary existing file. TAR stores it as
a `LNKTYPE` entry and RAR5 as an `FHEXTRA_REDIR` hard-link record. ZIP and 7-Zip
have no hard-link entry type, so neither has an equivalent.

## Permission annoyance: read-only files (all four formats)

| File | Technique |
|------|-----------|
| `readonly-slip` | A file extracted `0444` (Unix), and in ZIP, 7-Zip, and RAR also via the DOS read-only attribute. `rm` prompts "remove write-protected file?" and needs `-f`; on Windows the read-only attribute must be cleared first. TAR has no DOS-attribute field, so its case is Unix-mode only. |

## Compression wrappers (`compress/`)

`compress/build-compressed.sh` wraps every `tar/` archive in gzip, bzip2, xz, and
zstd, producing `compress/{gz,bz2,xz,zst}/<case>.tar.<ext>`. Each variant
decompresses to the exact original `tar/<case>.tar`.

The compression layer is orthogonal to the slip primitive. It rewrites the byte
stream, not the archive semantics, so it adds no new attack. It tests one thing:
that an extractor's auto-decompress path (`tar xzf`, libarchive sniffing a magic
byte, a library that pipes through zlib then untars) still applies its
traversal/symlink checks after decompression. A checker that runs on `.tar` but
is skipped for `.tar.gz` is a real bug class.

This is also why there is no gzip corpus of its own. gzip is not an archive
format. It is one compressed stream of one file, with no entry names, links, or
directories, so it cannot express any of these cases by itself; every slip
primitive lives in the tar layer underneath a `.tar.gz`. The same holds for
bzip2, xz, and zstd.

## Testing an extractor safely

Extract each archive in a disposable directory and check that:

- no symlink pointing outside the target is created (the `exfil-slip` archives
  exist purely to test this), and
- no file lands outside the extraction root, so `/tmp/PWNED.txt` should not
  appear.

For `hardlink-slip.{tar,rar}`, first create the victim so the link resolves:

```sh
echo original > /tmp/VICTIM.txt
# extract hardlink-slip.tar (or .rar) in a disposable dir
cat /tmp/VICTIM.txt   # should still print "original", not "PWNED"
```

The `rar/toctou-slip.rar` directory entry is a valid no-data RAR5 directory
block, but libarchive before 3.8 (older `bsdtar`) rejects it with "no data found
in file/service block." Read the RAR corpus with a current `unrar`, p7zip, or
libarchive 3.8 or newer. This is a reader limitation, not a fault in the archive.
