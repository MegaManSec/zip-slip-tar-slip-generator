# symlink / hard-link slip test corpus

Proof-of-concept archives that show link- and traversal-based path escapes
("zip slip" / "tar slip") in extractors. Inspired by
[justi.cz "Data exfiltration with CDNs"](https://justi.cz/security/2018/05/23/cdn-tar-oops.html).

Two formats, one per directory:

- `zip/` holds the ZIP archives, built by `zip/build-zips.py`.
- `tar/` holds the TAR archives, built by `tar/build-tars.py`. It mirrors the
  ZIP corpus and adds the hard-link case, which the ZIP format has no entry type
  to express.

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
- `hardlink-slip.tar` can only overwrite a file that already exists, because the
  hard link won't resolve otherwise. That is the one real difference: it is
  purely an overwrite, never a create.
- `exfil-slip` writes nothing dangerous itself. It leaves symlinks pointing at
  host files like `/etc/passwd`, and anything that later reads through them leaks
  the target.

None of this is theoretical. The "Zip Slip" disclosure (Snyk, 2018) affected
hundreds of libraries. The case and Unicode collision cases here mirror node-tar
CVE-2021-37712; arbitrary overwrite via symlink is CVE-2018-20834; and adm-zip's
`../` traversal is CVE-2018-1002204.

## Read / exfiltration (both formats)

| File | Technique |
|------|-----------|
| `exfil-slip` | Symlinks (`passwd` → `/etc/passwd`, `env` → `/proc/self/environ`, `root` → `/`) that survive extraction. No collision needed. When the output is later served or read, they leak arbitrary host files. |

## Write: baseline traversal (both formats)

| File | Technique |
|------|-----------|
| `dotdot-slip` | Plain `../` path traversal: entry named `../../../../../../tmp/PWNED.txt`. |
| `abs-slip` | Absolute path `/tmp/PWNED.txt`, for an extractor that doesn't strip a leading `/`. |
| `backslash-slip` | Windows backslash traversal `..\..\..\tmp\PWNED.txt`, for a sanitizer that only splits on `/`. |

## Write: symlink collisions (both formats)

A symlink points at `/tmp` and a `PWNED.txt` payload is written to a path that
collides with that symlink. An extractor that doesn't re-check the resolved path
writes through the symlink and lands `/tmp/PWNED.txt` outside the root.

| File | Technique |
|------|-----------|
| `toctou-slip` | TOCTOU cache poisoning. A real dir `d/sub/` is validated, then replaced by a symlink at `d/sub`, then written through. |
| `case-slip` | Case-insensitive collision: symlink `LINK` vs. path `link/`. |
| `unicode-slip` | Unicode NFC/NFD collision: `café` (composed) vs. `café` (decomposed). |
| `unicode-nfkc-slip` | Unicode NFKC compatibility collision: `ﬁle` (U+FB01 ligature) vs. `file`. |

## Write: hard-link overwrite (tar only)

| File | Technique |
|------|-----------|
| `hardlink-slip.tar` | Hard-link `hl` → `/tmp/VICTIM.txt`, then a regular file `hl` whose bytes are written through the link into the target. |

A hard link can't point at a directory, so unlike the symlink cases this
overwrites an existing file rather than writing through a symlinked dir.
Vulnerable `tar-fs` and `node-tar` versions created the link and then wrote the
colliding regular entry, overwriting an arbitrary existing file. ZIP has no
hard-link entry type, so there is no ZIP equivalent.

## Permission annoyance: read-only files (both formats)

| File | Technique |
|------|-----------|
| `readonly-slip` | A file extracted `0444` (Unix) and, in the ZIP, also via the DOS read-only attribute. `rm` prompts "remove write-protected file?" and needs `-f`; on Windows the read-only attribute must be cleared first. |

This is the closest an archive can get to a `chattr +i`-style "can't delete it"
file, but it is not kernel-enforced. `rm -f` removes it, and deletion still
depends on the parent directory being writable. No archive format can encode the
real Linux immutable flag, which is an inode flag set by ioctl rather than part
of the file mode.

## Testing an extractor safely

Extract each archive in a disposable directory and check that:

- no symlink pointing outside the target is created (the `exfil-slip` archives
  exist purely to test this), and
- no file lands outside the extraction root, so `/tmp/PWNED.txt` should not
  appear.

For `hardlink-slip.tar`, first create the victim so the link resolves:

```sh
echo original > /tmp/VICTIM.txt
# extract hardlink-slip.tar in a disposable dir
cat /tmp/VICTIM.txt   # should still print "original", not "PWNED"
```
