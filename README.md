# symlink zip-slip test corpus

Proof-of-concept ZIP archives that show symlink-based path traversal ("zip
slip") in extractors. Each archive contains a symlink whose name collides with
a later directory entry. An extractor that doesn't re-check the resolved path
writes a file through the symlink and escapes the extraction directory (here,
into `/tmp`).

In each archive, a symlink points at `/tmp` and a `PWNED.txt` payload is written
to a path that collides with that symlink. A vulnerable extractor ends up
creating `/tmp/PWNED.txt`.

| File | Technique |
|------|-----------|
| `toctou-slip.zip` | TOCTOU cache poisoning. A real dir `d/sub/` is validated, then replaced by a symlink at `d/sub`, then written through. |
| `case-slip.zip` | Case-insensitive collision: symlink `LINK` vs. path `link/`. |
| `unicode-slip.zip` | Unicode NFC/NFD collision: `café` (composed) vs. `café` (decomposed). |
| `unicode-nfkc-slip.zip` | Unicode NFKC compatibility collision: `ﬁle` (U+FB01 ligature) vs. `file`. |

## Testing an extractor safely

Extract each archive in a disposable directory and check that:

- no symlinks pointing outside the target are created, and
- no file lands outside the extraction root. `/tmp/PWNED.txt` should not appear.
