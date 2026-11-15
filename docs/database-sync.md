# Manual database comparison

The desktop sidebar's **Database Sync** view compares unlocked databases with
the same Trove database UUID. Set this UUID through **Database metadata** on each
copy. Full database paths distinguish files with the same name.

Entries match by their KeePass UUID, not their title. The list shows changed
entries and entries present in only one copy. Enable **Show matching entries and
their history** to review entries with identical current content too.

Comparisons refresh every three seconds while the window is visible, and when
it regains focus. Every comparison, including opening the view and clicking
**Refresh comparison**, rereads and decrypts both database files and computes
their differences again. Sync does not reuse cached database contents or skip
reads based on file timestamps. Read or reload errors are shown instead of
presenting a stale comparison as current. Changing either database in the pair
starts a fresh comparison immediately, without waiting for the periodic refresh.

An entry's recycle-bin state is part of its comparison token. An active entry
and an otherwise identical recycled copy therefore appear as different. Choose
the active source version to restore the recycled target into the source folder.
A permanently deleted target can also be recreated with its original UUID.
Neither operation propagates deletions to the other database.

Select an entry to compare its fields, attachments, tags and entry settings.
Protected values stay hidden until explicitly revealed. Each side has a version
selector showing the current entry and the actual snapshots saved in that file's
KDBX history. Dates are information, not an automatic conflict-resolution rule.

**Use left version** copies the selected left version into the right database;
**Use right version** copies the selected right version into the left database.
The confirmation names the exact target path. Only applying that confirmation
writes the file. The source is unchanged. A historical selection therefore
restores that version in the target; it does not also roll back the source.

Each applied choice is saved to the target file before success is reported;
there is no queue waiting for the explicit Save button. Trove then rereads both
files and recomputes the remaining differences immediately, keeping the selected
database pair. A resolved entry disappears from the differences list and the
next remaining entry is selected. Saving locally does not confirm remote upload.

The entry detail toolbar's clock button opens the same comparison for a single
entry's local history, allowing an old snapshot to be restored as a new edit.

## First-iteration boundaries

- Choices apply whole entry versions, not individual fields. Attachments and
  their bytes, custom attributes, entry custom data and settings travel together.
- A target's displaced version is retained in its own history, subject to its
  normal KDBX history limits. The source's complete history is not automatically
  copied or combined with the target's history.
- A unique entry keeps its UUID and is created under its source folder path.
  An existing active target entry stays in its current folder. A recycled target
  restored from an active source returns to the source folder instead.
- Other folder moves, deletion propagation, database metadata and settings are
  not synchronized.
- Read-only databases can be compared and copied from, but not written to.
- Stale choices and files changed outside the application are rejected; reload
  the affected database and refresh the comparison before choosing again.

There is no automatic timestamp winner and no automatic background syncing.

## Saving to synchronized folders

Trove finishes encrypting the database in memory before creating its temporary
file, then writes, flushes and atomically replaces the local database. This avoids
leaving a header-only temporary file visible while key derivation runs, when a
file provider could upload that incomplete snapshot.

A successful local save does not confirm that a file provider has finished
uploading or that the server has the same bytes. If copies disagree, compare
their sizes and checksums before replacing either one; retain complete conflict
copies until recovery is verified.
