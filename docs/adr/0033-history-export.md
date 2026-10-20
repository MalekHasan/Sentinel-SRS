# ADR-0033: Export of the history to JSON and CSV

- Status: **Accepted** (Sprint 9; `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements SRS §12.3, "Export of flows, alerts and actions to JSON and CSV", through the core interface's `Export(range, format)` (§14.2).
- Follows §15.2, "Exports are user-initiated only, with a warning that they contain sensitive data", and NF-11, "no user data leaves the device except what the user exports".

## Context

The history holds every connection with its app, alerts with their evidence, and the action journal (SRS §13). Some users want them outside the app:
- the power user of SRS §3, to study their own traffic in a spreadsheet;
- someone who wants to show what was found to a person who can help.

The history is encrypted on the phone (ADR-0009). An export is plain text, so it is only ever made at the user's request.

A phone keeps up to 30 days of connections, possibly hundreds of thousands, so an export must not need them all in memory at once.

## Decision

1. **The core exports one kind of record at a time**, as JSON or CSV, for a time range (from inclusive, to exclusive, Unix ms):
   - **flows:** the connections kept in full, by start time. Days already rolled up into totals (SRS §13.2) are not exported;
   - **alerts:** by the time raised;
   - **actions:** the journal, by the time taken.
2. **A page at a time.** `export_page(kind, format, from, to, after, limit)` returns at most `limit` records, oldest first, and where the next page starts.
   - The pages, written out in order, make one document: one JSON array, or one CSV table with a header row.
   - The app writes each page to the file the user chose and asks for the next. Nothing larger than a page is held, and no plain-text copy is kept on the phone by Sentinel.
3. **The contents:**
   - Times are ISO 8601 in UTC, to the millisecond.
   - Every field the history holds for the record is exported, under plain names (`bytes_up_while_away`, `hostname_source`).
   - Alert evidence and the journal's before and after states are exported as stored: JSON within JSON, or one quoted JSON cell in CSV. An alert this version cannot read is still exported.
   - Each alert also gets its app, as a column.
4. **CSV follows RFC 4180:** cells with commas, quotes or line breaks are quoted, quotes are doubled, and lines end with CRLF.
   - **CSV injection:** a text cell starting with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, so that a spreadsheet shows it as text and does not run it. Host names come from the network and could be made to start like a formula.
5. **Nothing is sent.** The export is a document the user saves where they choose.
6. **The Android screen** ("Export your history", from the main screen):
   - The user chooses what (connections, alerts or their actions), from when (the last 24 hours, the last 7 days, or everything kept) and the format (CSV for spreadsheets, JSON for programs).
   - The screen says that connections are kept one by one for 30 days, and that older days, kept only as totals, are not exported.
   - **Before the file is chosen, a warning:** the history is encrypted on the phone and the file is not; anyone who opens it can read which apps connected where and when, and what Sentinel found. Nothing happens unless the user goes on.
   - **Android's document picker** creates the file where the user chooses (`ACTION_CREATE_DOCUMENT`), so Sentinel needs no storage permission. The suggested name says what and when: `sentinel-connections-2026-10-20.csv`.
   - The pages, 500 records each, are written straight into that document on a thread of its own, which goes on if the user leaves the screen. Sentinel writes no copy anywhere else.
   - The screen says when the file is saved, with its size. A document left unfinished, for example because the place chosen ran out of space, is deleted, and the screen says the file could not be written.

## Verification

- `sentinel-store` (unit):
  - times, including a leap day and before 1970;
  - CSV cells: quoting, doubled quotes, line breaks, JSON, and formulas kept as text.
- `sentinel-store` (against a real encrypted database): flows, an alert and an action are recorded, and a flow the next day is outside the range.
  - For each kind and format, pages of 1, 2, 3 and 7 records join into exactly the document one page gives. With 7 records and pages of 7, the last page holds only the end of the document.
  - The JSON parses and holds each field.
  - The CSV has its header and one line per flow, and a host name like a formula is text.
  - An empty range gives `[]`, or a header alone.
- `sentinel-ffi`: two alerts export through the app's interface in pages of one and parse as one JSON array.
- On the Android 14 emulator (`ExportTest`):
  - five journalled actions, in pages of 1, 2 and 3, write exactly the document one page writes, in JSON and in CSV; the JSON has five records, the CSV a header and five lines;
  - an alert is in the last day's export now, not in it two days later, and still in the last week's and in everything;
  - saving writes the document and reports its size; a document that cannot be opened is reported as not written;
  - the file name;
  - the warning comes before the picker: cancelling it saves nothing, and going on saves what was chosen;
  - while an export is being written, another cannot start;
  - the main screen opens the screen.
- `RtlTest.export`: the screen, a saved export with its size, and the warning, in Arabic right to left.

The document picker itself is Android's and is not driven by the tests; the tests write to a file the same way.

## Consequences

- **Spreadsheets may misread non-Latin text in the CSV.** It is UTF-8 without a byte-order mark, as RFC 4180 tools expect; some spreadsheets assume another encoding unless told. Host names and package names are Latin; alert evidence and the journal may not be.
- **Rolled-up days are not in a flow export.** A user who wants more than the days kept in full has only the app's totals.
- **Gaps and sensor uses are not exported.** §12.3 names flows, alerts and actions; the others can be added as kinds later.
- **An export is plain text** wherever the user saves it. The warning says so; protecting it is then up to the user.
