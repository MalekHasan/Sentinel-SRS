# ADR-0033: Export of the history to JSON and CSV

- Status: **Accepted** (Sprint 9; `crates/sentinel-store`, `crates/sentinel-ffi`). The Android screen that uses it is still to come.
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
5. **Nothing is sent.** The export is a document the user saves where they choose. The app will ask first, saying that it holds sensitive data: which apps went where, and when.

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

## Consequences

- **The Android screen is not built yet.** It is to:
  - choose what and which format;
  - warn that the file holds sensitive data;
  - let the user choose where to save it (Android's document picker, so Sentinel needs no storage permission);
  - write the pages there.
- **Rolled-up days are not in a flow export.** A user who wants more than the days kept in full has only the app's totals.
- **Gaps and sensor uses are not exported.** §12.3 names flows, alerts and actions; the others can be added as kinds later.
- **An export is plain text** wherever the user saves it. The warning says so; protecting it is then up to the user.
