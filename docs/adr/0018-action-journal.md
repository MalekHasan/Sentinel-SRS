# ADR-0018: The action journal and undo on Android

- Status: **Accepted** (Sprint 6; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS §9 "Rules for actions" for Android ("Each action writes a journal entry: who, what, when, before-state, after-state, and how to undo it"), the §13.1 `action_journal` table, the §14.2 `UndoAction(journal_id)` call, and the §12.2 "journal of actions with Undo"

## Context

Sentinel's Android actions all change the firewall:
- blocking or allowing an app, a destination or a company, from an alert or the app detail screen (RA-01, [ADR-0015](0015-firewall-rules.md));
- taking a block back;
- switching the firewall mode (CM-08, [ADR-0016](0016-firewall-modes.md));
- isolating the phone and ending isolation (RA-03, [ADR-0017](0017-isolation.md)).

Each was reversible only by doing the opposite by hand, and some of them were not reversible that way at all:
- Switching Block new apps off and on again moves the time it counts from, so apps installed in between lose their "new" status.
- Ending isolation and isolating again moves when isolation began.
- Replacing a rule (allow instead of block) loses the earlier one.

The decision the firewall takes for each connection is not an action in this sense. SRS §9 allows it automatically in Block-unknown mode, and the history already records each blocked connection as blocked (`flow.verdict`).

## Decision

1. **An action changes one setting of the firewall:**
   - the rule about one app and destination, by its key;
   - the mode;
   - isolation.

   The journal keeps the setting's state before and after, as JSON (`sentinel_detect::Setting`). It also keeps the action's name, what undoes it, when, the actor and the alert it was taken from, in the SRS columns (schema version 14). The actor is always `user` on Android, where every action is the user's. Desktop editions will add the account.
2. **The change and its journal entry are written in one transaction**, so neither exists without the other. An action that changes nothing writes no entry:
   - keeping a rule that is already kept;
   - setting the mode in force;
   - isolating while isolated;
   - removing a rule that is not there.
3. **Undo puts the before-state back exactly**, the times Block new apps and isolation began included. It applies at once: the engine decides open connections again, as after any firewall change. The entry records when it was undone; undoing is not itself a new entry.
4. **Undo only while the setting is as the action left it.** If something changed the setting since, undoing would overwrite that later change, so it is refused ("changed since") and nothing changes. The journal says which actions can be undone now: in practice the latest action on each setting. Undoing that one makes the action before it on the same setting undoable, so a user can step back through a setting's history.
5. **The alert an action was taken from is kept** when it exists (`alert_id`, set to NULL if that alert is later deleted). This makes the incident report (SRS §12.3) possible later.
6. **"Your actions" on the main screen lists the journal**, newest first. Each action shows:
   - one sentence saying what it did;
   - when, and "From an alert" if it came from one;
   - an Undo button while it can be undone, and when it was undone if it was.

   Rules are described by the app's name, the domain or address, and "the company …".

## Verification

- `sentinel-detect`: each kind of setting is stored as fixed JSON and read back. Unreadable states are refused: a rule that does not match its key or would be refused when made, an unknown mode, Watch only with a start time, isolation with one of its two fields. A change is one setting from one state to another; each action has its name, and its undo is the opposite action.
- `sentinel-store`:
  - every change to the rules, the mode and isolation is journalled with the states before and after, when, `user`, and the alert if it exists; changes that change nothing are not; the journal is encrypted, survives reopening and is wiped with the history;
  - undo restores a new, a replaced and a removed rule, the mode with when Block-unknown began, and isolation with when it began. It refuses an action whose setting changed since, and an action already undone. Undoing the later action makes the earlier one undoable again.
- `sentinel-ffi`: an action taken from an alert keeps the alert. Undoing a block lets the app through at the next decision and signals running engines. The mode and isolation are back in force at once, isolation with when it began, also after reopening.
- On the Android 14 emulator (`JournalTest`):
  - blocking this app from an alert stops its request; the journal shows the action as from that alert, and tapping Undo lets the request through again;
  - after switching to Block new apps, isolating and ending isolation, the journal offers Undo on the latest action of each setting only; tapping Undo, newest first, brings isolation back with when it began, then ends it, then returns the mode to Watch only;
  - each kind of action is described in one sentence, with Undo only where it applies;
  - `RtlTest` shows the journal in Arabic, right to left.

## Consequences

- **The journal grows with every change.** SRS §13.2 keeps alerts and the journal for a year; neither has a retention step yet (Sprint 9).
- **A rule restored by undo counts as new**: its creation time is when it was restored, so it moves to the top of the list of rules.
- **Undo restores the setting, not the connections.** A connection that a block ended stays ended; the app's next connection gets through.
- **Only firewall actions exist on Android so far.** Later actions (RA-09, restoring DNS or proxy settings; RA-10, closing network ADB) will be journalled the same way, as new kinds of settings. Any that cannot be undone will have no `undo`.
