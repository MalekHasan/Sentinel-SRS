# ADR-0037: TalkBack, large text and high contrast

- Status: **Accepted** (Sprint 10; `apps/android`)
- Date: 2026-10-20
- Implements the "TalkBack, large text, high contrast pass" of [PHASE-A-ANDROID.md](../PHASE-A-ANDROID.md) (Sprint 10), towards SRS §12.4: "WCAG 2.2 AA, full keyboard navigation, Narrator/TalkBack support, high-contrast themes, English and Arabic with RTL layout".
- Amended 2026-10-22 for audit finding A-17 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)): Sentinel's screens are data-sensitive to accessibility services that are not tools.

## Context

Sentinel is for people who may be watched by someone close to them. Some of them use TalkBack, large text or more contrast, and they need the app as much as anyone.

The screens were built with Material 3 in Jetpack Compose. That gives much of this for free:
- text sizes in `sp`, which follow Android's font size;
- buttons and radio buttons that TalkBack names, with touch targets of at least 48 dp;
- text read in the screen's language, right to left in Arabic (S3.4).

A review of every screen found what was missing:
- **TalkBack users could not move by headings.** Screen and section titles were styled as titles but not marked as headings.
- **Tappable rows** (alerts, apps, recent connections) said nothing about what tapping does. Rows of one line of small text were about 16 dp high, under WCAG 2.2's 24 px minimum (2.5.8) and Android's 48 dp.
- **Changing statuses were silent.** Whether monitoring runs, what an Undo did, and how an export went change while the screen is open, and TalkBack did not read them out.
- **No high-contrast colours.** Android 14 lets the user ask for more colour contrast (Settings, Display, Colour contrast), and Sentinel's colours ignored it.
- **Large text was never tested.** No text is cut off on purpose (no `maxLines`, every screen scrolls), but nothing checked it.

## Decision

1. **Headings.** Every screen's title, and the title of every section on it, is a heading (`Modifier.asHeading()`), so TalkBack users can move between them.
2. **Tappable rows say what they open, and are large enough to hit** (`Modifier.opens(label)`):
   - TalkBack says "double-tap to open the alert" or "to see what this app did";
   - the row is at least 48 dp high, centred, and the whole of it responds.
3. **Statuses are announced** (`Modifier.announced()`, a polite live region): monitoring on, starting or off; what an Undo did; whether an export is being saved, was saved, or failed.
4. **High contrast follows Android's setting.** From Android 14, when the user sets colour contrast to medium or high (`UiModeManager.getContrast()` at 0.5 or more), Sentinel uses colour schemes of its own:
   - white or black backgrounds;
   - text that stands out at least 7:1 (WCAG AAA 1.4.6) in every pair the app uses, and outlines 4.5:1.
   - The theme follows the setting while the app is open. Before Android 14 there is no such setting to read.
   - Otherwise Material's own colours stay; every pair the app uses for text meets WCAG AA (4.5:1), and outlines 3:1.
5. **Large text is tested at 200%**, the largest Android offers: no text is cut, and none runs off the screen's width.

## Verification

On the Android 14 emulator (`AccessibilityTest`):
- the main screen's titles (the app's name, alerts, recent connections, gaps) are headings;
- the alert row and a connection row each carry their TalkBack label, are at least 48 dp high, and open what they say;
- the monitoring status and an export's result are live regions;
- at twice the text size, no text is cut or off the screen on the main screen, an alert, the export screen and "Keep monitoring running";
- in light and dark, standard and high contrast, each text pair the app uses (text, dialogs, text buttons, buttons, the four severity badges, errors) meets 4.5:1, or 7:1 in high contrast, and outlines 3:1, or 4.5:1;
- setting Android's colour contrast to high (`settings put secure contrast_level 1.0`) switches the open screen to high-contrast colours, and setting it back switches it back. Android may recreate the open screen when the contrast changes; the test's screen sets its own content, as Sentinel's do (`ThemeProbeActivity`, debug builds only), so it shows the colours either way.

## Accessibility services that are not tools (audit A-17)

Spyware often holds accessibility access, which ID-12 reports, and with it can read any screen and press its buttons: Allow on its own alert, End isolation, Wipe. From Android 14, Sentinel's windows and dialogs are data-sensitive (`setAccessibilityDataSensitive`): only accessibility services that declare themselves tools (`isAccessibilityTool`), as TalkBack and Switch Access do, can read and act on them. Other services see nothing of them. On every version, a touch made while another app's window covers Sentinel's is dropped (`filterTouchesWhenObscured`), and from Android 12 other apps' overlays are hidden while Sentinel's window shows (`setHideOverlayWindows`, with `HIDE_OVERLAY_WINDOWS`). `WindowGuardTest` checks both windows and dialogs, and that a tap marked as under another window does nothing.

A helper that is not a tool, such as a screen reader that does not declare itself one, can no longer read Sentinel from Android 14. Before Android 14 the guard is touches and overlays only. The guard also keeps Sentinel's screens out of screenshots and screen recordings ([ADR-0040](0040-other-apps-and-sentinels-screens.md), audit A-42).

## Consequences

- **Not done by hand yet:** a walk through every screen with TalkBack on, in English and in Arabic, on a real phone. The tests check the semantics TalkBack reads, not how it sounds. The usability sessions of Sprint 10 should include a TalkBack user.
- **Full keyboard navigation** (SRS §12.4) is not checked. Compose makes buttons and rows focusable, but the order and the focus indicator were not tested with a keyboard.
- **Android's "high contrast text"** (Accessibility settings) draws outlines around text in views. Whether Compose text follows it was not checked; the colour contrast setting above is the one Sentinel reads.
- **Only some screens are tested at 200%.** The others use the same building blocks (scrolling columns, wrapping text). A screen that adds a fixed height or `maxLines` should get the same check.
- **Notifications** are Android's own layouts, which follow the system's text size and contrast.
