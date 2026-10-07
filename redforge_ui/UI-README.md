# RedForge dashboard (Flutter-web) — setup & deploy

A single-screen dashboard that visualizes a RedForge audit: the five-stage
pipeline (scout → strategist → PoC → remediation → verification), with a replay
animation and a detail panel per stage showing the findings, ranked hypotheses,
the generated exploit, the patch diff, and the Halmos-proved verification report.

**Showcase mode** (this build) loads the bundled `run.json` — no backend, no
Docker, no key — so it deploys to a URL anyone can open. **Live mode** (next
iteration) points the same screens at a local FastAPI SSE stream.

> I couldn't run the Flutter analyzer in my environment, so expect a few minor
> fixups — run `flutter analyze` and `dart format .` and fix anything it flags
> (most likely: `withOpacity` → `withValues` deprecation warnings on newer
> Flutter; they're warnings, not errors, and the app runs regardless).

## Files in this drop

```
pubspec.yaml            deps (flutter only) + assets: assets/run.json
lib/theme.dart          RedForge dark palette + text styles
lib/models.dart         parses the exported run.json (defensive)
lib/pipeline.dart       the 5-stage pipeline graph + replay states
lib/panels.dart         per-stage detail panels + code/diff blocks
lib/main.dart           app, header, replay controller, layout
```

## Setup (one-time)

Flutter must be installed with web enabled (`flutter config --enable-web`).

```bash
# 1. scaffold a Flutter project (generates web/, etc.)
flutter create --platforms web redforge_ui
cd redforge_ui

# 2. drop in the files from this zip, replacing the generated ones:
#    - replace lib/  (theme.dart, models.dart, pipeline.dart, panels.dart, main.dart)
#    - replace pubspec.yaml
#    - mkdir assets

# 3. provide the real run data (the exported verified run):
cp ../showcase/dvd-unstoppable-verified/run.json assets/run.json

flutter pub get
flutter analyze        # fix any nits
```

## Run locally

```bash
flutter run -d chrome
```
You should see: the RedForge header with a VERIFIED badge, the target/cost/time
stats, the five-stage pipeline (all complete by default), and the verification
panel showing the Halmos proof. Tap any stage to inspect it. Click **Replay
pipeline** to watch the stages light up in sequence (the real ~23-min timeline is
compressed to ~9s, proportional to each stage's real duration).

## Build & deploy the showcase (your shareable URL)

```bash
flutter build web --release
# deploy build/web/ to any static host:
#   Netlify:  drag build/web onto app.netlify.com, or `netlify deploy --dir build/web --prod`
#   Vercel:   `vercel build/web --prod`
#   GitHub Pages: push build/web to a gh-pages branch (set base href, see below)
```
For GitHub Pages under a repo subpath, build with the base href:
```bash
flutter build web --release --base-href /redforge/
```
Put the resulting URL in the README and pin it on the repo. That link is the
thing you share — it opens instantly, needs nothing installed, and shows the
whole pipeline.

## Optional: shrink the asset

`run.json` is ~1 MB because it carries all 1347 findings. The UI only shows the
top 8, so you can trim the bundled copy: keep everything except replace the big
`findings` array with just its top ~50 by severity (the `findingCount` for the
header can be preserved by keeping a count, or just leave the full array — 1 MB
is fine for a one-time load). Only bother if you want a snappier first paint.

## Design notes (so edits stay coherent)

- Default view = the finished, VERIFIED pipeline, with the verification panel
  open — a visitor sees the payoff immediately. Replay is opt-in.
- Ranking uses `priority` (the top hypothesis is 360). `confidence` is 0.0 in
  this checkpoint (saved before that field existed), so it's intentionally not
  shown.
- The Halmos proof line in the verification panel is shown as the headline proof;
  it reflects the real `halmos_proved: true` result.
- Colours: verified/pass = green, confirmed/patched = amber, mapped = blue,
  fail = red, forge-red accent throughout.

## Next: live mode (separate drop)

Add a thin FastAPI endpoint that runs an audit and streams graph events over SSE
in the SAME shape as `run.json`'s `events[]` plus the growing state. The Flutter
app gets a mode toggle: "Showcase" (bundled run.json) vs "Live" (connect to
`http://localhost:8000/audit/stream`). The widgets don't change — only the data
source. Scope that once the showcase is deployed and you've recorded the video.
