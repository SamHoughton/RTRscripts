#!/usr/bin/env bash
# =============================================================================
# macOS Browser History — RTR / IR Script
# IR Phase   : Identification
# Platform   : macOS 12+
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Extract recent browsing history from Safari, Chrome, and Firefox for all
#   user profiles. Useful for identifying phishing visits, C2 connections,
#   malware downloads, or attacker reconnaissance activity.
#
#   History databases are SQLite files; this script uses the sqlite3 binary
#   which ships with macOS. Results are limited to the last 7 days.
#
# USAGE
#   runscript -CloudFile="macos/artefact-collection/browser-history.sh"
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)
DAYS=7

echo "===== macOS BROWSER HISTORY ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo "Window   : Last $DAYS days"
echo ""

# Unix epoch cutoff: now minus DAYS
CUTOFF=$(date -v "-${DAYS}d" '+%s' 2>/dev/null || date -d "-${DAYS} days" '+%s' 2>/dev/null || echo 0)

# Helper: check sqlite3
if ! command -v sqlite3 &>/dev/null; then
  echo "[ERROR] sqlite3 not found — cannot query browser databases"
  exit 1
fi

# =============================================================================
# SECTION 1 — Safari
# History stored at: ~/Library/Safari/History.db (SQLite WAL mode)
# history_items: id, url; history_visits: id, history_item, visit_time (Mac epoch: seconds since 2001-01-01)
# Mac absolute time epoch offset = 978307200 seconds from Unix epoch
# =============================================================================
echo "===== SAFARI HISTORY ====="
SAFARI_FOUND=0

for USERDIR in /Users/*/; do
  USERNAME=$(basename "$USERDIR")
  DB="$USERDIR/Library/Safari/History.db"
  [ -f "$DB" ] || continue

  echo "  --- User: $USERNAME ---"
  # Copy to /tmp to avoid WAL lock issues
  TMPDB="/tmp/safari_hist_$$.db"
  cp "$DB" "$TMPDB" 2>/dev/null || { echo "  [!] Cannot copy $DB (permission denied)"; continue; }

  # visit_time in Safari uses Mac Absolute Time (CFAbsoluteTime): seconds since 2001-01-01
  # Convert to Unix: add 978307200
  CUTOFF_MAC=$((CUTOFF - 978307200))

  sqlite3 "$TMPDB" "
    SELECT
      datetime(v.visit_time + 978307200, 'unixepoch', 'localtime') AS visited,
      i.url
    FROM history_visits v
    JOIN history_items i ON v.history_item = i.id
    WHERE v.visit_time >= $CUTOFF_MAC
    ORDER BY v.visit_time DESC
    LIMIT 200;
  " 2>/dev/null | while IFS='|' read -r dt url; do
    echo "  [$dt]  $url"
  done || echo "  [!] Query failed"

  rm -f "$TMPDB"
  SAFARI_FOUND=$((SAFARI_FOUND+1))
done

[ "$SAFARI_FOUND" -eq 0 ] && echo "  No Safari history databases found"
echo ""

# =============================================================================
# SECTION 2 — Google Chrome / Chromium
# DB path: ~/Library/Application Support/Google/Chrome/<Profile>/History
# urls table: id, url, title, visit_count, last_visit_time (WebKit epoch: microseconds since 1601-01-01)
# Convert to Unix: subtract 11644473600 seconds, divide by 1000000
# =============================================================================
echo "===== CHROME HISTORY ====="
CHROME_FOUND=0

for USERDIR in /Users/*/; do
  USERNAME=$(basename "$USERDIR")
  BASE="$USERDIR/Library/Application Support/Google/Chrome"
  [ -d "$BASE" ] || continue

  for PROFILE in "$BASE"/*/; do
    DB="$PROFILE/History"
    [ -f "$DB" ] || continue

    PROFILE_NAME=$(basename "$PROFILE")
    echo "  --- User: $USERNAME / Profile: $PROFILE_NAME ---"

    TMPDB="/tmp/chrome_hist_$$.db"
    cp "$DB" "$TMPDB" 2>/dev/null || { echo "  [!] Cannot copy $DB (permission denied)"; continue; }

    # WebKit timestamp to Unix: (webkit_ts / 1000000) - 11644473600
    CUTOFF_WK=$(( (CUTOFF + 11644473600) * 1000000 ))

    sqlite3 "$TMPDB" "
      SELECT
        datetime((last_visit_time/1000000) - 11644473600, 'unixepoch', 'localtime') AS visited,
        url,
        title
      FROM urls
      WHERE last_visit_time >= $CUTOFF_WK
      ORDER BY last_visit_time DESC
      LIMIT 200;
    " 2>/dev/null | while IFS='|' read -r dt url title; do
      printf "  [%s]  %-80s  %s\n" "$dt" "$url" "$title"
    done || echo "  [!] Query failed"

    rm -f "$TMPDB"
    CHROME_FOUND=$((CHROME_FOUND+1))
  done
done

[ "$CHROME_FOUND" -eq 0 ] && echo "  No Chrome history databases found"
echo ""

# =============================================================================
# SECTION 3 — Firefox
# Profile DB: ~/Library/Application Support/Firefox/Profiles/*/places.sqlite
# moz_historyvisits: visit_date is microseconds since Unix epoch
# =============================================================================
echo "===== FIREFOX HISTORY ====="
FF_FOUND=0

for USERDIR in /Users/*/; do
  USERNAME=$(basename "$USERDIR")
  BASE="$USERDIR/Library/Application Support/Firefox/Profiles"
  [ -d "$BASE" ] || continue

  for PROFILE in "$BASE"/*/; do
    DB="$PROFILE/places.sqlite"
    [ -f "$DB" ] || continue

    PROFILE_NAME=$(basename "$PROFILE")
    echo "  --- User: $USERNAME / Profile: $PROFILE_NAME ---"

    TMPDB="/tmp/ff_hist_$$.db"
    cp "$DB" "$TMPDB" 2>/dev/null || { echo "  [!] Cannot copy $DB (permission denied)"; continue; }

    CUTOFF_FF=$(( CUTOFF * 1000000 ))

    sqlite3 "$TMPDB" "
      SELECT
        datetime(v.visit_date/1000000, 'unixepoch', 'localtime') AS visited,
        p.url,
        p.title
      FROM moz_historyvisits v
      JOIN moz_places p ON v.place_id = p.id
      WHERE v.visit_date >= $CUTOFF_FF
      ORDER BY v.visit_date DESC
      LIMIT 200;
    " 2>/dev/null | while IFS='|' read -r dt url title; do
      printf "  [%s]  %-80s  %s\n" "$dt" "$url" "$title"
    done || echo "  [!] Query failed"

    rm -f "$TMPDB"
    FF_FOUND=$((FF_FOUND+1))
  done
done

[ "$FF_FOUND" -eq 0 ] && echo "  No Firefox history databases found"
echo ""

# =============================================================================
# SECTION 4 — Downloads (all browsers via quarantine database)
# com.apple.LaunchServices.QuarantineEventsV2 tracks file downloads system-wide
# =============================================================================
echo "===== RECENT DOWNLOADS (Quarantine DB) ====="
QDBPATH=$(ls ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 2>/dev/null || \
          ls /Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 2>/dev/null | head -1 || true)

if [ -n "$QDBPATH" ]; then
  for QFILE in /Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2; do
    [ -f "$QFILE" ] || continue
    QU=$(echo "$QFILE" | awk -F'/' '{print $3}')
    echo "  --- User: $QU ---"
    TMPQDB="/tmp/quarantine_$$.db"
    cp "$QFILE" "$TMPQDB" 2>/dev/null || { echo "  [!] Cannot copy quarantine db"; continue; }

    # TimeStamp is Mac absolute time (seconds since 2001-01-01)
    CUTOFF_MAC=$((CUTOFF - 978307200))
    sqlite3 "$TMPQDB" "
      SELECT
        datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch', 'localtime') AS downloaded,
        LSQuarantineDataURLString AS source_url,
        LSQuarantineOriginURLString AS referrer,
        LSQuarantineAgentName AS browser
      FROM LSQuarantineEvent
      WHERE LSQuarantineTimeStamp >= $CUTOFF_MAC
      ORDER BY LSQuarantineTimeStamp DESC
      LIMIT 100;
    " 2>/dev/null | while IFS='|' read -r dt src ref browser; do
      echo "  [$dt] via $browser"
      echo "    URL: $src"
      [ -n "$ref" ] && echo "    Ref: $ref"
    done || echo "  [!] Quarantine query failed"
    rm -f "$TMPQDB"
  done
else
  echo "  [i] Quarantine database not accessible"
fi

echo ""
echo "===== END macOS BROWSER HISTORY ====="
