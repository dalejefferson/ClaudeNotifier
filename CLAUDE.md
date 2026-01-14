# ClaudeNotifier - Project Context

A macOS menu bar app that monitors Claude Code sessions, displays real-time usage stats, and sends notifications when tasks complete. Features a professional UI with 5 customizable color themes, progress bars, and activity charts.

## Quick Commands

```bash
# Build from command line
cd ~/Dropbox/ClaudeNotifier
xcodebuild -scheme ClaudeNotifier -configuration Debug build

# Open in Xcode
open ClaudeNotifier.xcodeproj

# Test the socket manually
echo '{"hook_event_name":"Stop","session_id":"test","cwd":"/tmp","transcript_path":"","stop_reason":"end_turn"}' | nc -U /tmp/claude-notifier.sock

# Check if app is running
pgrep ClaudeNotifier

# Check socket exists
ls -la /tmp/claude-notifier.sock

# Launch built app
open ~/Library/Developer/Xcode/DerivedData/ClaudeNotifier-*/Build/Products/Debug/ClaudeNotifier.app
```

## Architecture

```
ClaudeNotifier/
├── App/
│   ├── ClaudeNotifierApp.swift     # @main, MenuBarExtra with sparkle icon
│   └── AppDelegate.swift           # Window management, focus stealing, event handling
├── Models/
│   ├── AnalyticsCalculator.swift   # Daily/weekly stats calculation
│   ├── ClaudeEvent.swift           # Event types: Stop, SubagentStop, Notification, SessionStart
│   ├── ColorPalette.swift          # 5 color themes with semantic colors
│   ├── EventStore.swift            # Persistent event history (~/.claude-notifier-events.json)
│   ├── SessionTracker.swift        # Duration tracking + subagent counting
│   ├── ThemeManager.swift          # Theme selection & persistence (@AppStorage)
│   ├── TranscriptParser.swift      # Parses ~/.claude/projects/*.jsonl for task summaries
│   └── UsageLimitTracker.swift     # 5hr usage window tracking with countdown
├── Services/
│   ├── LaunchAtLoginManager.swift  # Launch at login toggle
│   ├── RateLimitFetcher.swift      # Fetches real usage from Anthropic API
│   ├── SocketServer.swift          # Unix socket at /tmp/claude-notifier.sock
│   └── StatsReader.swift           # Reads ~/.claude/stats-cache.json for token usage
├── Views/
│   ├── Components/
│   │   ├── ActivitySparkline.swift # Hourly activity line chart
│   │   └── UsageProgressBar.swift  # Usage limit progress bar
│   ├── MenuBarView.swift           # Main dropdown (420px) with tabs, stats, events
│   └── NotificationWindowView.swift # Toast popup with task details
└── Extensions/
    └── Color+Hex.swift             # Color(hex:) initializer
```

## How It Works

1. **Claude Code hooks** (configured in `~/.claude/settings.json`) call shell scripts on events
2. **Hook scripts** (`~/.local/bin/claude-notifier-*`) send JSON to Unix socket
3. **SocketServer** receives events, posts to NotificationCenter
4. **AppDelegate** enriches events with duration/summary, shows popup window
5. **RateLimitFetcher** polls Anthropic API for real usage data (cached 1 hour)

## Key Files Outside Project

| File | Purpose |
|------|---------|
| `~/.local/bin/claude-notifier-hook` | Main hook script for Stop/SubagentStop/Notification events |
| `~/.local/bin/claude-notifier-start-tracker` | PreToolUse hook to record session start times |
| `~/.claude/settings.json` | Claude Code hooks configuration |
| `~/.claude/stats-cache.json` | Token usage stats (read by StatsReader) |
| `~/.claude-notifier-events.json` | Persistent event history (30 day retention) |
| `~/.claude-notifier-sessions.json` | Persisted session start times |
| `~/.claude-notifier-token-cache` | Cached API access token (1 hour) |
| `/tmp/claude-notifier.sock` | Unix socket for IPC |

## Menu Bar Features (420px dropdown)

### Project Tabs
- Tab bar at top with project tabs
- **"+" button** opens project picker (~/Dropbox/VIBE CODING/)
- Selecting a project creates a tab AND launches Claude Code in Ghostty
- Close tabs with "x" button (appears on hover)

### Theme System (5 Palettes)
- **Warm Professional** - Orange/Blue on cream (#F5F2F2, #FEB05D, #5A7ACD, #2B2A2A)
- **Cool Elegance** - Teal/Mauve on light gray (#EEEEEE, #6594B1, #DDAED3, #213C51)
- **Nature Inspired** - Aqua/Sage on pale yellow (#F6F3C2, #4B9DA9, #91C6BC, #E37434)
- **Warm Coral** - Red/Coral on peach (#FFEAD3, #D25353, #EA7B7B, #9E3B3B)
- **Vintage Mauve** - Purple/Rose on cream (#FFDAB3, #574964, #C8AAAA, #9F8383)
- Theme picker in Settings section (color swatches)
- Persists via `@AppStorage("selectedPaletteId")`

### Usage Progress Bars
- **5-Hour Usage**: Visual bar showing remaining capacity
- **7-Day Usage**: Visual bar with days/hours until reset
- Color-coded: Green (>50%), Yellow (20-50%), Red (<20%)
- Data from Anthropic OAuth API via RateLimitFetcher

### Activity Sparkline Chart
- Line chart showing hourly task completions today
- Gradient fill with theme primary color
- Time labels: 12am, 6am, 12pm, 6pm, Now
- Only displays when there's activity data

### Current Session (Collapsible)
- Model badge (Opus 4.5, Sonnet 4.5, Haiku 4.5)
- Token count badge
- Progress bars for 5h/7d usage
- Active agents count badge
- Chevron toggle to collapse/expand

### Today's Stats
- Task count (green badge)
- Total duration (blue badge)
- Average duration (orange badge)
- Activity sparkline chart

### Recent Events (2 items)
- Card-style event rows with circular icon backgrounds
- Running events show spinning arrow icon + "Agent Running" text
- Completed events show checkmark
- Duration badge on right

### Settings
- Launch at Login toggle
- Theme picker (5 color swatches)

## Event Types

- **Stop** - Main Claude task completed (stop_reason: end_turn, interrupt, max_turns, stop_tool)
- **SubagentStop** - Subagent/Task agent completed
- **Notification** - Permission prompt or idle prompt
- **SessionStart** - Internal event to track task duration

## Hooks Configuration

In `~/.claude/settings.json`:
```json
{
  "hooks": {
    "Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]}],
    "SubagentStop": [{"matcher": "", "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]}],
    "Notification": [
      {"matcher": "permission_prompt", "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]},
      {"matcher": "idle_prompt", "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]}
    ],
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-start-tracker"}]}]
  }
}
```

## Common Issues

**Build errors in Xcode IDE but command line works:**
- Clean build: `⌘ + Shift + K`, then rebuild `⌘ + B`
- IDE analysis is separate from actual compilation

**Popup not appearing:**
- Check app running: `pgrep ClaudeNotifier`
- Check socket: `ls /tmp/claude-notifier.sock`
- Test manually with `nc -U` command above

**Duration not showing:**
- PreToolUse hook must fire first to record start time
- Check `~/.claude-notifier-sessions.json` for tracked sessions

**Usage showing 0%:**
- Check Keychain has "Claude Code-credentials" entry
- Verify API token: `security find-generic-password -s "Claude Code-credentials" -w`
- RateLimitFetcher caches token for 1 hour

**Themes not persisting:**
- Check `defaults read com.claude.notifier selectedPaletteId`

## Development Notes

- Requires macOS 13+ (MenuBarExtra, SwiftUI Charts alternative)
- Uses Network.framework for Unix sockets
- SwiftUI for views, AppKit for window management
- `@MainActor` isolation on published properties
- Singleton pattern for services (ThemeManager.shared, SessionTracker.shared, etc.)
- No storyboard - pure SwiftUI with NSApplicationDelegateAdaptor

## Component Reference

### StatBadge
```swift
StatBadge(icon: "checkmark.circle.fill", value: "12", label: "Tasks", color: .green)
```
- Rounded rectangle with color.opacity(0.12) background
- Icon + value/label stack
- Uses theme colors for text

### UsageProgressBar
```swift
UsageProgressBar(utilization: 0.6, label: "5-Hour Usage", resetTime: "2h 15m")
```
- Shows remaining percentage (1 - utilization)
- Color-coded based on remaining capacity
- Animated fill width

### ActivitySparkline
```swift
ActivitySparkline(hourlyData: [0, 0, 1, 2, 5, 3, ...])
```
- Path-based line chart with gradient fill
- Normalized to max value
- Theme-aware colors

### EventRowView
- Card-style with 12px corner radius
- Circular icon background (36x36)
- Spinning animation for running events
- Duration badge with monospace font
