# ClaudeNotifier

A macOS menu bar app that interrupts you with a focus-stealing 800x600 popup when Claude Code completes tasks.

## Features

- **Focus-stealing popup** (800x600) - Interrupts whatever you're doing when Claude finishes
- **Task duration tracking** - Shows how long each task took
- **Task summaries** - Parses Claude transcripts to show what was accomplished
- **Menu bar integration** - Lives silently in your menu bar
- **All events captured** - Task completion, subagent completion, permission prompts, idle notifications

## Quick Setup

Run the setup script:

```bash
cd ~/Dropbox/ClaudeNotifier
chmod +x setup.sh
./setup.sh
```

This will install the hook scripts and configure Claude Code (if settings don't already exist).

## Manual Installation

### 1. Generate Xcode Project

**Option A: Using xcodegen (recommended)**
```bash
brew install xcodegen
cd ~/Dropbox/ClaudeNotifier
xcodegen generate
open ClaudeNotifier.xcodeproj
```

**Option B: Manual Xcode setup**
1. Open Xcode → File → New → Project
2. Choose macOS → App
3. Product Name: `ClaudeNotifier`
4. Interface: SwiftUI, Language: Swift
5. Save to `~/Dropbox/ClaudeNotifier`
6. Delete auto-generated files
7. Add all files from `ClaudeNotifier/` folder
8. Set Info.plist path in Build Settings

### 2. Build & Run

1. Open `ClaudeNotifier.xcodeproj` in Xcode
2. Select your signing team in Signing & Capabilities
3. Press `⌘R` to build and run
4. Look for the ✦ sparkle icon in your menu bar

### 3. Install Hook Scripts

```bash
mkdir -p ~/.local/bin
cp ~/Dropbox/ClaudeNotifier/HookScripts/claude-notifier-hook ~/.local/bin/
cp ~/Dropbox/ClaudeNotifier/HookScripts/claude-notifier-start-tracker ~/.local/bin/
chmod +x ~/.local/bin/claude-notifier-*
```

### 4. Configure Claude Code Hooks

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "Stop": [{
      "matcher": "",
      "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]
    }],
    "SubagentStop": [{
      "matcher": "",
      "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]
    }],
    "Notification": [
      {"matcher": "permission_prompt", "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]},
      {"matcher": "idle_prompt", "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-hook"}]}
    ],
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{"type": "command", "command": "~/.local/bin/claude-notifier-start-tracker"}]
    }]
  }
}
```

### 5. Deploy App

After building in Xcode:
```bash
# Copy from Xcode's build folder to Applications
cp -r ~/Library/Developer/Xcode/DerivedData/ClaudeNotifier-*/Build/Products/Debug/ClaudeNotifier.app /Applications/
```

Or use Xcode: Product → Archive → Distribute App → Copy App

### 6. Add to Login Items (Auto-Start)

System Settings → General → Login Items → Add ClaudeNotifier

## Usage

1. Start ClaudeNotifier (it lives in your menu bar with a ✦ icon)
2. Use Claude Code normally
3. When Claude finishes a task, a popup will appear with:
   - Task completion status (success/interrupted/permission needed)
   - Duration of the task
   - Summary of what was done
   - Working directory

Click **Dismiss** (or press Return) to close the popup.

## Testing

Test the socket connection:
```bash
echo '{"hook_event_name":"Stop","session_id":"test123","cwd":"/tmp","transcript_path":"","stop_reason":"end_turn"}' | nc -U /tmp/claude-notifier.sock
```

## Troubleshooting

### Popup not appearing

1. Check ClaudeNotifier is running: `pgrep ClaudeNotifier`
2. Check socket exists: `ls -la /tmp/claude-notifier.sock`
3. Test hook script: `echo '{"hook_event_name":"Stop"}' | ~/.local/bin/claude-notifier-hook`

### Hook scripts not working

1. Verify executable: `ls -la ~/.local/bin/claude-notifier-*`
2. Test manually: `echo '{"session_id":"test"}' | ~/.local/bin/claude-notifier-start-tracker`
3. Install jq for better JSON parsing: `brew install jq`

### Build errors in Xcode

Ensure macOS deployment target is 13.0+ (MenuBarExtra requires macOS 13)

## File Locations

| File | Location |
|------|----------|
| Source code | `~/Dropbox/ClaudeNotifier/ClaudeNotifier/` |
| Hook scripts | `~/.local/bin/claude-notifier-*` |
| Claude settings | `~/.claude/settings.json` |
| Unix socket | `/tmp/claude-notifier.sock` |
| Session data | `~/.claude-notifier-sessions.json` |

## Architecture

```
ClaudeNotifier/
├── App/
│   ├── ClaudeNotifierApp.swift    # @main entry, MenuBarExtra
│   └── AppDelegate.swift          # Window management, focus stealing
├── Models/
│   ├── ClaudeEvent.swift          # Event data model
│   ├── SessionTracker.swift       # Duration tracking
│   └── TranscriptParser.swift     # Parse .jsonl transcripts
├── Services/
│   └── SocketServer.swift         # Unix socket listener
└── Views/
    ├── NotificationWindowView.swift  # 800x600 popup
    └── MenuBarView.swift             # Menu bar dropdown
```

## License

MIT
