#!/bin/bash
#
# ClaudeNotifier Setup Script
# This script sets up the Xcode project and installs hook scripts
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== ClaudeNotifier Setup ==="
echo ""

# Check for xcodegen
if command -v xcodegen &> /dev/null; then
    echo "✓ Found xcodegen, generating Xcode project..."
    xcodegen generate
    echo "✓ Xcode project generated"
else
    echo "⚠ xcodegen not found. Install it with: brew install xcodegen"
    echo "  Then run: xcodegen generate"
    echo ""
    echo "  Alternatively, create a new Xcode project manually:"
    echo "  1. Open Xcode → File → New → Project"
    echo "  2. Choose macOS → App"
    echo "  3. Product Name: ClaudeNotifier"
    echo "  4. Interface: SwiftUI, Language: Swift"
    echo "  5. Uncheck 'Include Tests'"
    echo "  6. Save to this directory"
    echo "  7. Delete the auto-generated files and add the files from ClaudeNotifier/"
fi

echo ""

# Install hook scripts
echo "=== Installing Hook Scripts ==="

HOOK_DIR="$HOME/.local/bin"
mkdir -p "$HOOK_DIR"

# Copy and make executable
cp "$SCRIPT_DIR/HookScripts/claude-notifier-hook" "$HOOK_DIR/"
cp "$SCRIPT_DIR/HookScripts/claude-notifier-start-tracker" "$HOOK_DIR/"
chmod +x "$HOOK_DIR/claude-notifier-hook"
chmod +x "$HOOK_DIR/claude-notifier-start-tracker"

echo "✓ Installed hooks to $HOOK_DIR"

# Configure Claude Code hooks
echo ""
echo "=== Configuring Claude Code Hooks ==="

CLAUDE_SETTINGS="$HOME/.claude/settings.json"

# Create .claude directory if needed
mkdir -p "$HOME/.claude"

# Check if settings file exists
if [ -f "$CLAUDE_SETTINGS" ]; then
    echo "⚠ Claude settings file already exists at $CLAUDE_SETTINGS"
    echo "  Please manually add the following hooks configuration:"
else
    # Create new settings file with hooks
    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "Stop": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "~/.local/bin/claude-notifier-hook"
      }]
    }],
    "SubagentStop": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "~/.local/bin/claude-notifier-hook"
      }]
    }],
    "Notification": [{
      "matcher": "permission_prompt",
      "hooks": [{
        "type": "command",
        "command": "~/.local/bin/claude-notifier-hook"
      }]
    }, {
      "matcher": "idle_prompt",
      "hooks": [{
        "type": "command",
        "command": "~/.local/bin/claude-notifier-hook"
      }]
    }],
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "~/.local/bin/claude-notifier-start-tracker"
      }]
    }]
  }
}
EOF
    echo "✓ Created Claude Code hooks configuration"
fi

echo ""
echo "=== Hooks Configuration (for manual addition if needed) ==="
cat << 'EOF'
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
EOF

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Open ClaudeNotifier.xcodeproj in Xcode (or generate with xcodegen)"
echo "2. Build and run the app (⌘R)"
echo "3. After building, copy the app to /Applications"
echo "4. Test by running Claude Code - notifications should appear when tasks complete"
echo ""
echo "To add to Login Items (auto-start on login):"
echo "  System Settings → General → Login Items → Add ClaudeNotifier"
