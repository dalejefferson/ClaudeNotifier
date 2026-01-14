//
//  NotificationWindowView.swift
//  ClaudeNotifier
//
//  Modern toast-style notification card with Ghostty integration.
//

import SwiftUI

struct NotificationWindowView: View {
    let event: ClaudeEvent
    let onDismiss: () -> Void

    @ObservedObject var themeManager = ThemeManager.shared
    @State private var isHovering = false

    // MARK: - Design Constants

    private let cardCornerRadius: CGFloat = 12
    private let iconCircleSize: CGFloat = 40
    private let cardWidth: CGFloat = 360

    // MARK: - Computed Properties

    private var iconName: String {
        switch event.type {
        case .stop:
            if event.stopReason == .interrupt {
                return "exclamationmark"
            }
            return "checkmark"
        case .subagentStop:
            return "person.fill"
        case .notification:
            if event.matcher == .permissionPrompt {
                return "lock.fill"
            }
            return "bell.fill"
        case .sessionStart:
            return "play.fill"
        }
    }

    private var iconColor: Color {
        switch event.type {
        case .stop, .subagentStop:
            switch event.stopReason {
            case .endTurn, .stopTool:
                return themeManager.palette.success
            case .interrupt:
                return themeManager.palette.active
            case .maxTurns:
                return themeManager.palette.warning
            case .none:
                return themeManager.palette.success
            }
        case .notification:
            if event.matcher == .permissionPrompt {
                return themeManager.palette.warning
            }
            return themeManager.palette.primary
        case .sessionStart:
            return themeManager.palette.primary
        }
    }

    private var headerTitle: String {
        switch event.type {
        case .stop:
            switch event.stopReason {
            case .endTurn, .stopTool:
                return "Task completed!"
            case .interrupt:
                return "Task interrupted"
            case .maxTurns:
                return "Max turns reached"
            case .none:
                return "Task completed!"
            }
        case .subagentStop:
            return "Subagent finished"
        case .notification:
            if event.matcher == .permissionPrompt {
                return "Permission required"
            }
            return "Notification"
        case .sessionStart:
            return "Session started"
        }
    }

    private var descriptionText: String {
        if let summary = event.taskSummary, !summary.isEmpty {
            return summary
        }
        return "Working in \(event.projectName)"
    }

    private var durationText: String? {
        guard let duration = event.duration else { return nil }
        let minutes = Int(duration) / 60
        let seconds = Int(duration) % 60
        if minutes > 0 {
            return "Completed in \(minutes)m \(seconds)s"
        }
        return "Completed in \(seconds)s"
    }

    // MARK: - Body

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Colored circular icon badge
            iconBadge

            // Text content
            VStack(alignment: .leading, spacing: 6) {
                // Title row with duration
                HStack {
                    Text(headerTitle)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(themeManager.palette.textPrimary)

                    Spacer()

                    if let duration = durationText {
                        Text(duration)
                            .font(.system(size: 11))
                            .foregroundColor(themeManager.palette.textTertiary)
                    }
                }

                // Description
                Text(descriptionText)
                    .font(.system(size: 13))
                    .foregroundColor(themeManager.palette.textSecondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                // Action buttons
                actionButtons
            }

            // Close button
            closeButton
        }
        .padding(16)
        .frame(width: cardWidth)
        .background(cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: cardCornerRadius))
        .shadow(color: Color.black.opacity(0.1), radius: 16, x: 0, y: 8)
        .shadow(color: Color.black.opacity(0.05), radius: 4, x: 0, y: 2)
        .onHover { hovering in
            isHovering = hovering
        }
    }

    // MARK: - Subviews

    private var iconBadge: some View {
        ZStack {
            Circle()
                .fill(iconColor)
                .frame(width: iconCircleSize, height: iconCircleSize)

            Image(systemName: iconName)
                .font(.system(size: 18, weight: .semibold))
                .foregroundColor(.white)
        }
    }

    private var actionButtons: some View {
        HStack(spacing: 16) {
            // Primary action: Open in Ghostty
            Button(action: openInGhostty) {
                HStack(spacing: 4) {
                    Text("Open in Ghostty")
                    Image(systemName: "arrow.right")
                        .font(.system(size: 11, weight: .semibold))
                }
                .font(.system(size: 13, weight: .medium))
                .foregroundColor(iconColor)
            }
            .buttonStyle(.plain)
            .onHover { hovering in
                if hovering {
                    NSCursor.pointingHand.push()
                } else {
                    NSCursor.pop()
                }
            }

            Spacer()

            // Secondary action: Dismiss
            Button(action: onDismiss) {
                Text("Dismiss")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(themeManager.palette.textSecondary)
            }
            .buttonStyle(.plain)
            .onHover { hovering in
                if hovering {
                    NSCursor.pointingHand.push()
                } else {
                    NSCursor.pop()
                }
            }
        }
        .padding(.top, 4)
    }

    private var closeButton: some View {
        Button(action: onDismiss) {
            Image(systemName: "xmark")
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(themeManager.palette.textTertiary)
                .frame(width: 24, height: 24)
                .background(
                    Circle()
                        .fill(themeManager.palette.border.opacity(isHovering ? 0.5 : 0))
                )
        }
        .buttonStyle(.plain)
        .keyboardShortcut(.return, modifiers: [])
    }

    private var cardBackground: some View {
        RoundedRectangle(cornerRadius: cardCornerRadius)
            .fill(themeManager.palette.surface)
            .overlay(
                RoundedRectangle(cornerRadius: cardCornerRadius)
                    .stroke(themeManager.palette.border, lineWidth: 1)
            )
    }

    // MARK: - Actions

    private func openInGhostty() {
        // Activate Ghostty terminal
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        task.arguments = ["-a", "Ghostty"]
        try? task.run()

        // Close the notification window
        onDismiss()
    }
}

// MARK: - Preview

#Preview {
    NotificationWindowView(
        event: ClaudeEvent(
            sessionId: "abc123def456",
            cwd: "/Users/developer/Projects/MyApp",
            type: .stop,
            stopReason: .endTurn,
            taskSummary: "Successfully refactored the authentication module and updated all related tests.",
            duration: 145.5
        ),
        onDismiss: {}
    )
    .padding(20)
    .background(Color.gray.opacity(0.3))
}
