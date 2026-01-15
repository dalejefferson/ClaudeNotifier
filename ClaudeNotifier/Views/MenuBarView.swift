//
//  MenuBarView.swift
//  ClaudeNotifier
//
//  Menu bar dropdown view for monitoring Claude Code events.
//

import SwiftUI

struct ProjectTabData: Identifiable, Equatable {
    let id: UUID
    let path: String
    let name: String

    init(path: String) {
        self.id = UUID()
        self.path = path
        self.name = (path as NSString).lastPathComponent
    }
}

struct MenuBarView: View {
    @ObservedObject var socketServer: SocketServer
    @ObservedObject var launchManager = LaunchAtLoginManager.shared
    @ObservedObject var statsReader = StatsReader.shared
    @ObservedObject var sessionTracker = SessionTracker.shared
    @ObservedObject var usageLimitTracker = UsageLimitTracker.shared
    @ObservedObject var rateLimitFetcher = RateLimitFetcher.shared
    @ObservedObject var themeManager = ThemeManager.shared
    var onEventSelected: ((ClaudeEvent) -> Void)?

    @State private var isPulsing = false
    @State private var openTabs: [ProjectTabData] = []  // Array of open project tabs
    @State private var activeTabId: UUID? = nil         // Currently selected tab
    @State private var showProjectPicker = false        // Show folder picker sheet
    @State private var isCurrentSessionCollapsed = false
    @AppStorage("currentSessionCollapsed") private var storedCollapsedState = false

    // Check if Claude is actively running (has active sessions)
    private var isClaudeRunning: Bool {
        sessionTracker.sessionCount > 0
    }

    // Total active agents (main sessions + subagents)
    private var totalAgentCount: Int {
        sessionTracker.totalActiveAgentCount
    }

    // Text to display for active agents
    private var agentCountText: String {
        if totalAgentCount == 0 {
            return "Claude Idle (0 agents)"
        } else if totalAgentCount == 1 {
            return "Claude Running (1 agent)"
        } else {
            return "Claude Running (\(totalAgentCount) agents)"
        }
    }

    // Cached analytics (uses EventStore's cached value to avoid recalculation)
    private var todayStats: AnalyticsCalculator.DailySummary {
        EventStore.shared.cachedTodayStats
    }

    // Hourly activity data for sparkline chart
    private var hourlyActivityData: [Int] {
        let calendar = Calendar.current
        let now = Date()

        var hourlyCount = Array(repeating: 0, count: 24)

        for event in EventStore.shared.eventsToday() {
            let hour = calendar.component(.hour, from: event.timestamp)
            if hour < 24 {
                hourlyCount[hour] += 1
            }
        }

        // Only return hours up to current hour
        let currentHour = calendar.component(.hour, from: now)
        return Array(hourlyCount.prefix(currentHour + 1))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Tab Bar
            tabBar

            // Status Header
            statusHeader

            // Model & Usage Section
            if let usage = statsReader.currentUsage {
                Divider()
                    .padding(.vertical, 8)

                modelUsageSection(usage)
            }

            Divider()
                .padding(.vertical, 8)

            // Today's Stats Section
            todayStatsSection

            Divider()
                .padding(.vertical, 8)

            // Recent Events Section
            recentEventsSection

            // Clear History Button
            if !socketServer.recentEvents.isEmpty {
                clearHistoryButton
            }

            Divider()
                .padding(.vertical, 8)

            // Settings Section
            settingsSection

            Divider()
                .padding(.vertical, 8)

            // Project Footer
            projectFooter

            // Quit Button
            quitButton
        }
        .padding(12)
        .frame(width: 420)
        .background(themeManager.palette.background)
    }

    // MARK: - Tab Bar

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                // Existing project tabs
                ForEach(openTabs) { tab in
                    TabButton(
                        title: tab.name,
                        isSelected: activeTabId == tab.id,
                        onSelect: { activeTabId = tab.id },
                        onClose: { closeTab(tab) }
                    )
                }

                // Add new tab button
                Button(action: { showProjectPicker = true }) {
                    Image(systemName: "plus")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .frame(width: 24, height: 24)
                        .background(Color(NSColor.controlBackgroundColor))
                        .cornerRadius(6)
                }
                .buttonStyle(.plain)
                .help("Open new project")
            }
            .padding(.horizontal, 2)
        }
        .padding(.bottom, 8)
        .popover(isPresented: $showProjectPicker, arrowEdge: .bottom) {
            projectPickerView
        }
    }

    // MARK: - Project Picker

    private var availableProjects: [String] {
        let vibeCodingPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Dropbox/VIBE CODING")

        do {
            let contents = try FileManager.default.contentsOfDirectory(
                at: vibeCodingPath,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
            return contents
                .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
                .map { $0.path }
                .sorted()
        } catch {
            print("Failed to list projects: \(error)")
            return []
        }
    }

    private var projectPickerView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Select Project")
                    .font(.headline)
                Spacer()
                Button("Cancel") {
                    showProjectPicker = false
                }
                .buttonStyle(.plain)
                .foregroundColor(.secondary)
            }
            .padding(.bottom, 4)

            Divider()

            if availableProjects.isEmpty {
                Text("No projects found in ~/Dropbox/VIBE CODING/")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.vertical, 20)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(availableProjects, id: \.self) { projectPath in
                            ProjectPickerRow(
                                path: projectPath,
                                isAlreadyOpen: openTabs.contains { $0.path == projectPath },
                                onSelect: {
                                    openProject(at: projectPath)
                                    showProjectPicker = false
                                }
                            )
                        }
                    }
                }
                .frame(maxHeight: 300)
            }
        }
        .padding(12)
        .frame(width: 300)
        .background(Color(NSColor.windowBackgroundColor))
        .cornerRadius(10)
    }

    private func openProject(at path: String) {
        // Check if already open
        if let existingTab = openTabs.first(where: { $0.path == path }) {
            activeTabId = existingTab.id
            return
        }

        // Create new tab
        let newTab = ProjectTabData(path: path)
        openTabs.append(newTab)
        activeTabId = newTab.id

        // Launch Claude Code in Ghostty
        launchClaudeCode(at: path)
    }

    private func closeTab(_ tab: ProjectTabData) {
        openTabs.removeAll { $0.id == tab.id }
        if activeTabId == tab.id {
            activeTabId = openTabs.first?.id
        }
    }

    private func projectDisplayName(_ cwd: String) -> String {
        return (cwd as NSString).lastPathComponent
    }

    // MARK: - Status Header

    private var statusHeader: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(socketServer.isRunning ? Color.green : Color.red)
                .frame(width: 10, height: 10)

            Text(socketServer.isRunning ? "Listening" : "Not Running")
                .font(.headline)

            Spacer()

            // Show animated indicator when Claude is running
            if isClaudeRunning {
                HStack(spacing: 6) {
                    Circle()
                        .fill(Color.orange)
                        .frame(width: 8, height: 8)
                        .scaleEffect(isPulsing ? 1.3 : 1.0)
                        .opacity(isPulsing ? 0.6 : 1.0)
                        .animation(
                            .easeInOut(duration: 0.8)
                            .repeatForever(autoreverses: true),
                            value: isPulsing
                        )

                    Text(agentCountText)
                        .font(.caption)
                        .fontWeight(.medium)
                        .foregroundColor(.orange)
                }
                .onAppear { isPulsing = true }
                .onDisappear { isPulsing = false }
            } else if socketServer.isRunning {
                Text("Unix Socket")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.bottom, 4)
    }

    // MARK: - Model & Usage Section

    private func modelUsageSection(_ usage: UsageSummary) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(action: {
                withAnimation(.easeInOut(duration: 0.2)) {
                    isCurrentSessionCollapsed.toggle()
                    storedCollapsedState = isCurrentSessionCollapsed
                }
            }) {
                HStack {
                    Text("Current Session")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Spacer()
                    Image(systemName: isCurrentSessionCollapsed ? "chevron.right" : "chevron.down")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .buttonStyle(.plain)

            if !isCurrentSessionCollapsed {
            // First row: Model and Tokens badges
            HStack(spacing: 12) {
                // Model badge - purple
                HStack(spacing: 6) {
                    Image(systemName: "cpu")
                        .foregroundColor(.purple)
                        .font(.caption)
                    Text(usage.shortModelName)
                        .font(.system(.caption, design: .rounded))
                        .fontWeight(.semibold)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Color.purple.opacity(0.1))
                .cornerRadius(6)

                // Tokens badge - blue
                HStack(spacing: 6) {
                    Image(systemName: "text.word.spacing")
                        .foregroundColor(.blue)
                        .font(.caption)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(usage.formattedTokens)
                            .font(.system(.caption, design: .rounded))
                            .fontWeight(.semibold)
                        Text("tokens")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Color.blue.opacity(0.1))
                .cornerRadius(6)

                Spacer()
            }

            // Usage Progress Bars
            VStack(spacing: 12) {
                if rateLimitFetcher.isLoading && rateLimitFetcher.fiveHourResetsAt == nil {
                    // Loading state - show placeholder
                    HStack(spacing: 6) {
                        ProgressView()
                            .scaleEffect(0.7)
                            .frame(width: 14, height: 14)
                        Text("Loading usage data...")
                            .font(.system(.caption, design: .rounded))
                            .foregroundColor(.secondary)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(6)
                } else {
                    UsageProgressBar(
                        utilization: rateLimitFetcher.fiveHourUtilization,
                        label: "5-Hour Usage",
                        resetTime: rateLimitFetcher.formattedTimeUntilReset
                    )

                    UsageProgressBar(
                        utilization: rateLimitFetcher.sevenDayUtilization,
                        label: "7-Day Usage",
                        resetTime: sevenDayResetTime
                    )
                }
            }

            // Third row: Active agents badge (only when agents running)
            if sessionTracker.totalActiveAgentCount > 0 {
                HStack(spacing: 12) {
                    StatBadge(
                        icon: "person.2.fill",
                        value: "\(sessionTracker.totalActiveAgentCount)",
                        label: sessionTracker.totalActiveAgentCount == 1 ? "Agent" : "Agents",
                        color: .orange
                    )
                    Spacer()
                }
            }
            }
        }
        .onAppear { isCurrentSessionCollapsed = storedCollapsedState }
    }

    /// Returns the appropriate color based on usage limit status (legacy, for fallback).
    private var usageLimitStatusColor: Color {
        switch usageLimitTracker.statusLevel {
        case .good:
            return .green
        case .warning:
            return .yellow
        case .critical:
            return .red
        }
    }

    // MARK: - Real API Usage Data (from RateLimitFetcher)

    /// Percentage remaining for the 5-hour window (100% - utilization).
    private var fiveHourPercentageRemaining: String {
        let remaining = max(0, (1.0 - rateLimitFetcher.fiveHourUtilization) * 100)
        return "\(Int(remaining))%"
    }

    /// Percentage remaining for the 7-day window (100% - utilization).
    private var sevenDayPercentageRemaining: String {
        let remaining = max(0, (1.0 - rateLimitFetcher.sevenDayUtilization) * 100)
        return "\(Int(remaining))%"
    }

    /// Color for the 5-hour usage status.
    private var fiveHourStatusColor: Color {
        let remaining = 1.0 - rateLimitFetcher.fiveHourUtilization
        if remaining > 0.5 {
            return .green
        } else if remaining > 0.2 {
            return .yellow
        } else {
            return .red
        }
    }

    /// Color for the 7-day usage status.
    private var sevenDayStatusColor: Color {
        let remaining = 1.0 - rateLimitFetcher.sevenDayUtilization
        if remaining > 0.5 {
            return .green
        } else if remaining > 0.2 {
            return .yellow
        } else {
            return .red
        }
    }

    /// Formatted reset time for the 7-day window.
    private var sevenDayResetTime: String {
        guard let resetDate = rateLimitFetcher.sevenDayResetsAt else { return "--" }
        let interval = resetDate.timeIntervalSinceNow
        let days = Int(interval) / 86400
        let hours = (Int(interval) % 86400) / 3600
        return "\(days)d \(hours)h"
    }

    // MARK: - Today's Stats Section

    private var todayStatsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Today")
                .font(.subheadline)
                .foregroundColor(.secondary)

            HStack(spacing: 16) {
                StatBadge(
                    icon: "checkmark.circle.fill",
                    value: "\(todayStats.taskCount)",
                    label: "Tasks",
                    color: .green
                )

                StatBadge(
                    icon: "clock.fill",
                    value: todayStats.totalDurationFormatted,
                    label: "Total",
                    color: .blue
                )

                if todayStats.taskCount > 0 {
                    StatBadge(
                        icon: "gauge.medium",
                        value: todayStats.averageDurationFormatted,
                        label: "Avg",
                        color: .orange
                    )
                }

                Spacer()
            }

            // Activity chart
            if !hourlyActivityData.isEmpty && hourlyActivityData.contains(where: { $0 > 0 }) {
                ActivitySparkline(hourlyData: hourlyActivityData)
                    .padding(.top, 8)
            }
        }
    }

    // MARK: - Recent Events Section

    private var recentEventsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Recent Events")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .padding(.bottom, 4)

            if socketServer.recentEvents.isEmpty {
                HStack {
                    Spacer()
                    Text("No recent events")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .padding(.vertical, 20)
            } else {
                ForEach(socketServer.recentEvents.suffix(2).reversed()) { event in
                    EventRowView(event: event)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            onEventSelected?(event)
                        }
                }
            }
        }
    }

    // MARK: - Clear History Button

    private var clearHistoryButton: some View {
        Button(action: {
            socketServer.clearHistory()
        }) {
            HStack {
                Image(systemName: "trash")
                    .font(.caption)
                Text("Clear History")
                    .font(.caption)
            }
            .foregroundColor(.secondary)
        }
        .buttonStyle(.plain)
        .padding(.top, 8)
    }

    // MARK: - Theme Picker

    private var themePicker: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Theme")
                .font(.caption)
                .foregroundColor(themeManager.palette.textSecondary)

            HStack(spacing: 10) {
                ForEach(ColorPalette.allPalettes) { palette in
                    Button(action: { themeManager.setPalette(palette) }) {
                        Circle()
                            .fill(palette.primary)
                            .frame(width: 28, height: 28)
                            .overlay(
                                Circle()
                                    .stroke(Color.white, lineWidth: themeManager.palette.id == palette.id ? 3 : 0)
                            )
                            .shadow(color: palette.primary.opacity(0.4), radius: 3, x: 0, y: 2)
                    }
                    .buttonStyle(.plain)
                    .scaleEffect(themeManager.palette.id == palette.id ? 1.1 : 1.0)
                    .animation(.spring(response: 0.3), value: themeManager.palette.id)
                    .help(palette.name)
                }
            }
        }
    }

    // MARK: - Settings Section

    private var settingsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Launch at Login Toggle
            Toggle(isOn: Binding(
                get: { launchManager.isEnabled },
                set: { launchManager.setEnabled($0) }
            )) {
                HStack(spacing: 6) {
                    Image(systemName: "power")
                        .foregroundColor(.secondary)
                        .font(.caption)
                    Text("Launch at Login")
                        .font(.caption)
                }
            }
            .toggleStyle(.switch)
            .controlSize(.small)

            // Theme Picker
            themePicker

            // Show status message if there's an issue
            if launchManager.requiresUserAction {
                Button(action: {
                    launchManager.openSystemSettings()
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.yellow)
                        Text(launchManager.statusMessage)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - Project Footer

    private var projectFooter: some View {
        Group {
            if let activeId = activeTabId,
               let activeTab = openTabs.first(where: { $0.id == activeId }) {
                HStack {
                    Image(systemName: "folder.fill")
                        .foregroundColor(.secondary)
                        .font(.caption)
                    Text("Project: \(activeTab.name)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .padding(.vertical, 4)
            }
        }
    }

    // MARK: - Quit Button

    private var quitButton: some View {
        Button(action: {
            NSApplication.shared.terminate(nil)
        }) {
            HStack {
                Text("Quit ClaudeNotifier")
                Spacer()
                Text("\u{2318}Q")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .buttonStyle(.plain)
        .keyboardShortcut("q", modifiers: .command)
    }

    // MARK: - Launch Claude Code

    private func launchClaudeCode(at projectPath: String) {
        // Create AppleScript to open Ghostty with Claude Code
        let script = """
        tell application "Ghostty"
            activate
            delay 0.3
            tell application "System Events"
                tell process "Ghostty"
                    keystroke "n" using command down
                    delay 0.3
                end tell
            end tell
        end tell

        delay 0.5

        tell application "System Events"
            tell process "Ghostty"
                keystroke "cd \\"\(projectPath)\\" && claude"
                keystroke return
            end tell
        end tell
        """

        var error: NSDictionary?
        if let appleScript = NSAppleScript(source: script) {
            appleScript.executeAndReturnError(&error)
            if let error = error {
                print("AppleScript error: \(error)")
                // Fallback: Try direct terminal command
                launchClaudeCodeFallback(at: projectPath)
            }
        }
    }

    private func launchClaudeCodeFallback(at projectPath: String) {
        // Fallback using open command
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        task.arguments = ["-a", "Ghostty"]

        do {
            try task.run()

            // Give Ghostty time to open, then send commands
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                let commandScript = """
                tell application "System Events"
                    tell process "Ghostty"
                        keystroke "cd \\"\(projectPath)\\" && claude"
                        keystroke return
                    end tell
                end tell
                """

                var error: NSDictionary?
                if let appleScript = NSAppleScript(source: commandScript) {
                    appleScript.executeAndReturnError(&error)
                }
            }
        } catch {
            print("Failed to launch Ghostty: \(error)")
        }
    }
}

// MARK: - Stat Badge

struct StatBadge: View {
    let icon: String
    let value: String
    let label: String
    let color: Color
    @ObservedObject var themeManager = ThemeManager.shared

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.system(size: 14, weight: .medium))

            VStack(alignment: .leading, spacing: 2) {
                Text(value)
                    .font(.system(.subheadline, design: .rounded))
                    .fontWeight(.semibold)
                    .foregroundColor(themeManager.palette.textPrimary)
                Text(label)
                    .font(.caption2)
                    .foregroundColor(themeManager.palette.textSecondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(color.opacity(0.12))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(color.opacity(0.2), lineWidth: 1)
        )
    }
}

// MARK: - Event Row View

struct EventRowView: View {
    let event: ClaudeEvent
    @ObservedObject var sessionTracker = SessionTracker.shared
    @ObservedObject var themeManager = ThemeManager.shared
    @State private var isSpinning = false

    private var isRunning: Bool {
        event.type == .notification && sessionTracker.isTracking(sessionId: event.sessionId)
    }

    private var iconName: String {
        switch event.type {
        case .stop:
            return "checkmark.circle.fill"
        case .subagentStop:
            return "person.circle.fill"
        case .notification:
            return isRunning ? "arrow.triangle.2.circlepath" : "bell.fill"
        case .sessionStart:
            return "play.circle.fill"
        }
    }

    private var iconColor: Color {
        switch event.type {
        case .stop, .subagentStop:
            switch event.stopReason {
            case .endTurn, .stopTool:
                return .green
            case .interrupt:
                return .orange
            case .maxTurns:
                return .yellow
            case .none:
                return .green
            }
        case .notification:
            return isRunning ? .orange : .blue
        case .sessionStart:
            return .purple
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            // Icon with circular background
            ZStack {
                Circle()
                    .fill(iconColor.opacity(0.15))
                    .frame(width: 36, height: 36)

                Image(systemName: iconName)
                    .foregroundColor(iconColor)
                    .font(.system(size: 14, weight: .medium))
                    .rotationEffect(.degrees(isSpinning && isRunning ? 360 : 0))
                    .animation(
                        isRunning ? .linear(duration: 1.5).repeatForever(autoreverses: false) : .default,
                        value: isSpinning
                    )
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(isRunning ? "Agent Running" : event.type.displayName)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(themeManager.palette.textPrimary)

                if let taskSummary = event.taskSummary, !taskSummary.isEmpty {
                    Text(taskSummary)
                        .font(.caption)
                        .foregroundColor(themeManager.palette.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }

            Spacer()

            if let duration = event.duration {
                Text(formatEventDuration(duration))
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(themeManager.palette.textTertiary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(themeManager.palette.surface.opacity(0.8))
                    .cornerRadius(6)
            }
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(themeManager.palette.surface)
                .shadow(color: Color.black.opacity(0.04), radius: 3, x: 0, y: 1)
        )
        .onAppear {
            if isRunning { isSpinning = true }
        }
        .onChange(of: isRunning) { newValue in
            isSpinning = newValue
        }
    }

    private func formatEventDuration(_ duration: TimeInterval) -> String {
        let minutes = Int(duration) / 60
        let seconds = Int(duration) % 60
        return String(format: "%d:%02d", minutes, seconds)
    }
}

// MARK: - Tab Button

struct TabButton: View {
    let title: String
    let isSelected: Bool
    let onSelect: () -> Void
    let onClose: () -> Void

    @State private var isHovering = false
    @ObservedObject var themeManager = ThemeManager.shared

    var body: some View {
        HStack(spacing: 4) {
            Button(action: onSelect) {
                Text(title)
                    .font(.system(.caption, design: .rounded))
                    .fontWeight(isSelected ? .semibold : .regular)
                    .foregroundColor(isSelected ? .white : .primary)
                    .lineLimit(1)
            }
            .buttonStyle(.plain)

            if isSelected || isHovering {
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundColor(isSelected ? .white.opacity(0.8) : .secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(isSelected ? themeManager.palette.primary : themeManager.palette.surface)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.gray.opacity(0.2), lineWidth: isSelected ? 0 : 1)
        )
        .onHover { isHovering = $0 }
    }
}

// MARK: - Project Picker Row

struct ProjectPickerRow: View {
    let path: String
    let isAlreadyOpen: Bool
    let onSelect: () -> Void

    private var projectName: String {
        (path as NSString).lastPathComponent
    }

    var body: some View {
        Button(action: onSelect) {
            HStack {
                Image(systemName: "folder.fill")
                    .foregroundColor(.blue)
                    .font(.caption)

                Text(projectName)
                    .font(.system(.caption, design: .rounded))

                Spacer()

                if isAlreadyOpen {
                    Text("Open")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.gray.opacity(0.2))
                        .cornerRadius(4)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Preview

#Preview {
    MenuBarView(socketServer: SocketServer())
}
