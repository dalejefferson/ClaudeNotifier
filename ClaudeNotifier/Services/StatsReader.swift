//
//  StatsReader.swift
//  ClaudeNotifier
//
//  Reads Claude Code usage statistics from ~/.claude/stats-cache.json
//

import Foundation

// MARK: - Stats Models

struct ClaudeStats: Codable {
    let version: Int?
    let lastComputedDate: String?
    let dailyActivity: [DailyActivity]?
    let dailyModelTokens: [DailyModelTokens]?
}

struct DailyActivity: Codable {
    let date: String
    let messageCount: Int
    let sessionCount: Int
    let toolCallCount: Int
}

struct DailyModelTokens: Codable {
    let date: String
    let tokensByModel: [String: Int]
}

// MARK: - Usage Summary

struct UsageSummary {
    let modelName: String
    let tokensToday: Int
    let messagestoday: Int
    let sessionsToday: Int

    var formattedTokens: String {
        if tokensToday >= 1_000_000 {
            return String(format: "%.1fM", Double(tokensToday) / 1_000_000)
        } else if tokensToday >= 1_000 {
            return String(format: "%.1fK", Double(tokensToday) / 1_000)
        }
        return "\(tokensToday)"
    }

    var shortModelName: String {
        // Convert "claude-opus-4-5-20251101" to "Opus 4.5"
        if modelName.contains("opus") {
            return "Opus 4.5"
        } else if modelName.contains("sonnet") {
            return "Sonnet 4.5"
        } else if modelName.contains("haiku") {
            return "Haiku 4.5"
        }
        return modelName
    }
}

// MARK: - Stats Reader

final class StatsReader: ObservableObject {

    static let shared = StatsReader()

    @Published private(set) var currentUsage: UsageSummary?
    @Published private(set) var lastUpdated: Date?

    private let statsPath: String
    private var refreshTimer: Timer?
    private var lastModificationDate: Date?

    // Static formatter (avoid recreation on each refresh)
    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter
    }()

    init() {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        self.statsPath = homeDir.appendingPathComponent(".claude/stats-cache.json").path

        // Initial load
        refresh()

        // Refresh every 60 seconds (was 30s)
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    deinit {
        refreshTimer?.invalidate()
    }

    func refresh() {
        // Check file modification time to avoid unnecessary reads
        if let attrs = try? FileManager.default.attributesOfItem(atPath: statsPath),
           let modDate = attrs[.modificationDate] as? Date {
            if let lastMod = lastModificationDate, modDate <= lastMod {
                // File hasn't changed, skip read
                return
            }
            lastModificationDate = modDate
        }

        guard let data = FileManager.default.contents(atPath: statsPath) else {
            return
        }

        do {
            let stats = try JSONDecoder().decode(ClaudeStats.self, from: data)

            // Get today's date string using static formatter
            let today = Self.dateFormatter.string(from: Date())

            // Find today's activity or most recent
            var messagesCount = 0
            var sessionsCount = 0

            if let activity = stats.dailyActivity?.first(where: { $0.date == today }) {
                messagesCount = activity.messageCount
                sessionsCount = activity.sessionCount
            } else if let latest = stats.dailyActivity?.last {
                messagesCount = latest.messageCount
                sessionsCount = latest.sessionCount
            }

            // Find today's tokens or most recent
            var modelName = "Unknown"
            var tokensCount = 0

            if let tokens = stats.dailyModelTokens?.first(where: { $0.date == today }) {
                // Get the model with most tokens today
                if let (name, count) = tokens.tokensByModel.max(by: { $0.value < $1.value }) {
                    modelName = name
                    tokensCount = count
                }
            } else if let latest = stats.dailyModelTokens?.last {
                if let (name, count) = latest.tokensByModel.max(by: { $0.value < $1.value }) {
                    modelName = name
                    tokensCount = count
                }
            }

            DispatchQueue.main.async {
                self.currentUsage = UsageSummary(
                    modelName: modelName,
                    tokensToday: tokensCount,
                    messagestoday: messagesCount,
                    sessionsToday: sessionsCount
                )
                self.lastUpdated = Date()
            }
        } catch {
            print("StatsReader: Failed to parse stats: \(error)")
        }
    }
}
