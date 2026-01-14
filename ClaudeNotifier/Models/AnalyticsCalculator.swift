//
//  AnalyticsCalculator.swift
//  ClaudeNotifier
//
//  Pure functions for computing task statistics from events.
//

import Foundation

/// Provides analytics calculations for Claude Code events.
enum AnalyticsCalculator {

    // MARK: - Summary Types

    /// Summary statistics for a single day.
    struct DailySummary {
        let date: Date
        let taskCount: Int
        let totalDuration: TimeInterval
        let averageDuration: TimeInterval
        let completedCount: Int
        let interruptedCount: Int
        let projectBreakdown: [String: Int]

        /// Formatted total duration (e.g., "2h 30m").
        var totalDurationFormatted: String {
            return formatDuration(totalDuration)
        }

        /// Formatted average duration (e.g., "5m 30s").
        var averageDurationFormatted: String {
            return formatDuration(averageDuration)
        }
    }

    /// Summary statistics for a week.
    struct WeeklySummary {
        let weekStart: Date
        let dailySummaries: [DailySummary]
        let totalTaskCount: Int
        let totalDuration: TimeInterval
        let averageDuration: TimeInterval
        let mostActiveProject: String?
        let busiestDay: DailySummary?

        /// Formatted total duration.
        var totalDurationFormatted: String {
            return formatDuration(totalDuration)
        }

        /// Formatted average duration.
        var averageDurationFormatted: String {
            return formatDuration(averageDuration)
        }
    }

    // MARK: - Daily Calculations

    /// Calculates summary statistics for events on a specific day.
    ///
    /// - Parameters:
    ///   - events: All events to analyze.
    ///   - date: The date to summarize.
    /// - Returns: Summary statistics for that day.
    static func dailySummary(from events: [ClaudeEvent], for date: Date) -> DailySummary {
        let calendar = Calendar.current
        let startOfDay = calendar.startOfDay(for: date)
        let endOfDay = calendar.date(byAdding: .day, value: 1, to: startOfDay)!

        let dayEvents = events.filter { event in
            event.timestamp >= startOfDay && event.timestamp < endOfDay &&
            event.type != .sessionStart && event.type != .notification
        }

        return calculateDailySummary(from: dayEvents, date: date)
    }

    /// Calculates summary statistics for today.
    static func todaySummary(from events: [ClaudeEvent]) -> DailySummary {
        return dailySummary(from: events, for: Date())
    }

    // MARK: - Weekly Calculations

    /// Calculates summary statistics for a week.
    ///
    /// - Parameters:
    ///   - events: All events to analyze.
    ///   - date: Any date within the week.
    /// - Returns: Summary statistics for that week.
    static func weeklySummary(from events: [ClaudeEvent], weekOf date: Date) -> WeeklySummary {
        let calendar = Calendar.current
        guard let weekStart = calendar.date(from: calendar.dateComponents([.yearForWeekOfYear, .weekOfYear], from: date)) else {
            return emptyWeeklySummary(weekStart: date)
        }

        // Calculate daily summaries for each day of the week
        var dailySummaries: [DailySummary] = []
        for dayOffset in 0..<7 {
            guard let dayDate = calendar.date(byAdding: .day, value: dayOffset, to: weekStart) else { continue }
            let summary = dailySummary(from: events, for: dayDate)
            dailySummaries.append(summary)
        }

        // Aggregate statistics
        let totalTaskCount = dailySummaries.reduce(0) { $0 + $1.taskCount }
        let totalDuration = dailySummaries.reduce(0) { $0 + $1.totalDuration }
        let averageDuration = totalTaskCount > 0 ? totalDuration / Double(totalTaskCount) : 0

        // Find most active project
        var projectCounts: [String: Int] = [:]
        for summary in dailySummaries {
            for (project, count) in summary.projectBreakdown {
                projectCounts[project, default: 0] += count
            }
        }
        let mostActiveProject = projectCounts.max(by: { $0.value < $1.value })?.key

        // Find busiest day
        let busiestDay = dailySummaries.max(by: { $0.taskCount < $1.taskCount })

        return WeeklySummary(
            weekStart: weekStart,
            dailySummaries: dailySummaries,
            totalTaskCount: totalTaskCount,
            totalDuration: totalDuration,
            averageDuration: averageDuration,
            mostActiveProject: mostActiveProject,
            busiestDay: busiestDay?.taskCount ?? 0 > 0 ? busiestDay : nil
        )
    }

    /// Calculates summary statistics for the current week.
    static func thisWeekSummary(from events: [ClaudeEvent]) -> WeeklySummary {
        return weeklySummary(from: events, weekOf: Date())
    }

    // MARK: - Private Helpers

    private static func calculateDailySummary(from events: [ClaudeEvent], date: Date) -> DailySummary {
        let taskCount = events.count
        let totalDuration = events.compactMap { $0.duration }.reduce(0, +)
        let averageDuration = taskCount > 0 ? totalDuration / Double(taskCount) : 0

        let completedCount = events.filter { event in
            event.stopReason == .endTurn || event.stopReason == .stopTool
        }.count

        let interruptedCount = events.filter { event in
            event.stopReason == .interrupt
        }.count

        // Project breakdown
        var projectBreakdown: [String: Int] = [:]
        for event in events {
            let projectName = extractProjectName(from: event.cwd)
            projectBreakdown[projectName, default: 0] += 1
        }

        return DailySummary(
            date: date,
            taskCount: taskCount,
            totalDuration: totalDuration,
            averageDuration: averageDuration,
            completedCount: completedCount,
            interruptedCount: interruptedCount,
            projectBreakdown: projectBreakdown
        )
    }

    private static func emptyWeeklySummary(weekStart: Date) -> WeeklySummary {
        return WeeklySummary(
            weekStart: weekStart,
            dailySummaries: [],
            totalTaskCount: 0,
            totalDuration: 0,
            averageDuration: 0,
            mostActiveProject: nil,
            busiestDay: nil
        )
    }

    /// Extracts a readable project name from a path.
    private static func extractProjectName(from path: String) -> String {
        return (path as NSString).lastPathComponent
    }
}

// MARK: - Duration Formatting

/// Formats a duration as a human-readable string.
///
/// - Parameter duration: The time interval to format.
/// - Returns: A formatted string (e.g., "2h 30m" or "5m 30s").
func formatDuration(_ duration: TimeInterval) -> String {
    let totalSeconds = Int(duration)

    if totalSeconds < 60 {
        return "\(totalSeconds)s"
    }

    let hours = totalSeconds / 3600
    let minutes = (totalSeconds % 3600) / 60
    let seconds = totalSeconds % 60

    if hours > 0 {
        if minutes > 0 {
            return "\(hours)h \(minutes)m"
        }
        return "\(hours)h"
    }

    if seconds > 0 && minutes < 10 {
        return "\(minutes)m \(seconds)s"
    }

    return "\(minutes)m"
}
