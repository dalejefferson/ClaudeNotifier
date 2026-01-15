//
//  SessionTracker.swift
//  ClaudeNotifier
//
//  Tracks Claude Code session start times for duration calculation.
//

import Foundation
import Combine

/// Tracks session start times for Claude Code sessions.
///
/// This class maintains a dictionary of session IDs to their start times,
/// allowing calculation of session durations. Session data is persisted
/// to disk to survive app restarts.
final class SessionTracker: ObservableObject {

    // MARK: - Properties

    /// Dictionary mapping session IDs to their start times.
    @Published private(set) var sessions: [String: Date] = [:]

    /// Set of active subagent session IDs.
    @Published private(set) var activeSubagents: Set<String> = []

    /// Number of currently active subagents.
    var activeSubagentCount: Int {
        return activeSubagents.count
    }

    /// Total number of active agents (main sessions + subagents).
    var totalActiveAgentCount: Int {
        return sessions.count + activeSubagents.count
    }

    /// Path to the persistence file.
    private let persistencePath: String

    /// JSON encoder for persistence.
    private let encoder = JSONEncoder()

    /// JSON decoder for persistence.
    private let decoder = JSONDecoder()

    /// Batched persistence timer.
    private var persistTimer: Timer?
    private var needsPersist = false
    private let batchInterval: TimeInterval = 2.0

    // MARK: - Singleton

    /// Shared instance for app-wide session tracking.
    static let shared = SessionTracker()

    // MARK: - Initialization

    /// Creates a new SessionTracker with the specified persistence path.
    ///
    /// - Parameter persistencePath: Path to save session data.
    ///   Defaults to `~/.claude-notifier-sessions.json`.
    init(persistencePath: String? = nil) {
        self.persistencePath = persistencePath ?? Self.defaultPersistencePath

        // Configure encoder for compact JSON
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]  // Compact JSON (no prettyPrinted)
        decoder.dateDecodingStrategy = .iso8601

        // Load any previously saved sessions
        load()
    }

    /// Default path for session persistence file.
    private static var defaultPersistencePath: String {
        let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        return homeDirectory.appendingPathComponent(".claude-notifier-sessions.json").path
    }

    // MARK: - Session Management

    /// Records the start time for a session if not already tracked.
    ///
    /// This method only records the start time if the session is not
    /// already being tracked, preserving the original start time.
    ///
    /// - Parameter sessionId: The Claude Code session ID.
    /// - Returns: `true` if the session was newly recorded, `false` if already tracked.
    @discardableResult
    func recordStart(sessionId: String) -> Bool {
        guard sessions[sessionId] == nil else {
            return false
        }

        sessions[sessionId] = Date()
        schedulePersist()
        return true
    }

    /// Records the start time for a session with a specific timestamp.
    ///
    /// - Parameters:
    ///   - sessionId: The Claude Code session ID.
    ///   - timestamp: The start time to record.
    /// - Returns: `true` if the session was newly recorded, `false` if already tracked.
    @discardableResult
    func recordStart(sessionId: String, timestamp: Date) -> Bool {
        guard sessions[sessionId] == nil else {
            return false
        }

        sessions[sessionId] = timestamp
        schedulePersist()
        return true
    }

    /// Gets the elapsed duration for a session.
    ///
    /// - Parameter sessionId: The Claude Code session ID.
    /// - Returns: The time interval since the session started, or `nil` if not tracked.
    func getDuration(sessionId: String) -> TimeInterval? {
        guard let startTime = sessions[sessionId] else {
            return nil
        }

        return Date().timeIntervalSince(startTime)
    }

    /// Gets the duration between the session start and a specific end time.
    ///
    /// - Parameters:
    ///   - sessionId: The Claude Code session ID.
    ///   - endTime: The end time to calculate duration to.
    /// - Returns: The time interval, or `nil` if the session is not tracked.
    func getDuration(sessionId: String, until endTime: Date) -> TimeInterval? {
        guard let startTime = sessions[sessionId] else {
            return nil
        }

        return endTime.timeIntervalSince(startTime)
    }

    /// Gets the start time for a session.
    ///
    /// - Parameter sessionId: The Claude Code session ID.
    /// - Returns: The start time, or `nil` if not tracked.
    func getStartTime(sessionId: String) -> Date? {
        return sessions[sessionId]
    }

    /// Removes a session from tracking.
    ///
    /// - Parameter sessionId: The Claude Code session ID to remove.
    func clearSession(sessionId: String) {
        sessions.removeValue(forKey: sessionId)
        schedulePersist()
    }

    /// Removes all tracked sessions.
    func clearAllSessions() {
        sessions.removeAll()
        schedulePersist()
    }

    // MARK: - Subagent Management

    /// Records a subagent as active.
    ///
    /// - Parameter sessionId: The subagent's session ID.
    /// - Returns: `true` if the subagent was newly recorded, `false` if already tracked.
    @discardableResult
    func recordSubagentStart(sessionId: String) -> Bool {
        guard !activeSubagents.contains(sessionId) else {
            return false
        }

        activeSubagents.insert(sessionId)
        return true
    }

    /// Removes a subagent from active tracking.
    ///
    /// - Parameter sessionId: The subagent's session ID.
    /// - Returns: `true` if the subagent was removed, `false` if not tracked.
    @discardableResult
    func recordSubagentStop(sessionId: String) -> Bool {
        guard activeSubagents.contains(sessionId) else {
            return false
        }

        activeSubagents.remove(sessionId)
        return true
    }

    /// Removes all active subagents.
    func clearAllSubagents() {
        activeSubagents.removeAll()
    }

    /// Checks if a session is being tracked.
    ///
    /// - Parameter sessionId: The Claude Code session ID.
    /// - Returns: `true` if the session is being tracked.
    func isTracking(sessionId: String) -> Bool {
        return sessions[sessionId] != nil
    }

    /// Returns the number of tracked sessions.
    var sessionCount: Int {
        return sessions.count
    }

    // MARK: - Persistence

    /// Schedules a batched persist operation.
    private func schedulePersist() {
        needsPersist = true
        guard persistTimer == nil else { return }
        persistTimer = Timer.scheduledTimer(withTimeInterval: batchInterval, repeats: false) { [weak self] _ in
            self?.flush()
        }
    }

    /// Flushes any pending writes to disk immediately.
    func flush() {
        guard needsPersist else { return }
        save()
        needsPersist = false
        persistTimer?.invalidate()
        persistTimer = nil
    }

    /// Saves the current sessions to disk.
    ///
    /// This method writes the sessions dictionary to a JSON file
    /// at the configured persistence path.
    func save() {
        do {
            let data = try encoder.encode(sessions)
            try data.write(to: URL(fileURLWithPath: persistencePath))
        } catch {
            print("SessionTracker: Failed to save sessions: \(error.localizedDescription)")
        }
    }

    /// Loads sessions from disk.
    ///
    /// This method reads the sessions dictionary from the JSON file
    /// at the configured persistence path. If the file doesn't exist
    /// or is invalid, the sessions dictionary remains empty.
    func load() {
        let fileURL = URL(fileURLWithPath: persistencePath)

        guard FileManager.default.fileExists(atPath: persistencePath) else {
            // No saved sessions file, start fresh
            return
        }

        do {
            let data = try Data(contentsOf: fileURL)
            sessions = try decoder.decode([String: Date].self, from: data)
        } catch {
            print("SessionTracker: Failed to load sessions: \(error.localizedDescription)")
            // Start with empty sessions on failure
            sessions = [:]
        }
    }

    // MARK: - Cleanup

    /// Removes sessions older than the specified time interval.
    ///
    /// This is useful for cleaning up stale sessions that may have
    /// been left over from crashed or terminated Claude Code instances.
    ///
    /// - Parameter maxAge: Maximum age for sessions to keep.
    /// - Returns: The number of sessions removed.
    @discardableResult
    func cleanupStaleSessions(olderThan maxAge: TimeInterval) -> Int {
        let cutoffDate = Date().addingTimeInterval(-maxAge)
        let initialCount = sessions.count

        sessions = sessions.filter { _, startTime in
            startTime > cutoffDate
        }

        let removedCount = initialCount - sessions.count

        if removedCount > 0 {
            schedulePersist()
        }

        return removedCount
    }
}

// MARK: - Convenience Extensions

extension SessionTracker {

    /// Cleans up sessions older than 24 hours.
    ///
    /// - Returns: The number of sessions removed.
    @discardableResult
    func cleanupDayStaleSessions() -> Int {
        return cleanupStaleSessions(olderThan: 24 * 60 * 60)
    }

    /// Cleans up sessions older than 1 hour.
    ///
    /// - Returns: The number of sessions removed.
    @discardableResult
    func cleanupHourStaleSessions() -> Int {
        return cleanupStaleSessions(olderThan: 60 * 60)
    }
}
