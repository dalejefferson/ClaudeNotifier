//
//  EventStore.swift
//  ClaudeNotifier
//
//  Persistent storage for Claude Code events with analytics support.
//

import Foundation
import Combine

/// Storage container for persisted events with metadata.
struct EventStoreData: Codable {
    var events: [ClaudeEvent]
    var metadata: EventStoreMetadata

    init(events: [ClaudeEvent] = [], metadata: EventStoreMetadata = EventStoreMetadata()) {
        self.events = events
        self.metadata = metadata
    }
}

/// Metadata about the event store.
struct EventStoreMetadata: Codable {
    let version: Int
    var lastCleanup: Date

    init(version: Int = 1, lastCleanup: Date = Date()) {
        self.version = version
        self.lastCleanup = lastCleanup
    }
}

/// Persistent storage for enriched Claude Code events.
///
/// Events are stored in a JSON file and support querying for analytics.
/// Automatic cleanup removes events older than 30 days by default.
final class EventStore: ObservableObject {

    // MARK: - Constants

    /// Default retention period (30 days).
    static let defaultRetentionDays: TimeInterval = 30 * 24 * 60 * 60

    // MARK: - Properties

    /// All stored events, sorted by timestamp (newest first).
    @Published private(set) var events: [ClaudeEvent] = []

    /// Cached analytics for today (avoids recalculation on every access).
    @Published private(set) var cachedTodayStats: AnalyticsCalculator.DailySummary = AnalyticsCalculator.DailySummary(
        date: Date(),
        taskCount: 0,
        totalDuration: 0,
        averageDuration: 0,
        completedCount: 0,
        interruptedCount: 0,
        projectBreakdown: [:]
    )

    /// Path to the persistence file.
    private let persistencePath: String

    /// Batched persistence timer.
    private var persistTimer: Timer?
    private var needsPersist = false
    private let batchInterval: TimeInterval = 5.0

    /// JSON encoder for persistence (compact JSON for smaller files).
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]  // Compact JSON (no prettyPrinted)
        return encoder
    }()

    /// JSON decoder for persistence.
    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    /// Store metadata.
    private var metadata = EventStoreMetadata()

    // MARK: - Singleton

    /// Shared instance for app-wide event storage.
    static let shared = EventStore()

    // MARK: - Initialization

    /// Creates a new EventStore with the specified persistence path.
    ///
    /// - Parameter persistencePath: Path to save event data.
    ///   Defaults to `~/.claude-notifier-events.json`.
    init(persistencePath: String? = nil) {
        self.persistencePath = persistencePath ?? Self.defaultPersistencePath
        load()
        updateCachedAnalytics()
    }

    /// Default path for event persistence file.
    private static var defaultPersistencePath: String {
        let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
        return homeDirectory.appendingPathComponent(".claude-notifier-events.json").path
    }

    // MARK: - Event Management

    /// Saves an enriched event to the store.
    ///
    /// - Parameter event: The enriched ClaudeEvent to save.
    func save(event: ClaudeEvent) {
        // Don't save session start events (internal tracking only)
        guard event.type != .sessionStart else { return }

        events.insert(event, at: 0)  // Newest first
        updateCachedAnalytics()  // Update cache immediately
        schedulePersist()  // Schedule batched write
    }

    // MARK: - Batched Persistence

    /// Schedules a batched persist operation.
    private func schedulePersist() {
        needsPersist = true
        guard persistTimer == nil else { return }
        persistTimer = Timer.scheduledTimer(withTimeInterval: batchInterval, repeats: false) { [weak self] _ in
            self?.flushToDisk()
        }
    }

    /// Flushes any pending writes to disk immediately.
    func flushToDisk() {
        guard needsPersist else { return }
        persist()
        needsPersist = false
        persistTimer?.invalidate()
        persistTimer = nil
    }

    // MARK: - Analytics Caching

    /// Updates the cached analytics for today.
    private func updateCachedAnalytics() {
        cachedTodayStats = AnalyticsCalculator.todaySummary(from: events)
    }

    /// Returns all events within a date range.
    ///
    /// - Parameters:
    ///   - startDate: The start of the range (inclusive).
    ///   - endDate: The end of the range (inclusive).
    /// - Returns: Events within the specified range.
    func events(from startDate: Date, to endDate: Date) -> [ClaudeEvent] {
        return events.filter { event in
            event.timestamp >= startDate && event.timestamp <= endDate
        }
    }

    /// Returns events from today.
    func eventsToday() -> [ClaudeEvent] {
        let calendar = Calendar.current
        let startOfDay = calendar.startOfDay(for: Date())
        let endOfDay = calendar.date(byAdding: .day, value: 1, to: startOfDay)!
        return events(from: startOfDay, to: endOfDay)
    }

    /// Returns events from this week.
    func eventsThisWeek() -> [ClaudeEvent] {
        let calendar = Calendar.current
        let now = Date()
        guard let weekStart = calendar.date(from: calendar.dateComponents([.yearForWeekOfYear, .weekOfYear], from: now)) else {
            return []
        }
        let weekEnd = calendar.date(byAdding: .weekOfYear, value: 1, to: weekStart)!
        return events(from: weekStart, to: weekEnd)
    }

    /// Returns events for a specific project (by working directory).
    ///
    /// - Parameter cwd: The working directory path.
    /// - Returns: Events from that project.
    func events(forProject cwd: String) -> [ClaudeEvent] {
        return events.filter { $0.cwd == cwd }
    }

    /// Returns the most recent N events.
    ///
    /// - Parameter count: Maximum number of events to return.
    /// - Returns: The most recent events.
    func recentEvents(_ count: Int) -> [ClaudeEvent] {
        return Array(events.prefix(count))
    }

    /// Clears all stored events.
    func clearAll() {
        events.removeAll()
        updateCachedAnalytics()
        schedulePersist()
    }

    // MARK: - Persistence

    /// Persists events to disk.
    private func persist() {
        do {
            let data = EventStoreData(events: events, metadata: metadata)
            let jsonData = try encoder.encode(data)
            try jsonData.write(to: URL(fileURLWithPath: persistencePath))
        } catch {
            print("EventStore: Failed to save events: \(error.localizedDescription)")
        }
    }

    /// Loads events from disk.
    private func load() {
        let fileURL = URL(fileURLWithPath: persistencePath)

        guard FileManager.default.fileExists(atPath: persistencePath) else {
            return
        }

        do {
            let jsonData = try Data(contentsOf: fileURL)
            let data = try decoder.decode(EventStoreData.self, from: jsonData)
            events = data.events
            metadata = data.metadata
        } catch {
            print("EventStore: Failed to load events: \(error.localizedDescription)")
            events = []
        }
    }

    // MARK: - Cleanup

    /// Removes events older than the specified time interval.
    ///
    /// - Parameter maxAge: Maximum age for events to keep.
    /// - Returns: The number of events removed.
    @discardableResult
    func cleanup(olderThan maxAge: TimeInterval = defaultRetentionDays) -> Int {
        let cutoffDate = Date().addingTimeInterval(-maxAge)
        let initialCount = events.count

        events = events.filter { event in
            event.timestamp > cutoffDate
        }

        let removedCount = initialCount - events.count

        if removedCount > 0 {
            metadata.lastCleanup = Date()
            updateCachedAnalytics()
            schedulePersist()
        }

        return removedCount
    }

    /// Performs automatic cleanup on app launch.
    ///
    /// Only runs cleanup once per day to avoid excessive file writes.
    func performCleanup() {
        let calendar = Calendar.current
        if !calendar.isDateInToday(metadata.lastCleanup) {
            let removed = cleanup()
            if removed > 0 {
                print("EventStore: Cleaned up \(removed) old events")
            }
        }
    }

    // MARK: - Statistics

    /// Total number of stored events.
    var totalEventCount: Int {
        return events.count
    }

    /// Unique projects (working directories) in the store.
    var uniqueProjects: [String] {
        return Array(Set(events.map { $0.cwd })).sorted()
    }
}
