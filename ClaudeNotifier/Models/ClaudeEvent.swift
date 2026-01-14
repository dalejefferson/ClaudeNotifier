//
//  ClaudeEvent.swift
//  ClaudeNotifier
//
//  Represents events received from Claude Code hooks.
//

import Foundation

// MARK: - Event Type

/// The type of hook event received from Claude Code.
enum EventType: String, Codable, CaseIterable {
    case stop = "Stop"
    case subagentStop = "SubagentStop"
    case notification = "Notification"
    case sessionStart = "SessionStart"

    var displayName: String {
        switch self {
        case .stop: return "Task Completed"
        case .subagentStop: return "Subagent Completed"
        case .notification: return "Notification"
        case .sessionStart: return "Session Started"
        }
    }
}

// MARK: - Stop Reason

/// The reason why Claude stopped processing.
enum StopReason: String, Codable, CaseIterable {
    case stopTool = "stop_tool"
    case endTurn = "end_turn"
    case maxTurns = "max_turns"
    case interrupt = "interrupt"

    var displayName: String {
        switch self {
        case .stopTool: return "Explicitly Stopped"
        case .endTurn: return "Completed"
        case .maxTurns: return "Max Turns Reached"
        case .interrupt: return "Interrupted"
        }
    }
}

// MARK: - Prompt Matcher

/// The type of prompt matcher for notification events.
enum PromptMatcher: String, Codable, CaseIterable {
    case permissionPrompt = "permission_prompt"
    case idlePrompt = "idle_prompt"
}

// MARK: - Claude Event

/// A Codable struct representing events from Claude Code hooks.
struct ClaudeEvent: Codable, Identifiable {

    // MARK: - Properties

    let id: UUID
    let sessionId: String
    let transcriptPath: String
    let cwd: String
    let type: EventType
    let stopReason: StopReason?
    let message: String?
    let matcher: PromptMatcher?
    var taskSummary: String?
    var duration: TimeInterval?
    let timestamp: Date

    // MARK: - Coding Keys

    private enum CodingKeys: String, CodingKey {
        case id
        case sessionId = "session_id"
        case transcriptPath = "transcript_path"
        case cwd
        case type = "hook_event_name"
        case stopReason = "stop_reason"
        case message
        case matcher
        case taskSummary
        case duration
        case timestamp
    }

    // MARK: - Initialization

    init(
        id: UUID = UUID(),
        sessionId: String = "",
        transcriptPath: String = "",
        cwd: String = "",
        type: EventType,
        stopReason: StopReason? = nil,
        message: String? = nil,
        matcher: PromptMatcher? = nil,
        taskSummary: String? = nil,
        duration: TimeInterval? = nil,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.sessionId = sessionId
        self.transcriptPath = transcriptPath
        self.cwd = cwd
        self.type = type
        self.stopReason = stopReason
        self.message = message
        self.matcher = matcher
        self.taskSummary = taskSummary
        self.duration = duration
        self.timestamp = timestamp
    }

    // MARK: - Custom Decoding

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.sessionId = try container.decodeIfPresent(String.self, forKey: .sessionId) ?? ""
        self.transcriptPath = try container.decodeIfPresent(String.self, forKey: .transcriptPath) ?? ""
        self.cwd = try container.decodeIfPresent(String.self, forKey: .cwd) ?? ""
        self.type = try container.decode(EventType.self, forKey: .type)
        self.stopReason = try container.decodeIfPresent(StopReason.self, forKey: .stopReason)
        self.message = try container.decodeIfPresent(String.self, forKey: .message)
        self.matcher = try container.decodeIfPresent(PromptMatcher.self, forKey: .matcher)
        self.taskSummary = try container.decodeIfPresent(String.self, forKey: .taskSummary)
        self.duration = try container.decodeIfPresent(TimeInterval.self, forKey: .duration)
        self.timestamp = try container.decodeIfPresent(Date.self, forKey: .timestamp) ?? Date()
    }
}

// MARK: - Convenience Extensions

extension ClaudeEvent {

    var eventDescription: String {
        switch type {
        case .stop:
            if let reason = stopReason {
                return "Stopped (\(reason.displayName))"
            }
            return "Stopped"
        case .subagentStop:
            return "Subagent Stopped"
        case .notification:
            if let matcher = matcher {
                return "Notification (\(matcher.rawValue))"
            }
            return "Notification"
        case .sessionStart:
            return "Session Started"
        }
    }

    var projectName: String {
        URL(fileURLWithPath: cwd).lastPathComponent
    }

    var formattedDuration: String? {
        guard let duration = duration else { return nil }

        let hours = Int(duration) / 3600
        let minutes = (Int(duration) % 3600) / 60
        let seconds = Int(duration) % 60

        if hours > 0 {
            return String(format: "%d:%02d:%02d", hours, minutes, seconds)
        } else {
            return String(format: "%d:%02d", minutes, seconds)
        }
    }
}
