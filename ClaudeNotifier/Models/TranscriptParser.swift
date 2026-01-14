//
//  TranscriptParser.swift
//  ClaudeNotifier
//
//  Parses Claude Code JSONL transcript files to extract session information.
//

import Foundation

/// Static parser for Claude Code JSONL transcript files.
///
/// Claude Code stores session transcripts as JSONL (JSON Lines) files,
/// where each line is a separate JSON object representing a message
/// in the conversation. This parser extracts useful information like
/// the user's initial prompt, assistant's final response, and timestamps.
enum TranscriptParser {

    // MARK: - Types

    /// The result of parsing a transcript file.
    struct ParseResult {
        /// A summary of the conversation (last assistant message).
        let summary: String

        /// The timestamp of the first message in the transcript.
        let firstTimestamp: Date?

        /// The user's initial prompt/question.
        let userPrompt: String?
    }

    /// Represents the type of message in the transcript.
    private enum MessageType: String {
        case user
        case assistant
        case system
    }

    // MARK: - Parsing

    /// Parses a Claude Code transcript file.
    ///
    /// This method reads a JSONL transcript file and extracts:
    /// - The first user message as the prompt
    /// - The last assistant message as a summary
    /// - The timestamp of the first message
    ///
    /// - Parameter path: The file path to the transcript.
    /// - Returns: A tuple containing the summary, first timestamp, and user prompt.
    static func parseTranscript(at path: String) -> (summary: String, firstTimestamp: Date?, userPrompt: String?) {
        let result = parse(path: path)
        return (result.summary, result.firstTimestamp, result.userPrompt)
    }

    /// Parses a transcript file and returns a ParseResult struct.
    ///
    /// - Parameter path: The file path to the transcript.
    /// - Returns: A ParseResult containing extracted information.
    static func parse(path: String) -> ParseResult {
        // Verify file exists
        guard FileManager.default.fileExists(atPath: path) else {
            return ParseResult(
                summary: "Transcript file not found",
                firstTimestamp: nil,
                userPrompt: nil
            )
        }

        // Read file contents
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return ParseResult(
                summary: "Unable to read transcript",
                firstTimestamp: nil,
                userPrompt: nil
            )
        }

        // Parse JSONL (each line is a separate JSON object)
        let lines = contents.components(separatedBy: .newlines)
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }

        var firstTimestamp: Date?
        var userPrompt: String?
        var lastAssistantText: String?

        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        // Also try without fractional seconds
        let dateFormatterNoFraction = ISO8601DateFormatter()
        dateFormatterNoFraction.formatOptions = [.withInternetDateTime]

        for line in lines {
            guard let data = line.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
            }

            // Extract timestamp from first valid entry
            if firstTimestamp == nil,
               let timestampString = json["timestamp"] as? String {
                firstTimestamp = dateFormatter.date(from: timestampString)
                    ?? dateFormatterNoFraction.date(from: timestampString)
            }

            // Get message type
            guard let typeString = json["type"] as? String else {
                continue
            }

            // Extract content based on message type
            let content = extractContent(from: json)

            switch typeString {
            case "user":
                // Capture first user message as prompt
                if userPrompt == nil, let content = content, !content.isEmpty {
                    userPrompt = truncateText(content, maxLength: 500)
                }

            case "assistant":
                // Always update to get the last assistant message
                if let content = content, !content.isEmpty {
                    lastAssistantText = content
                }

            default:
                break
            }
        }

        // Create summary from last assistant text
        let summary: String
        if let assistantText = lastAssistantText {
            summary = createSummary(from: assistantText)
        } else {
            summary = "No assistant response found"
        }

        return ParseResult(
            summary: summary,
            firstTimestamp: firstTimestamp,
            userPrompt: userPrompt
        )
    }

    // MARK: - Content Extraction

    /// Extracts text content from a message JSON object.
    ///
    /// Message content can be either a simple string or an array of
    /// content blocks (each with type and text fields).
    ///
    /// - Parameter json: The message JSON dictionary.
    /// - Returns: The extracted text content, or nil if not found.
    private static func extractContent(from json: [String: Any]) -> String? {
        guard let message = json["message"] as? [String: Any] else {
            return nil
        }

        guard let content = message["content"] else {
            return nil
        }

        // Content can be a simple string
        if let stringContent = content as? String {
            return stringContent
        }

        // Or an array of content blocks
        if let arrayContent = content as? [[String: Any]] {
            let textParts = arrayContent.compactMap { block -> String? in
                // Only extract text blocks
                guard let blockType = block["type"] as? String,
                      blockType == "text",
                      let text = block["text"] as? String else {
                    return nil
                }
                return text
            }

            return textParts.joined(separator: "\n")
        }

        return nil
    }

    // MARK: - Text Processing

    /// Creates a summary from assistant text.
    ///
    /// - Parameter text: The full assistant response text.
    /// - Returns: A truncated summary suitable for notifications.
    private static func createSummary(from text: String) -> String {
        // Clean up the text
        let cleaned = text
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\n+", with: " ", options: .regularExpression)
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)

        return truncateText(cleaned, maxLength: 200)
    }

    /// Truncates text to a maximum length, adding ellipsis if needed.
    ///
    /// - Parameters:
    ///   - text: The text to truncate.
    ///   - maxLength: Maximum character count.
    /// - Returns: The truncated text.
    private static func truncateText(_ text: String, maxLength: Int) -> String {
        guard text.count > maxLength else {
            return text
        }

        let truncated = String(text.prefix(maxLength))

        // Try to break at a word boundary
        if let lastSpace = truncated.lastIndex(of: " ") {
            return String(truncated[..<lastSpace]) + "..."
        }

        return truncated + "..."
    }
}

// MARK: - Convenience Extensions

extension TranscriptParser {

    /// Checks if a transcript file exists at the given path.
    ///
    /// - Parameter path: The file path to check.
    /// - Returns: `true` if the file exists.
    static func transcriptExists(at path: String) -> Bool {
        return FileManager.default.fileExists(atPath: path)
    }

    /// Gets the file size of a transcript in bytes.
    ///
    /// - Parameter path: The file path to the transcript.
    /// - Returns: The file size in bytes, or nil if the file doesn't exist.
    static func transcriptSize(at path: String) -> UInt64? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attributes[.size] as? UInt64 else {
            return nil
        }
        return size
    }

    /// Parses only the first user prompt from a transcript.
    ///
    /// This is a lightweight parse that stops after finding the first user message.
    ///
    /// - Parameter path: The file path to the transcript.
    /// - Returns: The first user prompt, or nil if not found.
    static func parseFirstPrompt(at path: String) -> String? {
        guard FileManager.default.fileExists(atPath: path),
              let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return nil
        }

        let lines = contents.components(separatedBy: .newlines)

        for line in lines {
            guard !line.trimmingCharacters(in: .whitespaces).isEmpty,
                  let data = line.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let type = json["type"] as? String,
                  type == "user" else {
                continue
            }

            if let content = extractContent(from: json), !content.isEmpty {
                return truncateText(content, maxLength: 500)
            }
        }

        return nil
    }
}
