//
//  UsageProgressBar.swift
//  ClaudeNotifier
//

import SwiftUI

struct UsageProgressBar: View {
    let utilization: Double  // 0.0 to 1.0 (amount USED)
    let label: String
    let resetTime: String
    @ObservedObject var themeManager = ThemeManager.shared

    private var remaining: Double {
        max(0, 1.0 - utilization)
    }

    private var statusColor: Color {
        if remaining > 0.5 {
            return themeManager.palette.success
        } else if remaining > 0.2 {
            return themeManager.palette.warning
        } else {
            return themeManager.palette.critical
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Header row
            HStack {
                HStack(spacing: 4) {
                    Image(systemName: "gauge.medium")
                        .font(.system(size: 11))
                        .foregroundColor(themeManager.palette.textSecondary)
                    Text(label)
                        .font(.system(size: 12))
                        .foregroundColor(themeManager.palette.textSecondary)
                }

                Spacer()

                Text("\(Int(remaining * 100))% remaining")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(statusColor)
            }

            // Progress bar
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    // Background track
                    RoundedRectangle(cornerRadius: 4)
                        .fill(themeManager.palette.border)
                        .frame(height: 8)

                    // Filled portion (shows remaining, not used)
                    RoundedRectangle(cornerRadius: 4)
                        .fill(
                            LinearGradient(
                                colors: [statusColor, statusColor.opacity(0.8)],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .frame(width: max(0, geometry.size.width * remaining), height: 8)
                        .animation(.easeOut(duration: 0.5), value: remaining)
                }
            }
            .frame(height: 8)

            // Reset time
            Text("Resets in \(resetTime)")
                .font(.system(size: 10))
                .foregroundColor(themeManager.palette.textTertiary)
        }
    }
}

#Preview {
    VStack(spacing: 20) {
        UsageProgressBar(utilization: 0.6, label: "5-Hour Usage", resetTime: "2h 15m")
        UsageProgressBar(utilization: 0.3, label: "7-Day Usage", resetTime: "3d 12h")
    }
    .padding()
    .frame(width: 350)
}
