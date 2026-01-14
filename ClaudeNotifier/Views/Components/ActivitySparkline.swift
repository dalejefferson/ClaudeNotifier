//
//  ActivitySparkline.swift
//  ClaudeNotifier
//

import SwiftUI

struct ActivitySparkline: View {
    let hourlyData: [Int]  // 24 values for each hour, or fewer
    @ObservedObject var themeManager = ThemeManager.shared

    private let chartHeight: CGFloat = 40

    private var maxValue: Int {
        max(hourlyData.max() ?? 1, 1)
    }

    private var normalizedData: [CGFloat] {
        hourlyData.map { CGFloat($0) / CGFloat(maxValue) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Activity Today")
                .font(.system(size: 11))
                .foregroundColor(themeManager.palette.textSecondary)

            GeometryReader { geometry in
                let width = geometry.size.width
                let height = geometry.size.height
                let stepX = normalizedData.count > 1 ? width / CGFloat(normalizedData.count - 1) : width

                ZStack {
                    // Gradient fill under the line
                    Path { path in
                        guard !normalizedData.isEmpty else { return }

                        path.move(to: CGPoint(x: 0, y: height))

                        for (index, value) in normalizedData.enumerated() {
                            let x = CGFloat(index) * stepX
                            let y = height - (value * height * 0.9)

                            if index == 0 {
                                path.addLine(to: CGPoint(x: x, y: y))
                            } else {
                                path.addLine(to: CGPoint(x: x, y: y))
                            }
                        }

                        path.addLine(to: CGPoint(x: width, y: height))
                        path.closeSubpath()
                    }
                    .fill(
                        LinearGradient(
                            colors: [
                                themeManager.palette.primary.opacity(0.25),
                                themeManager.palette.primary.opacity(0.05)
                            ],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )

                    // Line stroke
                    Path { path in
                        guard !normalizedData.isEmpty else { return }

                        for (index, value) in normalizedData.enumerated() {
                            let x = CGFloat(index) * stepX
                            let y = height - (value * height * 0.9)

                            if index == 0 {
                                path.move(to: CGPoint(x: x, y: y))
                            } else {
                                path.addLine(to: CGPoint(x: x, y: y))
                            }
                        }
                    }
                    .stroke(
                        themeManager.palette.primary,
                        style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round)
                    )

                    // Data points
                    ForEach(Array(normalizedData.enumerated()), id: \.offset) { index, value in
                        let x = CGFloat(index) * stepX
                        let y = height - (value * height * 0.9)

                        Circle()
                            .fill(themeManager.palette.primary)
                            .frame(width: 4, height: 4)
                            .position(x: x, y: y)
                    }
                }
            }
            .frame(height: chartHeight)

            // Time labels
            HStack {
                Text("12am")
                Spacer()
                Text("6am")
                Spacer()
                Text("12pm")
                Spacer()
                Text("6pm")
                Spacer()
                Text("Now")
            }
            .font(.system(size: 9))
            .foregroundColor(themeManager.palette.textTertiary)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(themeManager.palette.surface)
                .shadow(color: Color.black.opacity(0.03), radius: 2, y: 1)
        )
    }
}

#Preview {
    ActivitySparkline(hourlyData: [0, 0, 0, 0, 0, 1, 2, 3, 5, 4, 6, 8, 5, 3, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0])
        .padding()
        .frame(width: 380)
}
