//
//  ColorPalette.swift
//  ClaudeNotifier
//

import SwiftUI

struct ColorPalette: Identifiable, Equatable {
    let id: String
    let name: String

    // Core colors
    let background: Color
    let surface: Color
    let primary: Color
    let secondary: Color

    // Text colors
    let textPrimary: Color
    let textSecondary: Color
    let textTertiary: Color

    // Status colors (semantic - same across themes for consistency)
    let success: Color
    let warning: Color
    let critical: Color
    let info: Color
    let active: Color

    // Border/divider
    let border: Color

    static let warmProfessional = ColorPalette(
        id: "warm-professional",
        name: "Warm Professional",
        background: Color(hex: "#F5F2F2"),
        surface: Color(hex: "#FFFFFF"),
        primary: Color(hex: "#FEB05D"),
        secondary: Color(hex: "#5A7ACD"),
        textPrimary: Color(hex: "#2B2A2A"),
        textSecondary: Color(hex: "#6B6868"),
        textTertiary: Color(hex: "#9E9A9A"),
        success: Color(hex: "#34C759"),
        warning: Color(hex: "#FFB84D"),
        critical: Color(hex: "#E85454"),
        info: Color(hex: "#5A7ACD"),
        active: Color(hex: "#FEB05D"),
        border: Color(hex: "#E8E4E4")
    )

    static let coolElegance = ColorPalette(
        id: "cool-elegance",
        name: "Cool Elegance",
        background: Color(hex: "#EEEEEE"),
        surface: Color(hex: "#FFFFFF"),
        primary: Color(hex: "#6594B1"),
        secondary: Color(hex: "#DDAED3"),
        textPrimary: Color(hex: "#213C51"),
        textSecondary: Color(hex: "#4A6A80"),
        textTertiary: Color(hex: "#7A9AAE"),
        success: Color(hex: "#5EC985"),
        warning: Color(hex: "#F5C86B"),
        critical: Color(hex: "#E87878"),
        info: Color(hex: "#6594B1"),
        active: Color(hex: "#DDAED3"),
        border: Color(hex: "#D4D4D4")
    )

    static let natureInspired = ColorPalette(
        id: "nature-inspired",
        name: "Nature Inspired",
        background: Color(hex: "#F6F3C2"),
        surface: Color(hex: "#FFFFFF"),
        primary: Color(hex: "#4B9DA9"),
        secondary: Color(hex: "#91C6BC"),
        textPrimary: Color(hex: "#2D4A4D"),
        textSecondary: Color(hex: "#5A7A7D"),
        textTertiary: Color(hex: "#8AA8AB"),
        success: Color(hex: "#91C6BC"),
        warning: Color(hex: "#E8B84D"),
        critical: Color(hex: "#E37434"),
        info: Color(hex: "#4B9DA9"),
        active: Color(hex: "#E37434"),
        border: Color(hex: "#D4E8E0")
    )

    static let warmCoral = ColorPalette(
        id: "warm-coral",
        name: "Warm Coral",
        background: Color(hex: "#FFEAD3"),
        surface: Color(hex: "#FFFFFF"),
        primary: Color(hex: "#D25353"),
        secondary: Color(hex: "#EA7B7B"),
        textPrimary: Color(hex: "#4A2828"),
        textSecondary: Color(hex: "#7A5050"),
        textTertiary: Color(hex: "#A88080"),
        success: Color(hex: "#5EC985"),
        warning: Color(hex: "#F5B84D"),
        critical: Color(hex: "#9E3B3B"),
        info: Color(hex: "#6B9ED4"),
        active: Color(hex: "#EA7B7B"),
        border: Color(hex: "#F0D8C8")
    )

    static let vintageMauve = ColorPalette(
        id: "vintage-mauve",
        name: "Vintage Mauve",
        background: Color(hex: "#FFDAB3"),
        surface: Color(hex: "#FFFFFF"),
        primary: Color(hex: "#574964"),
        secondary: Color(hex: "#C8AAAA"),
        textPrimary: Color(hex: "#3A3040"),
        textSecondary: Color(hex: "#6A5A68"),
        textTertiary: Color(hex: "#9A8A98"),
        success: Color(hex: "#7DB88F"),
        warning: Color(hex: "#FFDAB3"),
        critical: Color(hex: "#C86B6B"),
        info: Color(hex: "#7A8AC8"),
        active: Color(hex: "#9F8383"),
        border: Color(hex: "#E0D4D4")
    )

    static let allPalettes: [ColorPalette] = [
        .warmProfessional,
        .coolElegance,
        .natureInspired,
        .warmCoral,
        .vintageMauve
    ]
}
