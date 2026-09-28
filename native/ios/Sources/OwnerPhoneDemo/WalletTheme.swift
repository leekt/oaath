/**
 EXPERIMENTAL PREVIEW — the owner-phone design language as SwiftUI tokens.

 Paper-and-ink receipt: a warm paper ground, cards on near-white, ink for
 emphasis, teal for actions the owner takes, red for refusal, amber for
 anything requested-but-unproven. Every color has a light and a dark value so
 the app follows the system appearance. Two voices: the system speaks in the
 default face; anything the chain owns (addresses, digests, selectors, wei,
 codes) is monospaced. Both voices are Dynamic Type text styles.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import SwiftUI
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

public enum WalletTheme {
    // MARK: Palette (light / dark)
    public static let paper = dynamic(0xF3F0E9, 0x14130E)
    public static let card = dynamic(0xFFFDF7, 0x1E1C16)
    /// Primary text and the filled primary control.
    public static let ink = dynamic(0x16160F, 0xF3F0E9)
    /// Text drawn on an `ink` fill.
    public static let inkText = dynamic(0xF3F0E9, 0x16160F)
    public static let border = dynamic(0xE3DED0, 0x37342B)
    public static let hairline = dynamic(0xEDE8DC, 0x2A2821)
    /// Secondary text; ≥4.5:1 on paper and card in both appearances.
    public static let muted = dynamic(0x655F51, 0xA7A193)
    public static let teal = dynamic(0x0B6B62, 0x5CC2B3)
    public static let tealWash = dynamic(0xE4EFEB, 0x163029)
    /// Text drawn on a `teal` fill.
    public static let onTeal = dynamic(0xFFFFFF, 0x0C1A17)
    public static let red = dynamic(0xB8321A, 0xF07A5E)
    public static let redWash = dynamic(0xFBE9E3, 0x3A1E17)
    public static let amber = dynamic(0x8A5C06, 0xE3AE45)
    public static let amberWash = dynamic(0xF6EEDB, 0x33280F)
    public static let chip = dynamic(0xEFEBE0, 0x29271F)
    public static let track = dynamic(0xDFD9CA, 0x3A372E)
    public static let mint = dynamic(0x0E8A6A, 0x5FD3A6)

    // MARK: Type roles
    /// Speech: sentences the app says to the owner.
    public static func speech(_ style: Font.TextStyle, _ weight: Font.Weight = .regular) -> Font {
        .system(style, design: .default).weight(weight)
    }

    /// Chain-owned facts: addresses, digests, selectors, codes, wei.
    public static func mono(_ style: Font.TextStyle, _ weight: Font.Weight = .regular) -> Font {
        .system(style, design: .monospaced).weight(weight)
    }

    private static func dynamic(_ light: UInt32, _ dark: UInt32) -> Color {
        #if canImport(UIKit)
        Color(UIColor { traits in
            traits.userInterfaceStyle == .dark ? platform(dark) : platform(light)
        })
        #elseif canImport(AppKit)
        Color(NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? platform(dark) : platform(light)
        })
        #endif
    }

    #if canImport(UIKit)
    private static func platform(_ hex: UInt32) -> UIColor {
        UIColor(
            red: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1)
    }
    #elseif canImport(AppKit)
    private static func platform(_ hex: UInt32) -> NSColor {
        NSColor(
            srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1)
    }
    #endif
}

/// Uppercase section label, e.g. "PENDING", "OWNER KEY".
struct WalletSectionLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(WalletTheme.speech(.caption, .semibold))
            .kerning(0.6)
            .foregroundStyle(WalletTheme.muted)
            .accessibilityAddTraits(.isHeader)
    }
}

/// The card every fact sits on. `emphasized` draws the ink border used for
/// anything awaiting the owner.
struct WalletCard<Content: View>: View {
    var emphasized = false
    var padding: CGFloat = 16
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(WalletTheme.card)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(emphasized ? WalletTheme.ink : WalletTheme.border, lineWidth: 1)
            )
    }
}

/// Small status chip: ENCLAVE / SIMULATOR KEY / UNAVAILABLE …
struct WalletStatusPill: View {
    let text: String
    let color: Color
    let background: Color

    var body: some View {
        Text(text)
            .font(WalletTheme.mono(.caption2, .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(background)
            .clipShape(Capsule())
            .fixedSize()
    }
}

/// Tone of an inline notice.
enum WalletNoticeTone {
    case neutral, success, warning, danger

    var color: Color {
        switch self {
        case .neutral: return WalletTheme.muted
        case .success: return WalletTheme.teal
        case .warning: return WalletTheme.amber
        case .danger: return WalletTheme.red
        }
    }

    var wash: Color {
        switch self {
        case .neutral: return WalletTheme.chip
        case .success: return WalletTheme.tealWash
        case .warning: return WalletTheme.amberWash
        case .danger: return WalletTheme.redWash
        }
    }

    var icon: String {
        switch self {
        case .neutral: return "info.circle"
        case .success: return "checkmark.circle"
        case .warning: return "exclamationmark.triangle"
        case .danger: return "xmark.octagon"
        }
    }
}

/// An inline status message with an icon, placed next to the control it
/// explains. Optional dismissal clears model-owned prose only.
struct WalletNotice: View {
    let text: String
    var tone: WalletNoticeTone = .neutral
    var dismiss: (() -> Void)?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: tone.icon)
                .foregroundStyle(tone.color)
                .accessibilityHidden(true)
            Text(text)
                .font(WalletTheme.speech(.footnote))
                .foregroundStyle(WalletTheme.ink)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
            if let dismiss {
                Button(action: dismiss) {
                    Image(systemName: "xmark")
                        .font(WalletTheme.speech(.caption, .semibold))
                        .foregroundStyle(WalletTheme.muted)
                        .frame(width: 32, height: 32)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Dismiss")
            }
        }
        .padding(.leading, 14)
        .padding(.trailing, dismiss == nil ? 14 : 4)
        .padding(.vertical, dismiss == nil ? 12 : 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tone.wash)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .accessibilityElement(children: .combine)
    }
}

/// Filled ink action button, the primary control.
struct WalletPrimaryButton: View {
    let title: String
    var systemImage: String?
    var enabled = true
    var busy = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                if busy {
                    ProgressView().tint(WalletTheme.inkText)
                } else if let systemImage {
                    Image(systemName: systemImage)
                }
                Text(title).font(WalletTheme.speech(.body, .semibold))
            }
            .foregroundStyle(enabled ? WalletTheme.inkText : WalletTheme.muted)
            .frame(maxWidth: .infinity, minHeight: 52)
            .background(enabled ? WalletTheme.ink : WalletTheme.track)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(WalletPressStyle())
        .disabled(!enabled || busy)
    }
}

/// Bordered secondary button; `destructive` renders the refusal red.
struct WalletSecondaryButton: View {
    let title: String
    var systemImage: String?
    var destructive = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let systemImage { Image(systemName: systemImage) }
                Text(title).font(WalletTheme.speech(.body, .medium))
            }
            .foregroundStyle(destructive ? WalletTheme.red : WalletTheme.ink)
            .frame(maxWidth: .infinity, minHeight: 48)
            .background(WalletTheme.card)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(destructive ? WalletTheme.red : WalletTheme.border, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(WalletPressStyle())
    }
}

/// Quiet press feedback shared by every custom button.
struct WalletPressStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .opacity(configuration.isPressed ? 0.72 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

/// A label/value row for facts in a grouped card.
struct WalletFactRow: View {
    let label: String
    let value: String
    var monospaced = true

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(WalletTheme.speech(.footnote))
                .foregroundStyle(WalletTheme.muted)
            Text(value)
                .font(monospaced ? WalletTheme.mono(.subheadline) : WalletTheme.speech(.body))
                .foregroundStyle(WalletTheme.ink)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

extension View {
    /// Paper ground and bar styling for every top-level screen.
    func walletScreen() -> some View {
        self
            .scrollContentBackground(.hidden)
            .background(WalletTheme.paper.ignoresSafeArea())
            #if os(iOS)
            .toolbarBackground(WalletTheme.paper, for: .navigationBar)
            #endif
    }
}
#endif
