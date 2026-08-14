/**
 EXPERIMENTAL PREVIEW — onboarding in the TURN-1 design: custody first (1n),
 then the pairing act (1o).

 Step 1 states the custody fact this launch actually resolved — Enclave,
 explicit simulator fallback, or plainly unavailable; there is no quiet
 downgrade. Step 2 is the existing pairing behavior in new clothes: scanning
 only fills the form, pairing is still a button, a blocked stored pairing must
 be forgotten explicitly, and every status line comes from DemoModel verbatim.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import OwnerPhone
import SwiftUI

struct WalletOnboardingView: View {
    @ObservedObject var model: DemoModel
    @State private var step = 0
    #if os(iOS)
    @State private var showingPairingScanner = false
    @State private var scannerMessage = ""
    #endif

    var body: some View {
        ZStack {
            WalletTheme.paper.ignoresSafeArea()
            if step == 0 {
                custodyStep
            } else {
                pairStep
            }
        }
    }

    // MARK: Step 1 of 2 — the key (design 1n)

    private var custodyStep: some View {
        VStack(alignment: .leading, spacing: 0) {
            stepHeader(1, "KEY")
            Text("Your phone becomes the key.")
                .font(WalletTheme.speech(27, .semibold))
                .foregroundStyle(WalletTheme.ink)
                .padding(.top, 12)
            Text(custodyLine)
                .font(WalletTheme.speech(14))
                .foregroundStyle(WalletTheme.muted)
                .padding(.top, 8)

            VStack(alignment: .leading, spacing: 14) {
                benefit("key.fill", "No seed phrase to lose",
                        "There is nothing to write down, because there is nothing to copy.")
                benefit("globe", "One account, every chain",
                        "The same address on every chain the relay serves.")
                benefit("hand.raised", "Apps ask; you decide",
                        "Every app runs on limits you grant, and you can revoke them at any time.")
            }
            .padding(.top, 24)

            custodyStateCard.padding(.top, 22)

            // A blocked stored pairing must stay recoverable even while the
            // owner key is unavailable — that combination is exactly when the
            // model demands an explicit local forget, so the control and the
            // model's own instruction surface here, not only on step 2.
            if model.storedPairingBlocked {
                if !model.statusLine.isEmpty {
                    Text(model.statusLine)
                        .font(WalletTheme.speech(12.5))
                        .foregroundStyle(WalletTheme.muted)
                        .padding(.top, 12)
                }
                WalletSecondaryButton(title: "Forget blocked pairing", destructive: true) {
                    model.unpair()
                }
                .padding(.top, 12)
            }

            Spacer()
            WalletPrimaryButton(
                title: model.ownerKey == nil ? "Key unavailable" : "Continue",
                systemImage: model.ownerKey == nil ? nil : "faceid",
                enabled: model.ownerKey != nil
            ) { step = 1 }
            Text("If your device has no Enclave, this app says so plainly instead of quietly falling back.")
                .font(WalletTheme.speech(11))
                .foregroundStyle(WalletTheme.muted)
                .frame(maxWidth: .infinity)
                .multilineTextAlignment(.center)
                .padding(.top, 9)
        }
        .padding(20)
    }

    private var custodyLine: String {
        guard let ownerKey = model.ownerKey else {
            return "This device could not create or load a P-256 key. Nothing can be signed until it can."
        }
        return ownerKey.secureEnclave
            ? "A P-256 key is generated inside this iPhone's Secure Enclave. It never leaves the chip, can't be exported, and every use asks for your presence."
            : "This build runs without a Secure Enclave, so the key is a regular keychain P-256 key — the explicit simulator fallback, never a quiet downgrade."
    }

    private var custodyStateCard: some View {
        HStack(spacing: 10) {
            Circle().fill(stateColor).frame(width: 7, height: 7)
            Text(stateText)
                .font(WalletTheme.mono(11, .medium))
                .foregroundStyle(WalletTheme.inkText)
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(WalletTheme.ink)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    private var stateColor: Color {
        guard let ownerKey = model.ownerKey else { return WalletTheme.red }
        return ownerKey.secureEnclave ? WalletTheme.mint : WalletTheme.amber
    }

    private var stateText: String {
        guard let ownerKey = model.ownerKey else {
            return model.storedPairingBlocked
                ? "OWNER KEY UNAVAILABLE — FORGET THE BLOCKED PAIRING FIRST"
                : "OWNER KEY UNAVAILABLE — RESTART TO RETRY"
        }
        return ownerKey.secureEnclave
            ? "KEY READY · SECURE ENCLAVE"
            : "KEY READY · SIMULATOR FALLBACK"
    }

    private func benefit(_ icon: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(WalletTheme.teal)
                .frame(width: 34, height: 34)
                .background(WalletTheme.tealWash)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(WalletTheme.speech(15, .semibold))
                    .foregroundStyle(WalletTheme.ink)
                Text(detail)
                    .font(WalletTheme.speech(12.5))
                    .foregroundStyle(WalletTheme.muted)
            }
        }
    }

    // MARK: Step 2 of 2 — pair (design 1o)

    private var pairStep: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    stepHeader(2, "PAIR")
                    Text("Point at the code on your computer.")
                        .font(WalletTheme.speech(27, .semibold))
                        .foregroundStyle(WalletTheme.ink)
                        .padding(.top, 12)
                    Text("On the Mac, open the printed loopback browser URL and choose Pair phone. Scan its transient QR here, tap the oaath-demo:// link, or fill the fields by hand.")
                        .font(WalletTheme.speech(12.5))
                        .foregroundStyle(WalletTheme.muted)
                        .padding(.top, 8)

                    #if os(iOS)
                    scanCard.padding(.top, 18)
                    #endif

                    fields.padding(.top, 16)
                    matchCodeExplainer.padding(.top, 16)

                    if !model.statusLine.isEmpty {
                        Text(model.statusLine)
                            .font(WalletTheme.speech(12.5))
                            .foregroundStyle(WalletTheme.muted)
                            .padding(.top, 12)
                    }
                    Text("The one-shot code shown by the browser is this demo's trust root, on a trusted network only. A production deployment owns pairing UX (QR, attestation).")
                        .font(WalletTheme.speech(10.5))
                        .foregroundStyle(WalletTheme.faint)
                        .padding(.top, 14)
                }
                .padding(20)
            }
            footer
        }
        #if os(iOS)
        .sheet(isPresented: $showingPairingScanner) { scannerSheet }
        #endif
    }

    private var fields: some View {
        WalletCard(padding: 14) {
            VStack(alignment: .leading, spacing: 12) {
                WalletSectionLabel(text: "Relay")
                TextField("http://<your-mac-lan-ip>:8787", text: $model.baseURLText)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    .font(WalletTheme.mono(13))
                    .padding(10)
                    .background(WalletTheme.paper)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                WalletSectionLabel(text: "Pairing code")
                TextField("ABCD-EFGH-JK or oaath-demo:// link", text: $model.pairingCodeText)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    .font(WalletTheme.mono(13))
                    .padding(10)
                    .background(WalletTheme.paper)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
        }
    }

    private var matchCodeExplainer: some View {
        WalletCard(padding: 15) {
            VStack(alignment: .leading, spacing: 12) {
                WalletSectionLabel(text: "Next: the match code")
                HStack(alignment: .center, spacing: 14) {
                    Text("Ab1- _9Zz")
                        .font(WalletTheme.mono(22, .bold))
                        .foregroundStyle(WalletTheme.ink)
                    Text("Every request shows eight characters. If they don't match your screen, someone else is asking.")
                        .font(WalletTheme.speech(12.5))
                        .foregroundStyle(WalletTheme.muted)
                }
            }
        }
    }

    private var footer: some View {
        VStack(spacing: 0) {
            if model.storedPairingBlocked {
                WalletSecondaryButton(title: "Forget blocked pairing", destructive: true, height: 52) {
                    model.unpair()
                }
            } else {
                WalletPrimaryButton(title: "Pair this device") {
                    Task { await model.pair() }
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.top, 12)
        .padding(.bottom, 14)
        .background(WalletTheme.card)
        .overlay(alignment: .top) { WalletTheme.border.frame(height: 1) }
    }

    #if os(iOS)
    private var scanCard: some View {
        Button {
            scannerMessage = ""
            showingPairingScanner = true
        } label: {
            VStack(spacing: 12) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 44, weight: .light))
                    .foregroundStyle(WalletTheme.inkText)
                Text("Scan pairing QR")
                    .font(WalletTheme.speech(15, .medium))
                    .foregroundStyle(WalletTheme.inkText)
                Text("Scanning only fills the form. Pairing is still a button.")
                    .font(WalletTheme.speech(12))
                    .foregroundStyle(WalletTheme.inkText.opacity(0.75))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 34)
            .background(WalletTheme.ink)
            .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        }
        .buttonStyle(.plain)
    }

    private var scannerSheet: some View {
        NavigationStack {
            ZStack(alignment: .bottom) {
                PairingQRCodeScanner { payload in
                    if model.applyScannedPairingPayload(payload) {
                        showingPairingScanner = false
                        return true
                    } else {
                        scannerMessage = "This QR code is not an OAAth pairing link."
                        return false
                    }
                } onFailure: { failure in
                    scannerMessage = failure.message
                }
                .ignoresSafeArea()

                Text(scannerMessage.isEmpty
                    ? "Point the camera at the pairing QR shown in the browser."
                    : scannerMessage)
                    .font(.footnote)
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                    .padding()
                    .background(.black.opacity(0.75), in: RoundedRectangle(cornerRadius: 12))
                    .padding()
            }
            .navigationTitle("Scan pairing QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showingPairingScanner = false }
                }
            }
        }
    }
    #endif

    private func stepHeader(_ step: Int, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                ForEach(1...2, id: \.self) { index in
                    Capsule()
                        .fill(index <= step ? WalletTheme.ink : WalletTheme.track)
                        .frame(height: 3)
                }
            }
            Text("STEP \(step) OF 2 · \(label)")
                .font(WalletTheme.mono(11, .semibold))
                .kerning(1.1)
                .foregroundStyle(WalletTheme.muted)
        }
        .padding(.top, 8)
    }
}
#endif
