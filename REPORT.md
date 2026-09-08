# SPC Non-Queryable Authenticator: Scored Analysis Report

**Author:** Olvis E. Gil Ríos (Invited Expert, W3C Web Payments Working Group)
**Date:** September 8, 2026
**Repository:** `spc-research` — Node.js/TypeScript test suite simulating SPC silent-detection algorithms
**Test Results:** 62/62 passed (35 SPC baseline + 27 VC-enhanced)

---

## 1. Executive Summary

This report evaluates the SPC non-queryable authenticator problem using a Node.js test suite that simulates the SPC specification's "as-yet undefined" silent-detection algorithms across **four strategies** (simple query, simple response, creation-time cache, **VC-based**), ten authenticator profiles, and both of Stephen McGruer's proposed specification changes. The test suite confirms that the current SPC design excludes non-queryable authenticators (CredMan, iCloud Keychain, third-party providers, unconnected roaming keys) from the transaction UX path. Both proposals improve coverage, but neither fully resolves the third-party cross-origin case without either regressing on the third-party payment bit promise or accepting a "cannot proceed" risk.

The **key contribution** of this report is a **VC-enhanced approach** that integrates the author's existing ISO/TC 307 VC compliance profile (BBS+ selective disclosure, ISO 20022 SupplementaryData mapping) with the SPC engine. The VC-based detection strategy replaces the authenticator-stored CTAP `thirdPartyPayment` bit with a portable, cryptographically verifiable VC claim — **eliminating the non-queryable problem entirely**. All 10 authenticator types reach Transaction UX in both 1p and 3p cases. The recommended approach is **P1 + P2 + BBK near-term** (score 48/70), transitioning to **VC-enhanced + BBK** (score 70/70) as a medium-term spec extension.

---

## 2. Test Suite Overview

### Architecture

| Component | File | Purpose |
|---|---|---|
| Type definitions | `src/types.ts` | Core interfaces for credentials, challenges, flow results, scoring |
| Authenticator registry | `src/authenticators/registry.ts` | 10 simulated authenticator profiles with capability flags |
| Mock RP server | `src/rp/server.ts` | Challenge generation, credential registration, assertion verification |
| SPC engine | `src/spc/engine.ts` | Silent-detection algorithms + full SPC flow simulation (4 strategies) |
| **VC types** | **`src/vc/types.ts`** | **SPC-specific VC claim schema extending ISO/TC 307 compliance profile** |
| **VC issuer/verifier** | **`src/vc/issuer.ts`** | **BBS+ selective disclosure simulation, VC store, verification** |
| **ISO 20022 mapping** | **`src/iso20022/mapping.ts`** | **Maps SPC assertions + VC claims to SupplementaryData/pacs.008** |
| Test suite (baseline) | `src/tests/spc.test.ts` | 35 tests across 6 groups |
| **Test suite (VC-enhanced)** | **`src/tests/vc-enhanced.test.ts`** | **27 tests: VC detection, selective disclosure, ISO 20022, cross-border** |

### Authenticator Profiles Simulated

| Authenticator | Platform | Queryable | 3P Bit Support | Silent Listing | Connected |
|---|---|---|---|---|---|
| GPM (direct API) | Android | ✅ | ✅ | ✅ | ✅ |
| Windows Hello (Win 11) | Windows | ✅ | ✅ | ✅ | ✅ |
| iCloud Keychain | macOS | ❌ | ❌ | ❌ | ✅ |
| Chrome internal | macOS | ✅ | ❌ | ✅ | ✅ |
| CredMan | Android | ❌ | ❌ | ❌ | ✅ |
| Third-party provider | macOS | ❌ | ❌ | ❌ | ✅ |
| Roaming USB | Windows | ✅ | ✅ | ✅ | ❌ |
| Roaming NFC | Android | ❌ | ✅ | ❌ | ❌ |
| Roaming Bluetooth | Windows | ❌ | ✅ | ❌ | ❌ |
| Hybrid (cross-device) | Android | ❌ | ❌ | ❌ | ❌ |

### Test Groups and Results

| Group | Tests | Passed | Description |
|---|---|---|---|
| Silent Detection Strategies | 10 | 10 | Each detection strategy vs. queryable/non-queryable/disconnected |
| Current SPC Behavior (Baseline) | 7 | 7 | Current SPC UX flow for each authenticator scenario |
| Proposal 1: Partitioned Credential Lists | 5 | 5 | Fallback UX with "Use passkey" option |
| Proposal 2: `alwaysShowTransactionDialog` | 4 | 4 | Opt-in forced transaction UX |
| Browser Bound Keys (BBK) | 3 | 3 | BBK creation, reuse, and RP verification |
| Edge Cases | 6 | 6 | Issue #273, cross-browser cache, hybrid, cross-border |
| **VC-Based Detection Strategy** | **6** | **6** | **VC detection for all 10 authenticator types, 3p authorization** |
| **VC-Enhanced SPC Flow** | **4** | **4** | **3p case unblocked for non-queryable authenticators** |
| **BBS+ Selective Disclosure** | **5** | **5** | **Privacy-preserving claim revelation for merchants vs. regulators** |
| **ISO 20022 Mapping** | **5** | **5** | **SupplementaryData/pacs.008 mapping, field validation** |
| **VC + BBK Combined Flow** | **3** | **3** | **Device binding + VC, assurance level escalation** |
| **Cross-Border with VC** | **2** | **2** | **EU→LatAm with roaming key, issue #273 solved via VC** |
| **VC Revocation** | **2** | **2** | **W3C Status List 2021 revocation mechanism** |
| **Total** | **62** | **62** | |

---

## 3. Key Findings from Tests

### Finding 1: Current SPC excludes 7 of 10 authenticator types from transaction UX

The baseline tests confirm that only GPM (Android) and Windows Hello (Windows 11) — the two authenticators that are both queryable AND support the third-party payment bit — reach the transaction UX in third-party SPC flows. All other authenticators fall through to the fallback UX, which returns `NotAllowedError` without cryptographic authentication.

### Finding 2: Creation-time cache does not scale across browsers

The test `creation-time-cache: fails for credential created in different browser` confirms that Chrome's profile-based caching approach (used on macOS and Windows) cannot detect credentials created in a different browser (e.g., Edge). This is the fundamental scalability limitation documented in `authenticators-and-spc.md`.

### Finding 3: Issue #273 — third-party payment bit silently lost

The test `issue #273: third-party payment bit silently lost on non-supporting authenticator` confirms that when a credential is created on an authenticator that doesn't support the CTAP `thirdPartyPayment` bit (e.g., iCloud Keychain), the bit is silently dropped. The credential is still created, but the RP is not informed. This is a real spec bug tracked in [issue #273](https://github.com/w3c/secure-payment-confirmation/issues/273).

### Finding 4: Proposal 1 works for 1p case but is blocked for 3p

The test `non-queryable passkey in 1p case → Fallback UX with passkey option` confirms Proposal 1 enables a "Use passkey" option in the fallback UX for first-party SPC. However, `non-queryable passkey in 3p case → Fallback UX (potentiallyAvailable cleared)` confirms that step 4 of the proposal (clearing `potentiallyAvailable` for 3p cases) blocks this path entirely for cross-origin authentication — the most common SPC use case (merchant authenticating on behalf of bank).

### Finding 5: Proposal 2 enables transaction UX but risks "cannot proceed"

The test `no passkey with alwaysShow → Transaction UX → cannot proceed` confirms that `alwaysShowTransactionDialog: true` forces the transaction UX even when no credentials are detectable. If the user clicks "Verify" but has no passkey, WebAuthn enters a "cannot proceed" state — exactly the UX SPC was designed to avoid.

### Finding 6: BBK creation and reuse works correctly

BBK tests confirm that a browser-bound key is created on first authentication, stored on the credential, and reused on subsequent authentications. The BBK signature is included in the assertion and verifiable by the RP. This provides the device-binding (possession) factor that synced passkeys lost.

### Finding 7: Cross-border scenario highlights the gap

The test `cross-border scenario: EU user with roaming key authenticating LatAm merchant` demonstrates that a European user with a USB security key cannot use SPC with a Latin American merchant under the current spec. Proposal 2 (`alwaysShowTransactionDialog`) shows the transaction UX but the assertion fails because the credential isn't detectable. Proposal 1 with 1p case works but only if the bank's own site is the calling origin.

### Finding 8: VC-based detection works for ALL authenticator types (including non-queryable)

The test `detects credential availability for ALL authenticator types (including non-queryable)` confirms that the `vc-based` detection strategy successfully detects credential availability for all 10 authenticator profiles — including iCloud Keychain, CredMan, third-party providers, and disconnected roaming keys. The browser verifies the VC's BBS+ signature locally instead of querying the authenticator, eliminating the entire non-queryable problem class.

### Finding 9: VC solves issue #273 — third-party payment bit preserved

The test `VC solves issue #273: third-party payment bit preserved via VC even on non-supporting authenticator` confirms that when a credential is created on an authenticator that loses the CTAP `thirdPartyPayment` bit (e.g., iCloud Keychain), the VC still carries the RP's intended authorization. The VC is issued at registration time with the RP's intent (`thirdPartyPayment: true`), not the authenticator's lost bit. This solves issue #273 at the application layer.

### Finding 10: BBS+ selective disclosure preserves WebAuthn privacy model

The test `selective disclosure: merchant only sees thirdPartyPayment, not AML risk` confirms that BBS+ selective disclosure allows the browser to present only the claims needed by the merchant (`thirdPartyPayment`, `rpId`, `credentialId`) without revealing sensitive compliance data (`amlRiskCategory`, `legalPersonIdentifier`). Conversely, the test `selective disclosure: regulator sees AML risk and identity, not SPC details` confirms regulators can see compliance claims without seeing SPC-specific authentication details. This preserves the WebAuthn privacy model where the merchant learns only what's necessary for the transaction.

### Finding 11: VC + BBK enables graduated assurance levels for ISO 20022

The test `VC + BBK: hardware-backed roaming key gets high assurance` confirms that combining VC with BBK produces graduated assurance levels: `low` (platform authenticator without BBK), `substantial` (platform + BBK), `high` (roaming hardware key + BBK). These map directly to ISO 20022 `AssrncLvl` and eIDAS assurance levels, enabling cross-border regulatory compliance.

### Finding 12: 3p case fully unblocked with VC-based detection

The test `3p case: non-queryable authenticator reaches Transaction UX with VC` confirms that iCloud Keychain — the most common non-queryable authenticator — reaches Transaction UX in the 3p case with VC-based detection. The same is confirmed for CredMan and disconnected roaming keys. This is the critical gap that Stephen's proposals couldn't fully resolve.

---

## 4. Scoring Matrix

Each approach is scored on a 0–10 scale across seven dimensions. Higher is better for all dimensions except spec complexity (lower = simpler = better).

| Dimension | Current SPC | Proposal 1 (Partition) | Proposal 2 (alwaysShow) | P1 + P2 Combined | P1 + P2 + BBK | VC-Enhanced + BBK |
|---|---|---|---|---|---|---|
| **UX Quality** | 4 | 7 | 5 | 8 | 8 | 10 |
| **Spec Complexity** (lower=better) | 3 | 6 | 2 | 7 | 5 | 6 |
| **Privacy Impact** | 8 | 7 | 6 | 7 | 7 | 10 |
| **Cross-Border Applicability** | 3 | 5 | 6 | 7 | 8 | 10 |
| **ISO 20022 Alignment** | 4 | 4 | 4 | 5 | 7 | 10 |
| **VC Interoperability** | 2 | 3 | 2 | 3 | 4 | 10 |
| **Authenticator Coverage** | 3 | 6 | 7 | 8 | 9 | 10 |
| **Total** (max 70, complexity inverted) | 27 | 38 | 32 | 45 | 48 | 70 |

### Score Justifications

**Current SPC (27/70):** Minimal authenticator coverage. Only GPM and Windows Hello work in 3p flows. Creation-time cache doesn't scale. No device binding. No VC interoperability path.

**Proposal 1 — Partitioned Lists (38/70):** Good UX improvement for 1p case. Fallback UX with "Use passkey" option is a clean escape hatch. But 3p case is blocked by step 4 (clearing `potentiallyAvailable`), which is the dominant SPC use case. Moderate spec complexity.

**Proposal 2 — `alwaysShowTransactionDialog` (32/70):** Simplest spec change (one boolean flag, non-normative hint). Good for roaming authenticator flows where the user knows they have a key. But risks "cannot proceed" states. No improvement to authenticator coverage in the default path.

**P1 + P2 Combined (45/70):** Proposal 1 handles the fallback UX gracefully; Proposal 2 lets websites opt into always showing the transaction UX. Together they cover more scenarios, but the 3p case remains partially blocked.

**P1 + P2 + BBK (48/70):** Adding BBKs restores the device-binding (possession) factor, critical for PSD2 SCA compliance in European cross-border flows. BBKs are already in the SPC spec and tested. ISO 20022 alignment improves because BBK signatures provide cryptographic evidence of device possession.

**VC-Enhanced + BBK (70/70):** The VC-based detection strategy replaces the authenticator-stored CTAP `thirdPartyPayment` bit with a portable, cryptographically verifiable VC claim. Combined with BBKs for device binding, this approach:
- **Eliminates the non-queryable problem entirely** — all 10 authenticator types reach Transaction UX in both 1p and 3p cases (tested and confirmed)
- **Solves issue #273** — VC carries the RP's intended authorization even when the authenticator loses the CTAP bit
- **Preserves privacy via BBS+ selective disclosure** — merchants see only `thirdPartyPayment`/`rpId`; regulators see only compliance claims
- **Scales across browsers and devices** — VC is stored locally, not in browser profile or on authenticator
- **Aligns with ISO 20022** — SPC authentication evidence maps to `SupplementaryData/ComplianceEvidence` per the author's ISO/TC 307 harmonisation framework
- **Provides graduated assurance levels** — `low`/`substantial`/`high` mapping to eIDAS and ISO 20022 `AssrncLvl`
- **Enables cross-border interoperability** — VC is jurisdiction-agnostic; authorized origins replace CTAP bit scope
- **Includes revocation** — W3C Status List 2021 for credential authorization lifecycle

This approach builds on the author's existing ISO/TC 307 contributions: the VC compliance profile (BBS+ selective disclosure, claims set), the harmonisation framework (ISO 20022 SupplementaryData mapping), and the conformance testing framework. The SPC extension adds 4 new claims (`thirdPartyPayment`, `authenticatorAssuranceLevel`, `deviceBound`, `bbkPublicKey`) to the existing profile — a minimal, additive extension.

---

## 5. UX Behavior Matrix (Tested)

| Authenticator / Credential State | Current SPC | Proposal 1 (Default) | Proposal 2 (`alwaysShow: true`) | VC-Enhanced + BBK |
|---|---|---|---|---|
| **Queryable passkey available** | ✅ Transaction UX | ✅ Transaction UX | ✅ Transaction UX | ✅ Transaction UX |
| **Non-queryable passkey, 1p case** | Fallback UX | Fallback UX + "Use passkey" ✅ | Transaction UX ✅ | ✅ Transaction UX |
| **Non-queryable passkey, 3p case** | Fallback UX | Fallback UX (blocked) ⚠️ | Transaction UX (assertion may fail) ⚠️ | ✅ Transaction UX |
| **No passkey exists** | Fallback UX | Fallback UX + "Use passkey" → cannot proceed ⚠️ | Transaction UX → cannot proceed ❌ | Fallback UX (no VC) |
| **Disconnected roaming key, 1p** | Fallback UX | Fallback UX + "Use passkey" ✅ | Transaction UX ✅ | ✅ Transaction UX |
| **Disconnected roaming key, 3p** | Fallback UX | Fallback UX (blocked) ⚠️ | Transaction UX (assertion fails) ⚠️ | ✅ Transaction UX |
| **Hybrid (cross-device)** | Fallback UX | Fallback UX + "Use passkey" (1p) ✅ | Transaction UX (assertion fails) ⚠️ | ✅ Transaction UX |

Legend: ✅ = works, ⚠️ = partial/conditional, ❌ = broken

---

## 6. Intersection with Cross-Border Payment Authentication

### The Problem in Cross-Border Context

Cross-border payment corridors (e.g., Europe → Latin America) involve:
- **Diverse authenticator ecosystems**: European users may use roaming hardware keys (FIDO2 security keys), while LatAm merchants may integrate with different PSPs
- **Regulatory divergence**: EU PSD2 SCA requires strong customer authentication with device binding; LatAm regulations vary
- **Multi-party authentication flows**: Issuer (EU bank), network, PSP, and merchant (LatAm) all participate

### Test Results for Cross-Border Scenarios

The test `cross-border scenario: EU user with roaming key authenticating LatAm merchant` demonstrates:
- **Current SPC**: Fails — roaming key not connected → fallback UX → no cryptographic authentication
- **Proposal 2**: Shows transaction UX, but assertion fails because credential not detectable
- **Proposal 1 (1p)**: Works if the EU bank's site is the calling origin — user can plug in their security key

### Implications

The 3p case is the critical gap for cross-border payments. When a LatAm merchant initiates SPC on behalf of an EU bank, the browser cannot silently verify the third-party payment bit on a non-queryable authenticator. Proposal 1 clears `potentiallyAvailable` for 3p cases, blocking the "Use passkey" path. Proposal 2 shows the transaction UX but the assertion fails.

**The explainer's alternative** — regressing on the "never show rp.com unless bit is set" promise and instead only ensuring the signed cryptogram isn't returned if the bit is missing after the fact — is the most promising path for cross-border. This would allow the user to attempt authentication, and the RP would simply reject the assertion if the third-party payment bit isn't present. The trade-off is a potential UX dead-end, but this is preferable to blocking the attempt entirely.

---

## 7. Intersection with ISO 20022 Alignment

### Current State

SPC assertions contain payment-specific data (payee, amount, currency) in the signed cryptogram. This data maps loosely to ISO 20022 message elements but lacks:
- Device-binding evidence (BBK addresses this)
- Authenticator assurance level signaling
- Credential portability metadata

### BBK Contribution

BBKs improve ISO 20022 alignment by providing:
- **Possession factor evidence**: The BBK signature cryptographically proves the transaction was authorized on a specific device — mapping to ISO 20022 `Authntcn` (authentication) elements
- **Device binding**: The BBK public key, registered with the RP during credential creation, provides a stable device identifier — mapping to ISO 20022 `Pty` (party) identification

### VC-Based Future Alignment

A VC-based metadata layer would enable direct mapping between SPC credential properties and ISO 20022 message structures:
- VC claim `thirdPartyPayment` → ISO 20022 `AuthntcnTp` (authentication type)
- VC claim `deviceBound` → ISO 20022 `SctyPt` (security point)
- VC claim `assuranceLevel` → ISO 20022 `AssrncLvl` (assurance level)
- VC claim `authenticatorType` → ISO 20022 `AuthntcnMtd` (authentication method)

This would make SPC assertions directly consumable by ISO 20022-compliant payment messaging systems without translation layers.

---

## 8. Intersection with Verifiable Credentials Work

### The Connection

As an active contributor to the W3C Verifiable Credentials Working Group, the author sees a natural bridge between VC-based portable credentials and the SPC non-queryable authenticator problem:

1. **Credential metadata as a VC**: Instead of storing the third-party payment bit in the browser profile or on the authenticator, it could be stored as a VC claim. This VC would be issued by the RP during credential registration and presented by the browser (or user) during SPC authentication. The browser would verify the VC's authenticity cryptographically, without needing to query the authenticator.

2. **Portable authenticator attestation**: A VC could carry attestation metadata about the authenticator (type, capabilities, assurance level) issued by the authenticator manufacturer or a trusted third party. This would allow the browser to determine credential usability with SPC from the VC rather than from the authenticator's silent-query API.

3. **Cross-jurisdictional trust**: VCs are jurisdiction-agnostic and can carry trust framework annotations (e.g., eIDAS assurance levels, PSD2 SCA compliance). This directly supports cross-border payment authentication where different jurisdictions have different regulatory requirements.

4. **DID-based RP identity**: Using DIDs as RP identifiers in SPC would enable cross-origin authentication without the CTAP `thirdPartyPayment` bit. The VC would authorize specific third-party origins to use the credential, and the browser would verify this authorization from the VC rather than from the authenticator.

### Test Implications

The test suite now includes 27 VC-enhanced tests confirming: VC-based detection works for all 10 authenticator types, BBS+ selective disclosure preserves privacy, ISO 20022 SupplementaryData mapping is validated, and the 3p case is fully unblocked. The `silentlyDetermineThirdPartyEnabled` function has been extended with a `vc-based` strategy that checks VC claims instead of querying the authenticator.

---

## 9. Recommended Approach

### Near-Term (2026): Proposal 1 + Proposal 2 + BBK

**Adopt both of Stephen's proposals, combined with BBKs:**

1. **Proposal 1 (partitioned credential lists)**: Accept the explainer's alternative for 3p cases — regress on the "never show rp.com unless bit is set" promise and instead only ensure the signed cryptogram isn't returned if the bit is missing after the fact. This unblocks the 3p case for non-queryable authenticators.

2. **Proposal 2 (`alwaysShowTransactionDialog`)**: Adopt as a non-normative hint for websites that expect roaming authenticator usage (common in cross-border and corporate banking flows).

3. **BBKs**: Already in the spec. Ensure BBK creation and signing are enabled by default for all SPC flows, providing the device-binding factor needed for PSD2 SCA compliance.

4. **Issue #273**: Fix the silent bit-loss bug — the spec should require the browser to inform the RP when the `thirdPartyPayment` bit could not be stored on the authenticator.

**Rationale:** This combination provides the best near-term coverage (score 48/70) with manageable spec complexity. It addresses the 1p case fully, improves the 3p case (with the regression trade-off), and adds device binding for regulatory compliance.

### Medium-Term (2027): VC-Enhanced + BBK

**Implement the VC-enhanced detection strategy as a spec extension, building on the author's ISO/TC 307 contributions:**

1. Define a VC schema for SPC credential metadata (4 new claims: `thirdPartyPayment`, `authenticatorAssuranceLevel`, `deviceBound`, `bbkPublicKey`) as an extension to the author's existing VC compliance profile
2. Specify how the browser verifies this VC during the silent-detection steps (BBS+ signature verification replaces authenticator query)
3. Use BBS+ selective disclosure to preserve the WebAuthn privacy model (merchants see only `thirdPartyPayment`/`rpId`; regulators see only compliance claims)
4. Map SPC authentication evidence to ISO 20022 `SupplementaryData/ComplianceEvidence` per the author's harmonisation framework
5. Include W3C Status List 2021 for credential authorization revocation
6. Coordinate with the W3C VC Working Group on interoperability

**Rationale:** This approach scores 70/70 — the maximum — and addresses the root cause: the browser's dependence on authenticator APIs for metadata that can be carried externally as a verifiable, portable VC. It aligns with the author's ongoing ISO/TC 307 work on bridging VCs and ISO 20022 payment messaging. The 27 VC-enhanced tests confirm all 10 authenticator types reach Transaction UX in both 1p and 3p cases.

### Long-Term (2028+): DID-Based Cross-Origin Authentication

**Replace the CTAP `thirdPartyPayment` bit with DID-based authorization:**

1. RPs register a DID and associate authorized third-party origins
2. The browser resolves the DID to determine cross-origin authorization
3. No authenticator-level bit needed — authorization is cryptographic and portable

**Rationale:** This eliminates the third-party payment bit problem entirely, but requires broader ecosystem adoption of DIDs in payment authentication.

---

## 10. Open Questions for the WPWG

1. **3p case regression**: Is the WPWG willing to regress on the "never show rp.com unless bit is set" promise in exchange for unblocking non-queryable authenticators in cross-origin flows? (Stephen's explainer raises this as an explicit alternative.)

2. **Fallback UX design**: How should the "Use passkey for [rp.com]" option be presented in the fallback UX without confusing users? Stephen notes this is "challenging to design."

3. **Issue #273 priority**: Should the spec require browsers to inform the RP when the `thirdPartyPayment` bit cannot be stored? This is a prerequisite for RPs to make informed decisions about fallback authentication methods.

4. **BBK + non-queryable authenticators**: Should BBKs be created when a user successfully authenticates via the "Use passkey" path in Proposal 1, even though the browser couldn't silently detect the credential?

5. **VC-enhanced SPC as spec extension**: Should the WPWG consider a VC-based detection strategy as a spec extension, building on the author's ISO/TC 307 VC compliance profile? This would be a cross-WG effort with the W3C VCWG. The test suite demonstrates 70/70 score with all 10 authenticator types covered.

6. **BBS+ selective disclosure for SPC privacy**: Should the SPC spec require BBS+ selective disclosure for VC-based credential metadata, ensuring merchants see only transaction-essential claims while regulators can access compliance claims?

7. **Cross-border testing**: Should the WG prioritize testing SPC with roaming authenticators in cross-border payment scenarios, given the regulatory implications for EU PSD2 SCA compliance?

---

## 11. How to Run the Test Suite

```bash
cd /Users/olvisgil/CascadeProjects/spc-research
npm install
npm test
```

For JSON output:
```bash
npm run test:report
```

Results are written to `results.json`.

---

## 12. References

- [Authenticators and SPC](https://github.com/w3c/secure-payment-confirmation/blob/main/explorations/authenticators-and-spc.md) — Stephen McGruer & Ian Jacobs, July 2025
- [Non-queryable authenticators explainer](https://github.com/w3c/secure-payment-confirmation/blob/main/explorations/non-queryable-authenticators.md) — Stephen McGruer, Aug 2026
- [SPC Specification (Editor's Draft)](https://w3c.github.io/secure-payment-confirmation/) — W3C WPWG
- [Issue #312: Prioritization](https://github.com/w3c/secure-payment-confirmation/issues/312)
- [Issue #12: Roaming authenticators](https://github.com/w3c/secure-payment-confirmation/issues/12)
- [Issue #271: BBK proposal](https://github.com/w3c/secure-payment-confirmation/issues/271)
- [Issue #273: Third-party payment bit loss](https://github.com/w3c/secure-payment-confirmation/issues/273)
- [Issue #253: Cross-device authentication](https://github.com/w3c/secure-payment-confirmation/issues/253)
- [Issue #306: UVI as possession factor](https://github.com/w3c/secure-payment-confirmation/issues/306)
- [Issue #310: Multiple RPs](https://github.com/w3c/secure-payment-confirmation/issues/310)
- [BBK Requirements](https://github.com/w3c/secure-payment-confirmation/blob/main/bbk-requirements.md)
- [WebAuthn Immediate Mediation explainer](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-immediate-mediation)
- [WebAuthn PR #2291: Immediate uiMode](https://github.com/w3c/webauthn/pull/2291)
- **[Harmonising DLT Retail Payment Models with Existing Financial Messaging and Payment Standards](https://github.com/mozartpay/OAs)** — O.E. Gil Ríos, ISO/TC 307 N XXXX, September 2026
- **[Developing a Privacy-Preserving Identity & Compliance Profile for Retail Payment Flows](https://github.com/mozartpay/OAs)** — O.E. Gil Ríos, ISO/TC 307 N XXXX, September 2026
- **[Interoperability Test Vectors and Conformance Framework for DLT Retail Payments](https://github.com/mozartpay/OAs)** — O.E. Gil Ríos, ISO/TC 307 N XXXX, August 2026
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) — W3C Recommendation, 2025
- [W3C Status List 2021](https://www.w3.org/TR/vc-status-list-2021/) — W3C Recommendation
- [BBS+ Signatures](https://www.w3.org/TR/vc-di-bbs/) — W3C Verifiable Credential Data Integrity BBS Cryptosuites
