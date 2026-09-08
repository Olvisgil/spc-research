// Core types for SPC non-queryable authenticator research

export type Platform = 'windows' | 'macos' | 'android' | 'ios' | 'chromeos' | 'linux';

export type AuthenticatorType =
  | 'gpm'           // Google Password Manager (direct API)
  | 'windows-hello' // Windows Hello
  | 'icloud-keychain'
  | 'chrome-internal'
  | 'credman'       // Android Credential Manager
  | 'third-party'   // Third-party passkey provider
  | 'roaming-usb'   // USB security key
  | 'roaming-nfc'   // NFC security key
  | 'roaming-bluetooth' // Bluetooth security key
  | 'hybrid';       // Cross-device via hybrid transport

export interface AuthenticatorCapabilities {
  type: AuthenticatorType;
  platform: Platform;
  queryable: boolean;              // Can browser silently query for credential existence?
  supportsThirdPartyPaymentBit: boolean;  // Can store/retrieve CTAP thirdPartyPayment bit?
  supportsSilentListing: boolean;  // Can browser list all credentials for an RP?
  connected: boolean;              // Is the authenticator currently connected/available?
  isPlatform: boolean;             // Platform authenticator (vs roaming)
}

export interface MockCredential {
  id: string;                      // Credential ID (base64url)
  rpId: string;                    // Relying Party ID
  userHandle: string;              // User handle
  publicKey: string;               // Public key (base64url)
  thirdPartyPaymentBit: boolean;  // CTAP thirdPartyPayment bit
  authenticatorType: AuthenticatorType;
  platform: Platform;
  isDiscoverable: boolean;
  bbkPublicKey?: string;           // Browser Bound Key public key
  bbkPrivateKey?: string;          // BBK private key (simulated, device-bound)
}

export interface SPCChallenge {
  challenge: string;               // base64url challenge
  rpId: string;
  credentialIds: string[];
  payeeName: string;
  payeeOrigin: string;
  totalAmount: string;
  totalCurrency: string;
  browserBoundPubKeyCredParams?: Array<{ type: string; alg: number }>;
  alwaysShowTransactionDialog?: boolean;
}

export interface SPCAssertionResult {
  credentialId: string;
  authenticatorData: string;       // base64url
  clientDataJSON: string;           // base64url
  signature: string;                // base64url
  userHandle: string;
  bbkSignature?: string;            // base64url BBK signature
  bbkPublicKey?: string;            // base64url BBK public key
  thirdPartyPaymentBit: boolean;
}

export type UXFlow = 'transaction-ux' | 'fallback-ux' | 'fallback-ux-with-passkey-option' | 'no-credentials';

export type UserChoice = 'verify' | 'verify-another-way' | 'confirm' | 'cancel' | 'use-passkey' | 'opt-out';

export interface SPCFlowResult {
  uxFlow: UXFlow;
  userChoice: UserChoice | null;
  assertion: SPCAssertionResult | null;
  error: string | null;
  definitelyAvailable: string[];
  potentiallyAvailable: string[];
  bbkCreated: boolean;
  bbkUsed: boolean;
}

export interface TestScenarioResult {
  name: string;
  description: string;
  passed: boolean;
  expectedUXFlow: UXFlow;
  actualUXFlow: UXFlow;
  details: string;
  score: number;  // 0-100
  category: string;
}

export interface ProposalScore {
  proposalName: string;
  uxQuality: number;          // 0-10
  specComplexity: number;     // 0-10 (lower = simpler = better)
  privacyImpact: number;      // 0-10 (higher = better privacy)
  crossBorderApplicability: number; // 0-10
  iso20022Alignment: number; // 0-10
  vcInteroperability: number; // 0-10
  authenticatorCoverage: number; // 0-10
  totalScore: number;
  notes: string;
}
