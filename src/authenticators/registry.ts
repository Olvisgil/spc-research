import { AuthenticatorCapabilities, AuthenticatorType, Platform, MockCredential } from '../types.js';

// Simulated authenticator registry — models the capability profiles from authenticators-and-spc.md

export const AUTHENTICATOR_PROFILES: Record<AuthenticatorType, AuthenticatorCapabilities> = {
  'gpm': {
    type: 'gpm',
    platform: 'android',
    queryable: true,
    supportsThirdPartyPaymentBit: true,
    supportsSilentListing: true,
    connected: true,
    isPlatform: true,
  },
  'windows-hello': {
    type: 'windows-hello',
    platform: 'windows',
    queryable: true,        // Windows 11 only — list-credentials API
    supportsThirdPartyPaymentBit: true, // Windows 11 only
    supportsSilentListing: true,        // Windows 11 only
    connected: true,
    isPlatform: true,
  },
  'icloud-keychain': {
    type: 'icloud-keychain',
    platform: 'macos',
    queryable: false,       // No silent listing API
    supportsThirdPartyPaymentBit: false,
    supportsSilentListing: false,
    connected: true,
    isPlatform: true,
  },
  'chrome-internal': {
    type: 'chrome-internal',
    platform: 'macos',
    queryable: true,        // Has list-credentials API but Chrome doesn't use it for SPC
    supportsThirdPartyPaymentBit: false,
    supportsSilentListing: true,
    connected: true,
    isPlatform: true,
  },
  'credman': {
    type: 'credman',
    platform: 'android',
    queryable: false,       // CredMan intermediates — no direct silent query
    supportsThirdPartyPaymentBit: false,
    supportsSilentListing: false,
    connected: true,
    isPlatform: true,
  },
  'third-party': {
    type: 'third-party',
    platform: 'macos',      // Could be any platform; using macos as example
    queryable: false,       // Depends on provider — generally no
    supportsThirdPartyPaymentBit: false,
    supportsSilentListing: false,
    connected: true,
    isPlatform: true,
  },
  'roaming-usb': {
    type: 'roaming-usb',
    platform: 'windows',    // Could be any platform
    queryable: true,        // When connected, USB keys can be queried
    supportsThirdPartyPaymentBit: true, // If they support FIDO thirdPartyPayment extension
    supportsSilentListing: true,
    connected: false,       // Not currently plugged in (non-queryable scenario)
    isPlatform: false,
  },
  'roaming-nfc': {
    type: 'roaming-nfc',
    platform: 'android',
    queryable: false,       // NFC requires user action to tap
    supportsThirdPartyPaymentBit: true,
    supportsSilentListing: false,
    connected: false,
    isPlatform: false,
  },
  'roaming-bluetooth': {
    type: 'roaming-bluetooth',
    platform: 'windows',
    queryable: false,       // Bluetooth requires pairing/discovery
    supportsThirdPartyPaymentBit: true,
    supportsSilentListing: false,
    connected: false,
    isPlatform: false,
  },
  'hybrid': {
    type: 'hybrid',
    platform: 'android',    // Phone as authenticator for desktop
    queryable: false,       // Cannot silently determine if nearby phone has credential
    supportsThirdPartyPaymentBit: false,
    supportsSilentListing: false,
    connected: false,
    isPlatform: false,
  },
};

export function getAuthenticatorProfile(type: AuthenticatorType): AuthenticatorCapabilities {
  const profile = AUTHENTICATOR_PROFILES[type];
  if (!profile) {
    throw new Error(`Unknown authenticator type: ${type}`);
  }
  return { ...profile };
}

export function getAuthenticatorProfileWithState(
  type: AuthenticatorType,
  overrides: Partial<AuthenticatorCapabilities> = {},
): AuthenticatorCapabilities {
  return { ...getAuthenticatorProfile(type), ...overrides };
}

// Simulate credential creation on a given authenticator
export function createMockCredential(
  rpId: string,
  userHandle: string,
  authenticatorType: AuthenticatorType,
  platform: Platform,
  options: { thirdPartyPayment?: boolean; discoverable?: boolean } = {},
): MockCredential {
  const profile = getAuthenticatorProfile(authenticatorType);
  const credentialId = generateId();
  const publicKey = generateId();

  // Third-party payment bit is only stored if the authenticator supports it
  let thirdPartyPaymentBit = false;
  if (options.thirdPartyPayment && profile.supportsThirdPartyPaymentBit) {
    thirdPartyPaymentBit = true;
  }
  // If the authenticator doesn't support the bit, it's silently lost (issue #273)
  // The credential is still created, but the bit is not stored

  return {
    id: credentialId,
    rpId,
    userHandle,
    publicKey,
    thirdPartyPaymentBit,
    authenticatorType,
    platform,
    isDiscoverable: options.discoverable ?? true,
  };
}

// Utility: generate random base64url-like ID
function generateId(): string {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return Buffer.from(bytes).toString('base64url');
}
