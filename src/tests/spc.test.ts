import { describe, it, expect, beforeEach } from 'vitest';
import { MockRPServer } from '../rp/server.js';
import { simulateSPCFlow, silentlyDetermineCredentialAvailability, silentlyDetermineThirdPartyEnabled, DetectionStrategy } from '../spc/engine.js';
import { MockCredential, SPCFlowResult, UXFlow } from '../types.js';
import { getAuthenticatorProfile, AUTHENTICATOR_PROFILES } from '../authenticators/registry.js';

// Test helpers
function setupRP(rpId: string = 'bank.example'): MockRPServer {
  return new MockRPServer(rpId, 'Test Bank');
}

function makeBrowserCache(credentials: MockCredential[]): Map<string, MockCredential> {
  const cache = new Map<string, MockCredential>();
  for (const cred of credentials) {
    cache.set(cred.id, cred);
  }
  return cache;
}

// ============================================================
// TEST GROUP 1: Silent Detection Strategy Comparison
// ============================================================
describe('Silent Detection Strategies', () => {
  it('simple-query: detects queryable connected authenticator', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'simple-query', new Map(),
    );
    expect(result).toBe(true);
  });

  it('simple-query: fails for non-queryable authenticator (CredMan)', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'credman', 'android', { thirdPartyPayment: true });
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'simple-query', new Map(),
    );
    expect(result).toBe(false);
  });

  it('simple-query: fails for disconnected roaming authenticator', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'simple-query', new Map(),
    );
    expect(result).toBe(false);
  });

  it('simple-response: detects queryable connected authenticator', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'simple-response', new Map(),
    );
    expect(result).toBe(true);
  });

  it('simple-response: fails for non-queryable authenticator (iCloud Keychain)', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: true });
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'simple-response', new Map(),
    );
    expect(result).toBe(false);
  });

  it('creation-time-cache: detects credential created in this browser', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'chrome-internal', 'macos', { thirdPartyPayment: false });
    const cache = makeBrowserCache([cred]);
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'creation-time-cache', cache,
    );
    expect(result).toBe(true);
  });

  it('creation-time-cache: fails for credential created in different browser', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: false });
    // Empty cache — credential was created in a different browser
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'creation-time-cache', new Map(),
    );
    expect(result).toBe(false);
  });

  it('third-party bit detection: simple-query succeeds for GPM', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const result = silentlyDetermineThirdPartyEnabled(
      cred.id, rp.getCredentials(), 'simple-query', new Map(),
    );
    expect(result).toBe(true);
  });

  it('third-party bit detection: fails for iCloud Keychain (no bit support)', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: true });
    const result = silentlyDetermineThirdPartyEnabled(
      cred.id, rp.getCredentials(), 'simple-query', new Map(),
    );
    expect(result).toBe(false);
  });

  it('third-party bit detection: creation-time-cache uses cached bit', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'chrome-internal', 'macos', { thirdPartyPayment: false });
    // Simulate browser stored the bit in profile even though authenticator doesn't support it
    const cachedCred = { ...cred, thirdPartyPaymentBit: true };
    const cache = makeBrowserCache([cachedCred]);
    const result = silentlyDetermineThirdPartyEnabled(
      cred.id, rp.getCredentials(), 'creation-time-cache', cache,
    );
    expect(result).toBe(true);
  });
});

// ============================================================
// TEST GROUP 2: Current SPC Behavior (Baseline)
// ============================================================
describe('Current SPC Behavior (Baseline)', () => {
  it('queryable passkey available → Transaction UX', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
    expect(result.error).toBeNull();
  });

  it('non-queryable passkey (CredMan) → Fallback UX', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'credman', 'android', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'confirm',
    );
    expect(result.uxFlow).toBe('fallback-ux');
    expect(result.assertion).toBeNull();
    expect(result.error).toContain('NotAllowedError');
  });

  it('non-queryable passkey (iCloud Keychain) → Fallback UX', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'confirm',
    );
    expect(result.uxFlow).toBe('fallback-ux');
  });

  it('disconnected roaming authenticator → Fallback UX', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'confirm',
    );
    expect(result.uxFlow).toBe('fallback-ux');
  });

  it('no passkey exists → Fallback UX', () => {
    const rp = setupRP();
    const challenge = rp.generateAuthenticationChallenge(
      ['nonexistent-cred-id'], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, [],
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'confirm',
    );
    expect(result.uxFlow).toBe('fallback-ux');
  });

  it('first-party case: queryable passkey without third-party bit → Transaction UX', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: false });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Test Bank', 'https://bank.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: false,  // First-party
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
  });

  it('third-party case: queryable passkey without third-party bit → Fallback UX', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: false });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'confirm',
    );
    expect(result.uxFlow).toBe('fallback-ux');
  });
});

// ============================================================
// TEST GROUP 3: Proposal 1 — Partitioned Credential Lists
// ============================================================
describe('Proposal 1: Partitioned Credential Lists', () => {
  it('non-queryable passkey in 1p case → Fallback UX with passkey option', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: false });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Test Bank', 'https://bank.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: false,  // First-party — no third-party bit needed
        alwaysShowTransactionDialog: false,
        enableProposal1: true,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'use-passkey',
    );
    expect(result.uxFlow).toBe('fallback-ux-with-passkey-option');
    expect(result.potentiallyAvailable).toContain(cred.id);
    expect(result.assertion).not.toBeNull();
  });

  it('non-queryable passkey in 3p case → Fallback UX (potentiallyAvailable cleared)', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: true,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'use-passkey',
    );
    // 3p case: potentiallyAvailable is cleared (can't verify third-party bit)
    expect(result.uxFlow).toBe('fallback-ux');
    expect(result.potentiallyAvailable).toHaveLength(0);
    expect(result.error).toContain('NotAllowedError');
  });

  it('queryable passkey available → Transaction UX (unchanged from baseline)', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: true,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.definitelyAvailable).toContain(cred.id);
  });

  it('mixed: queryable + non-queryable → Transaction UX (prefers queryable)', () => {
    const rp = setupRP();
    const credQueryable = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const credNonQueryable = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [credQueryable.id, credNonQueryable.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: false,  // 1p case — potentiallyAvailable not cleared
        alwaysShowTransactionDialog: false,
        enableProposal1: true,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.definitelyAvailable).toContain(credQueryable.id);
    expect(result.potentiallyAvailable).toContain(credNonQueryable.id);
  });

  it('no passkey exists → Fallback UX with passkey option (WebAuthn cannot proceed)', () => {
    const rp = setupRP();
    const challenge = rp.generateAuthenticationChallenge(
      ['nonexistent-cred-id'], 'Test Bank', 'https://bank.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, [],
      {
        detectionStrategy: 'simple-query',
        isThirdParty: false,
        alwaysShowTransactionDialog: false,
        enableProposal1: true,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'use-passkey',
    );
    expect(result.uxFlow).toBe('fallback-ux-with-passkey-option');
    expect(result.error).toContain('NotAllowedError');
    expect(result.error).toContain('cannot proceed');
  });
});

// ============================================================
// TEST GROUP 4: Proposal 2 — alwaysShowTransactionDialog
// ============================================================
describe('Proposal 2: alwaysShowTransactionDialog', () => {
  it('non-queryable passkey with alwaysShow → Transaction UX', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
      { alwaysShowTransactionDialog: true },
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: true,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    // But assertion will fail because credential is not detectable
    expect(result.error).toContain('NotAllowedError');
  });

  it('no passkey with alwaysShow → Transaction UX → cannot proceed', () => {
    const rp = setupRP();
    const challenge = rp.generateAuthenticationChallenge(
      ['nonexistent-cred-id'], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
      { alwaysShowTransactionDialog: true },
    );
    const result = simulateSPCFlow(
      challenge, [],
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: true,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.error).toContain('NotAllowedError');
    expect(result.error).toContain('no credentials found');
  });

  it('queryable passkey with alwaysShow → Transaction UX (same as baseline)', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
      { alwaysShowTransactionDialog: true },
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: true,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
  });

  it('3p case with alwaysShow still clears potentiallyAvailable', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
      { alwaysShowTransactionDialog: true },
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: true,
        enableProposal1: true,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.potentiallyAvailable).toHaveLength(0);
  });
});

// ============================================================
// TEST GROUP 5: Browser Bound Keys (BBK)
// ============================================================
describe('Browser Bound Keys (BBK)', () => {
  it('BBK created on first authentication', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
      { browserBoundPubKeyCredParams: [{ type: 'public-key', alg: -7 }] },
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.bbkCreated).toBe(true);
    expect(result.bbkUsed).toBe(true);
    expect(result.assertion?.bbkPublicKey).toBeDefined();
    expect(result.assertion?.bbkSignature).toBeDefined();
  });

  it('BBK reused on subsequent authentication', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const challenge1 = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    // First auth — creates BBK
    simulateSPCFlow(
      challenge1, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    // Second auth — should reuse BBK
    const challenge2 = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '200.00', 'EUR',
    );
    const result2 = simulateSPCFlow(
      challenge2, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result2.bbkCreated).toBe(false);
    expect(result2.bbkUsed).toBe(true);
  });

  it('BBK assertion verified by RP', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.assertion).not.toBeNull();
    const verification = rp.verifyAssertion(result.assertion!);
    expect(verification.valid).toBe(true);
  });
});

// ============================================================
// TEST GROUP 6: Edge Cases
// ============================================================
describe('Edge Cases', () => {
  it('issue #273: third-party payment bit silently lost on non-supporting authenticator', () => {
    const rp = setupRP();
    // Create credential on iCloud Keychain with thirdPartyPayment requested
    // But iCloud Keychain doesn't support the bit — it's silently lost
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: true });
    expect(cred.thirdPartyPaymentBit).toBe(false);  // Bit was lost!
    // RP thinks the credential has the bit, but it doesn't
    // This is the issue #273 scenario
  });

  it('creation-time-cache: cross-browser failure (Chrome → Edge)', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'chrome-internal', 'macos', { thirdPartyPayment: false });
    // Credential created in Chrome — Edge has empty cache
    const edgeCache = new Map<string, MockCredential>();
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'creation-time-cache', edgeCache,
    );
    expect(result).toBe(false);  // Edge can't see Chrome's cached credential
  });

  it('hybrid authenticator: cannot silently determine availability', () => {
    const rp = setupRP();
    const cred = rp.registerCredential('user1', 'hybrid', 'android', { thirdPartyPayment: true });
    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'simple-query', new Map(),
    );
    expect(result).toBe(false);
  });

  it('multiple credentials: mixed queryable and non-queryable, 1p case', () => {
    const rp = setupRP();
    const credGPM = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: false });
    const crediCloud = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: false });
    const credRoaming = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: false });
    const challenge = rp.generateAuthenticationChallenge(
      [credGPM.id, crediCloud.id, credRoaming.id],
      'Test Bank', 'https://bank.example', '100.00', 'EUR',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: false,
        alwaysShowTransactionDialog: false,
        enableProposal1: true,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.definitelyAvailable).toContain(credGPM.id);
    expect(result.potentiallyAvailable).toContain(crediCloud.id);
    expect(result.potentiallyAvailable).toContain(credRoaming.id);
  });

  it('cross-border scenario: EU user with roaming key authenticating LatAm merchant', () => {
    const rp = setupRP('eu-bank.example');
    const cred = rp.registerCredential('user-eu', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'LatAm Merchant', 'https://merchant.latam.example', '500.00', 'USD',
    );
    // Baseline: roaming key not connected → fallback UX
    const baselineResult = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'confirm',
    );
    expect(baselineResult.uxFlow).toBe('fallback-ux');

    // Proposal 2: alwaysShow → transaction UX (user can plug in key)
    const proposal2Result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: true,
        alwaysShowTransactionDialog: true,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
      },
      'verify',
    );
    expect(proposal2Result.uxFlow).toBe('transaction-ux');
    // But assertion fails because credential not detectable
    expect(proposal2Result.error).toContain('NotAllowedError');
  });

  it('cross-border scenario: Proposal 1 with 1p case allows roaming key', () => {
    const rp = setupRP('eu-bank.example');
    const cred = rp.registerCredential('user-eu', 'roaming-usb', 'windows', { thirdPartyPayment: false });
    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'EU Bank', 'https://eu-bank.example', '500.00', 'USD',
    );
    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'simple-query',
        isThirdParty: false,  // 1p case
        alwaysShowTransactionDialog: false,
        enableProposal1: true,
        enableBBK: true,
        browserProfileCache: new Map(),
      },
      'use-passkey',
    );
    expect(result.uxFlow).toBe('fallback-ux-with-passkey-option');
    expect(result.assertion).not.toBeNull();
    expect(result.bbkCreated).toBe(true);
  });
});
