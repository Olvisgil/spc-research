import { MockCredential, SPCChallenge, SPCAssertionResult, AuthenticatorType, Platform } from '../types.js';
import { createMockCredential } from '../authenticators/registry.js';
import * as crypto from 'crypto';

// Mock Relying Party server — simulates SPC challenge generation, credential registration, and assertion verification

export class MockRPServer {
  private rpId: string;
  private rpName: string;
  private credentials: Map<string, MockCredential> = new Map();
  private challenges: Map<string, { challenge: string; timestamp: number }> = new Map();

  constructor(rpId: string, rpName: string) {
    this.rpId = rpId;
    this.rpName = rpName;
  }

  getRpId(): string {
    return this.rpId;
  }

  getRpName(): string {
    return this.rpName;
  }

  // Generate SPC registration challenge
  generateRegistrationChallenge(userHandle: string, thirdPartyPayment: boolean = false): {
    challenge: string;
    rpId: string;
    rpName: string;
    userHandle: string;
    thirdPartyPayment: boolean;
  } {
    const challenge = crypto.randomBytes(32).toString('base64url');
    this.challenges.set(challenge, { challenge, timestamp: Date.now() });
    return {
      challenge,
      rpId: this.rpId,
      rpName: this.rpName,
      userHandle,
      thirdPartyPayment,
    };
  }

  // Generate SPC authentication challenge
  generateAuthenticationChallenge(
    credentialIds: string[],
    payeeName: string,
    payeeOrigin: string,
    totalAmount: string,
    totalCurrency: string,
    options: { browserBoundPubKeyCredParams?: Array<{ type: string; alg: number }>; alwaysShowTransactionDialog?: boolean } = {},
  ): SPCChallenge {
    const challenge = crypto.randomBytes(32).toString('base64url');
    this.challenges.set(challenge, { challenge, timestamp: Date.now() });
    return {
      challenge,
      rpId: this.rpId,
      credentialIds,
      payeeName,
      payeeOrigin,
      totalAmount,
      totalCurrency,
      browserBoundPubKeyCredParams: options.browserBoundPubKeyCredParams,
      alwaysShowTransactionDialog: options.alwaysShowTransactionDialog,
    };
  }

  // Register a credential (simulated attestation)
  registerCredential(
    userHandle: string,
    authenticatorType: AuthenticatorType,
    platform: Platform,
    options: { thirdPartyPayment?: boolean; discoverable?: boolean } = {},
  ): MockCredential {
    const challenge = this.generateRegistrationChallenge(userHandle, options.thirdPartyPayment ?? false);
    const credential = createMockCredential(
      this.rpId,
      userHandle,
      authenticatorType,
      platform,
      options,
    );
    this.credentials.set(credential.id, credential);
    return credential;
  }

  // Get all registered credentials for this RP
  getCredentials(): MockCredential[] {
    return Array.from(this.credentials.values());
  }

  // Get credential by ID
  getCredential(id: string): MockCredential | undefined {
    return this.credentials.get(id);
  }

  // Get credentials by user handle
  getCredentialsByUser(userHandle: string): MockCredential[] {
    return this.getCredentials().filter((c) => c.userHandle === userHandle);
  }

  // Verify an SPC assertion (simulated)
  verifyAssertion(assertion: SPCAssertionResult): { valid: boolean; reason?: string } {
    const credential = this.credentials.get(assertion.credentialId);
    if (!credential) {
      return { valid: false, reason: 'Unknown credential ID' };
    }

    // In a real implementation, we'd verify the signature cryptographically.
    // Here we simulate the verification logic.

    // Check that the credential's third-party payment bit matches what's claimed
    if (credential.thirdPartyPaymentBit !== assertion.thirdPartyPaymentBit) {
      return {
        valid: false,
        reason: `Third-party payment bit mismatch: credential has ${credential.thirdPartyPaymentBit}, assertion claims ${assertion.thirdPartyPaymentBit}`,
      };
    }

    // Verify BBK signature if present
    if (assertion.bbkPublicKey && assertion.bbkSignature) {
      // In real implementation, verify BBK signature over transaction data
      // Here we just check the BBK public key matches what was registered
      if (credential.bbkPublicKey && credential.bbkPublicKey !== assertion.bbkPublicKey) {
        return { valid: false, reason: 'BBK public key mismatch' };
      }
    }

    return { valid: true };
  }

  // Check if a challenge is still valid (not expired)
  isChallengeValid(challenge: string, maxAgeMs: number = 300000): boolean {
    const entry = this.challenges.get(challenge);
    if (!entry) return false;
    return Date.now() - entry.timestamp < maxAgeMs;
  }

  // Consume a challenge (one-time use)
  consumeChallenge(challenge: string): void {
    this.challenges.delete(challenge);
  }
}
