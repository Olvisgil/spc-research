import {
  MockCredential,
  SPCChallenge,
  SPCFlowResult,
  UXFlow,
  UserChoice,
  SPCAssertionResult,
  AuthenticatorCapabilities,
} from '../types.js';
import { getAuthenticatorProfile, AUTHENTICATOR_PROFILES } from '../authenticators/registry.js';
import { VCStore, VCVerifier } from '../vc/issuer.js';
import { SPCCredentialClaims } from '../vc/types.js';
import * as crypto from 'crypto';

// SPC Engine — implements the spec's silent-detection algorithms and simulates the full SPC flow

export type DetectionStrategy = 'simple-query' | 'simple-response' | 'creation-time-cache' | 'vc-based';

export interface SPCEngineOptions {
  detectionStrategy: DetectionStrategy;
  isThirdParty: boolean;       // Is this a 3p SPC call (merchant calling on behalf of RP)?
  alwaysShowTransactionDialog: boolean;  // Proposal 2 flag
  enableProposal1: boolean;    // Enable partitioned credential lists (Proposal 1)
  enableBBK: boolean;          // Enable Browser Bound Keys
  browserProfileCache: Map<string, MockCredential>;  // Simulated browser profile credential store
  vcStore?: VCStore;           // VC-based detection: browser's local VC store
  vcVerifier?: VCVerifier;     // VC-based detection: verifier for BBS+ proofs
  callingOrigin?: string;      // Origin of the calling website (for 3p authorization check)
}

// Step 1: Steps to silently determine if a credential is available for the current device
// (Currently "as-yet undefined process" in the SPC spec)
export function silentlyDetermineCredentialAvailability(
  credentialId: string,
  credentials: MockCredential[],
  strategy: DetectionStrategy,
  browserProfileCache: Map<string, MockCredential>,
  options?: { vcStore?: VCStore },
): boolean {
  const credential = credentials.find((c) => c.id === credentialId);
  if (!credential) return false;

  const profile = getAuthenticatorProfile(credential.authenticatorType);

  switch (strategy) {
    case 'simple-query': {
      // Browser silently queries all reachable authenticators for all credentials for that RP
      // Then compares returned list against input
      if (!profile.connected) return false;
      if (!profile.supportsSilentListing) return false;
      // Check if this credential exists in the authenticator's store
      return true; // If we found it in the authenticator, it's available
    }

    case 'simple-response': {
      // Browser silently queries: "Do you have this credential?" — yes/no response
      if (!profile.connected) return false;
      // Even non-queryable authenticators might respond to a direct credential ID query
      // But "closed" authenticators don't allow this
      if (!profile.queryable) return false;
      return true;
    }

    case 'creation-time-cache': {
      // Browser checks its own cache from credential creation time
      // Only recognizes credentials created through that specific browser
      return browserProfileCache.has(credentialId);
    }

    case 'vc-based': {
      // VC-based detection: check if a VC exists for this credential in the browser's VC store
      // This works for ALL authenticator types — no authenticator query needed
      // The VC was issued at credential registration time and stored locally
      if (!options?.vcStore) return false;
      return options.vcStore.has(credentialId);
    }

    default:
      return false;
  }
}

// Step 2: Steps to silently determine if an SPC Credential is third-party enabled
// (Currently "as-yet undefined process" in the SPC spec)
export function silentlyDetermineThirdPartyEnabled(
  credentialId: string,
  credentials: MockCredential[],
  strategy: DetectionStrategy,
  browserProfileCache: Map<string, MockCredential>,
  options?: { vcStore?: VCStore; vcVerifier?: VCVerifier; callingOrigin?: string },
): boolean {
  const credential = credentials.find((c) => c.id === credentialId);
  if (!credential) return false;

  const profile = getAuthenticatorProfile(credential.authenticatorType);

  switch (strategy) {
    case 'simple-query':
    case 'simple-response': {
      // Need to query the authenticator for the thirdPartyPayment bit
      if (!profile.connected) return false;
      if (!profile.supportsThirdPartyPaymentBit) return false;
      return credential.thirdPartyPaymentBit;
    }

    case 'creation-time-cache': {
      // Check browser's cached record of the bit
      const cached = browserProfileCache.get(credentialId);
      if (!cached) return false;
      return cached.thirdPartyPaymentBit;
    }

    case 'vc-based': {
      // VC-based detection: verify the VC's thirdPartyPayment claim
      // This replaces the CTAP bit check with a VC claim check
      // Works for ALL authenticator types — no authenticator query needed
      if (!options?.vcStore) return false;
      const vc = options.vcStore.retrieve(credentialId);
      if (!vc) return false;

      // Verify the VC's BBS+ signature
      if (options.vcVerifier) {
        const verification = options.vcVerifier.verifyVC(vc);
        if (!verification.valid) return false;
      }

      // Check the thirdPartyPayment claim
      const claims = vc.credentialSubject;
      if (!claims.thirdPartyPayment) return false;

      // Check origin authorization if callingOrigin is provided
      if (options.callingOrigin && claims.authorizedOrigins) {
        if (!claims.authorizedOrigins.includes(options.callingOrigin)) {
          return false;
        }
      }

      return true;
    }

    default:
      return false;
  }
}

// Main SPC flow simulation
export function simulateSPCFlow(
  challenge: SPCChallenge,
  credentials: MockCredential[],
  options: SPCEngineOptions,
  userChoice: UserChoice,
): SPCFlowResult {
  const definitelyAvailable: string[] = [];
  const potentiallyAvailable: string[] = [];

  // Step: Check if a payment can be made (modified for Proposal 1)
  for (const credId of challenge.credentialIds) {
    const isAvailable = silentlyDetermineCredentialAvailability(
      credId,
      credentials,
      options.detectionStrategy,
      options.browserProfileCache,
      { vcStore: options.vcStore },
    );

    if (!isAvailable) {
      // Credential not silently detectable
      if (options.enableProposal1) {
        potentiallyAvailable.push(credId);
      }
      continue;
    }

    if (!options.isThirdParty) {
      // First-party case — no need to check third-party bit
      definitelyAvailable.push(credId);
      continue;
    }

    // Third-party case — check third-party payment bit
    const isThirdPartyEnabled = silentlyDetermineThirdPartyEnabled(
      credId,
      credentials,
      options.detectionStrategy,
      options.browserProfileCache,
      { vcStore: options.vcStore, vcVerifier: options.vcVerifier, callingOrigin: options.callingOrigin },
    );

    if (isThirdPartyEnabled) {
      definitelyAvailable.push(credId);
    } else if (options.enableProposal1) {
      // In proposal 1, we could still add to potentially available
      // But step 4 of the proposal clears potentiallyAvailable for 3p cases
      // (unless we regress on the promise — see explainer note)
      potentiallyAvailable.push(credId);
    }
  }

  // Step 4 of Proposal 1: Clear potentiallyAvailable for 3p cases
  // (to enforce third-party payment bit protection)
  if (options.isThirdParty && options.enableProposal1) {
    potentiallyAvailable.length = 0;
  }

  // Determine UX flow
  let uxFlow: UXFlow;
  let assertion: SPCAssertionResult | null = null;
  let error: string | null = null;
  let bbkCreated = false;
  let bbkUsed = false;

  if (options.alwaysShowTransactionDialog) {
    // Proposal 2: Always show transaction UX regardless of detection
    uxFlow = 'transaction-ux';
  } else if (definitelyAvailable.length > 0) {
    uxFlow = 'transaction-ux';
  } else if (options.enableProposal1 && potentiallyAvailable.length > 0) {
    uxFlow = 'fallback-ux-with-passkey-option';
  } else if (challenge.credentialIds.length > 0) {
    uxFlow = 'fallback-ux';
  } else {
    uxFlow = 'no-credentials';
  }

  // Process user choice
  const credentialToUse = definitelyAvailable.length > 0
    ? definitelyAvailable[0]
    : potentiallyAvailable.length > 0
      ? potentiallyAvailable[0]
      : null;

  const cred = credentialToUse ? credentials.find((c) => c.id === credentialToUse) : null;

  switch (userChoice) {
    case 'verify': {
      if (uxFlow === 'transaction-ux' && cred) {
        // Check BBK creation BEFORE generateAssertion (which mutates cred.bbkPublicKey)
        if (options.enableBBK) {
          bbkUsed = true;
          if (!cred.bbkPublicKey) {
            bbkCreated = true;
          }
        }
        // Generate assertion
        assertion = generateAssertion(cred, challenge, options);
      } else if (uxFlow === 'transaction-ux' && !cred && options.alwaysShowTransactionDialog) {
        // Proposal 2 with no detectable credentials — WebAuthn will show "cannot proceed"
        error = 'NotAllowedError — WebAuthn cannot proceed, no credentials found';
      }
      break;
    }

    case 'use-passkey': {
      // Proposal 1: User explicitly chose to use a passkey from fallback UX
      if (uxFlow === 'fallback-ux-with-passkey-option' && potentiallyAvailable.length > 0) {
        // Trigger WebAuthn with potentially available credentials
        // For 3p case, potentiallyAvailable was cleared — so this would fail
        if (options.isThirdParty) {
          error = 'NotAllowedError — cannot verify third-party payment bit for non-queryable credential';
        } else {
          const potCred = credentials.find((c) => c.id === potentiallyAvailable[0]);
          if (potCred) {
            // Check BBK creation BEFORE generateAssertion
            if (options.enableBBK) {
              bbkUsed = true;
              if (!potCred.bbkPublicKey) {
                bbkCreated = true;
              }
            }
            assertion = generateAssertion(potCred, challenge, options);
          } else {
            // Credential ID was provided but no matching credential exists
            error = 'NotAllowedError — WebAuthn cannot proceed, no credentials available';
          }
        }
      } else {
        // No potentially available credentials — WebAuthn "cannot proceed" state
        error = 'NotAllowedError — WebAuthn cannot proceed, no credentials available';
      }
      break;
    }

    case 'verify-another-way': {
      error = 'NotAllowedError — user chose to verify another way';
      break;
    }

    case 'confirm': {
      // Fallback UX — user confirms but no passkey authentication
      error = 'NotAllowedError — user confirmed without passkey authentication';
      break;
    }

    case 'cancel': {
      error = 'AbortError — user cancelled';
      break;
    }

    case 'opt-out': {
      error = 'NotAllowedError — user opted out of SPC for this RP';
      break;
    }
  }

  return {
    uxFlow,
    userChoice,
    assertion,
    error,
    definitelyAvailable,
    potentiallyAvailable,
    bbkCreated,
    bbkUsed,
  };
}

// Generate a simulated SPC assertion
function generateAssertion(
  credential: MockCredential,
  challenge: SPCChallenge,
  options: SPCEngineOptions,
): SPCAssertionResult {
  const authenticatorData = crypto.randomBytes(37).toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'payment.get',
    challenge: challenge.challenge,
    origin: challenge.payeeOrigin,
    crossOrigin: options.isThirdParty,
  })).toString('base64url');
  const signature = crypto.randomBytes(64).toString('base64url');

  let bbkSignature: string | undefined;
  let bbkPublicKey: string | undefined;

  if (options.enableBBK) {
    if (!credential.bbkPublicKey) {
      // Create BBK
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' });
      bbkPublicKey = pubKeyDer.toString('base64url');
      credential.bbkPublicKey = bbkPublicKey;
      credential.bbkPrivateKey = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
    } else {
      bbkPublicKey = credential.bbkPublicKey;
    }

    // Sign transaction data with BBK
    const txData = Buffer.from(JSON.stringify({
      payeeName: challenge.payeeName,
      payeeOrigin: challenge.payeeOrigin,
      totalAmount: challenge.totalAmount,
      totalCurrency: challenge.totalCurrency,
    }));
    const key = crypto.createPrivateKey({
      key: Buffer.from(credential.bbkPrivateKey!, 'base64url'),
      format: 'der',
      type: 'pkcs8',
    });
    bbkSignature = crypto.sign(null, txData, key).toString('base64url');
  }

  return {
    credentialId: credential.id,
    authenticatorData,
    clientDataJSON,
    signature,
    userHandle: credential.userHandle,
    bbkSignature,
    bbkPublicKey,
    thirdPartyPaymentBit: credential.thirdPartyPaymentBit,
  };
}
