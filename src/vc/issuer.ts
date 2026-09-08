import * as crypto from 'crypto';
import {
  VerifiableCredential,
  VCPresentation,
  BBSPlusProof,
  SPCCredentialClaims,
  AssuranceLevel,
  BaseComplianceClaims,
} from './types.js';
import { MockCredential } from '../types.js';
import { getAuthenticatorProfile } from '../authenticators/registry.js';

// VC Issuer — simulates RP issuing a VC at credential registration time
// The VC carries SPC metadata that replaces the CTAP thirdPartyPayment bit

export class VCIssuer {
  private issuerDID: string;

  constructor(issuerDID: string = 'did:web:bank.example') {
    this.issuerDID = issuerDID;
  }

  getIssuerDID(): string {
    return this.issuerDID;
  }

  // Issue an SPC credential VC at WebAuthn credential registration time
  issueSPCCredential(
    credential: MockCredential,
    baseClaims: Partial<BaseComplianceClaims> = {},
    options: {
      authorizedOrigins?: string[];
      expirationDays?: number;
    } = {},
  ): VerifiableCredential {
    const profile = getAuthenticatorProfile(credential.authenticatorType);

    // Determine assurance level based on authenticator capabilities
    const assuranceLevel = this.determineAssuranceLevel(credential, profile.isPlatform);

    // Determine deviceBound from BBK presence
    const deviceBound = !!credential.bbkPublicKey;

    const claims: SPCCredentialClaims = {
      // Base compliance claims from Olvis's profile
      legalPersonIdentifier: baseClaims.legalPersonIdentifier,
      amlRiskCategory: baseClaims.amlRiskCategory,
      subjectRole: 'originator',
      transactionPurposeCode: baseClaims.transactionPurposeCode,
      consentProof: baseClaims.consentProof,

      // SPC extension claims
      thirdPartyPayment: credential.thirdPartyPaymentBit,
      authenticatorAssuranceLevel: assuranceLevel,
      deviceBound,
      bbkPublicKey: credential.bbkPublicKey,
      authenticatorType: credential.authenticatorType,
      rpId: credential.rpId,
      credentialId: credential.id,
      authorizedOrigins: options.authorizedOrigins ?? [],
    };

    const now = new Date();
    const expirationDate = new Date(now);
    expirationDate.setDate(expirationDate.getDate() + (options.expirationDays ?? 365));

    // Simulate BBS+ signature
    const proofValue = this.simulateBBSSignature(JSON.stringify(claims));

    const vc: VerifiableCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://ogtechnologies.eu/spc/2026',
      ],
      type: ['VerifiableCredential', 'SPCCredential'],
      issuer: this.issuerDID,
      issuanceDate: now.toISOString(),
      expirationDate: expirationDate.toISOString(),
      credentialSubject: claims,
      proof: {
        type: 'BbsSignature2020',
        created: now.toISOString(),
        verificationMethod: `${this.issuerDID}#keys-1`,
        proofPurpose: 'assertionMethod',
        proofValue,
      },
      credentialStatus: {
        type: 'StatusList2021',
        id: `https://bank.example/status-list/${credential.rpId}`,
        statusPurpose: 'revocation',
        statusListIndex: Math.floor(Math.random() * 100000),
      },
    };

    return vc;
  }

  // Determine assurance level from authenticator profile and device binding
  private determineAssuranceLevel(
    credential: MockCredential,
    isPlatform: boolean,
  ): AssuranceLevel {
    const profile = getAuthenticatorProfile(credential.authenticatorType);

    // Hardware-backed roaming authenticator + BBK = high
    if (!isPlatform && credential.bbkPublicKey) {
      return 'high';
    }

    // Platform authenticator with BBK = substantial
    if (isPlatform && credential.bbkPublicKey) {
      return 'substantial';
    }

    // Platform authenticator without BBK = low
    return 'low';
  }

  // Simulate BBS+ signature (in production, use @mattrglobal/bbs-signatures or similar)
  private simulateBBSSignature(payload: string): string {
    return crypto.createHash('sha256').update(payload).digest('base64url');
  }
}

// VC Verifier — simulates browser verifying a VC at SPC authentication time
// Replaces the SPC spec's "silently determine" steps with VC verification

export class VCVerifier {
  private trustedIssuers: Set<string>;

  constructor(trustedIssuers: string[] = ['did:web:bank.example']) {
    this.trustedIssuers = new Set(trustedIssuers);
  }

  addTrustedIssuer(issuerDID: string): void {
    this.trustedIssuers.add(issuerDID);
  }

  // Verify a VC's BBS+ signature and claims
  verifyVC(vc: VerifiableCredential): { valid: boolean; reason?: string; claims?: SPCCredentialClaims } {
    // Check issuer is trusted
    if (!this.trustedIssuers.has(vc.issuer)) {
      return { valid: false, reason: `Untrusted issuer: ${vc.issuer}` };
    }

    // Check expiration
    if (vc.expirationDate) {
      const exp = new Date(vc.expirationDate);
      if (exp < new Date()) {
        return { valid: false, reason: 'VC expired' };
      }
    }

    // Verify BBS+ proof (simulated — in production, verify cryptographically)
    const expectedProof = crypto
      .createHash('sha256')
      .update(JSON.stringify(vc.credentialSubject))
      .digest('base64url');

    if (vc.proof.proofValue !== expectedProof) {
      return { valid: false, reason: 'BBS+ signature verification failed' };
    }

    return { valid: true, claims: vc.credentialSubject };
  }

  // Create a selective disclosure presentation — only reveal specified claims
  // This preserves the WebAuthn privacy model: merchant only sees what's needed
  createPresentation(
    vc: VerifiableCredential,
    revealedClaims: string[],
    holderDID: string = 'did:web:browser.example',
  ): VCPresentation {
    // Filter credentialSubject to only revealed claims
    const revealedSubject: Partial<SPCCredentialClaims> = {};
    const fullSubject = vc.credentialSubject as unknown as Record<string, unknown>;
    for (const key of revealedClaims) {
      if (key in fullSubject) {
        (revealedSubject as Record<string, unknown>)[key] = fullSubject[key];
      }
    }

    // Simulate BBS+ selective disclosure proof
    const proofValue = crypto
      .createHash('sha256')
      .update(JSON.stringify(revealedSubject) + revealedClaims.join(','))
      .digest('base64url');

    return {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: 'VerifiablePresentation',
      holder: holderDID,
      verifiableCredential: {
        '@context': vc['@context'],
        type: vc.type,
        issuer: vc.issuer,
        issuanceDate: vc.issuanceDate,
        credentialSubject: revealedSubject,
      },
      proof: {
        type: 'BbsSignature2020',
        created: new Date().toISOString(),
        verificationMethod: `${holderDID}#keys-1`,
        proofPurpose: 'assertionMethod',
        proofValue,
        revealedAttributes: revealedClaims,
      },
    };
  }

  // Verify a presentation's selective disclosure proof
  verifyPresentation(presentation: VCPresentation): { valid: boolean; revealedClaims?: Partial<SPCCredentialClaims> } {
    // In production: verify BBS+ proof that revealed claims are a valid subset of the original VC
    // Here we simulate by checking proof exists
    if (!presentation.proof || !presentation.proof.proofValue) {
      return { valid: false };
    }

    return {
      valid: true,
      revealedClaims: presentation.verifiableCredential.credentialSubject,
    };
  }

  // Check if a VC authorizes a specific origin for 3p SPC
  isAuthorizedForOrigin(claims: SPCCredentialClaims, origin: string): boolean {
    if (!claims.authorizedOrigins || claims.authorizedOrigins.length === 0) {
      return false;
    }
    return claims.authorizedOrigins.includes(origin);
  }

  // Check VC revocation status (simulated via W3C Status List 2021)
  checkRevocationStatus(vc: VerifiableCredential): { revoked: boolean; suspended: boolean } {
    // In production: fetch status list and check index
    // Here we simulate: not revoked unless explicitly marked
    if (!vc.credentialStatus) {
      return { revoked: false, suspended: false };
    }
    return { revoked: false, suspended: false };
  }
}

// VC Store — simulates the browser's local VC store
// VCs are created at credential registration time and stored locally
// At SPC authentication time, the browser retrieves VCs from this store
export class VCStore {
  private vcs: Map<string, VerifiableCredential> = new Map(); // credentialId -> VC

  store(credentialId: string, vc: VerifiableCredential): void {
    this.vcs.set(credentialId, vc);
  }

  retrieve(credentialId: string): VerifiableCredential | undefined {
    return this.vcs.get(credentialId);
  }

  has(credentialId: string): boolean {
    return this.vcs.has(credentialId);
  }

  remove(credentialId: string): void {
    this.vcs.delete(credentialId);
  }

  getAll(): Map<string, VerifiableCredential> {
    return new Map(this.vcs);
  }
}
