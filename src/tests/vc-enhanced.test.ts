import { describe, it, expect, beforeEach } from 'vitest';
import { MockRPServer } from '../rp/server.js';
import { simulateSPCFlow, silentlyDetermineCredentialAvailability, silentlyDetermineThirdPartyEnabled } from '../spc/engine.js';
import { VCIssuer, VCVerifier, VCStore } from '../vc/issuer.js';
import { VerifiableCredential, SPCCredentialClaims } from '../vc/types.js';
import { mapToSupplementaryData, mapToPacs008, validatePacs008, mapAssuranceToISO20022, mapAuthenticatorToISO20022 } from '../iso20022/mapping.js';
import { MockCredential } from '../types.js';

// Test helpers
function setupVCPipeline(
  rp: MockRPServer,
  credential: MockCredential,
  authorizedOrigins: string[] = [],
  intendedThirdPartyPayment?: boolean,
): {
  vc: VerifiableCredential;
  vcStore: VCStore;
  vcVerifier: VCVerifier;
  vcIssuer: VCIssuer;
} {
  const vcIssuer = new VCIssuer(`did:web:${credential.rpId}`);
  // If intendedThirdPartyPayment is provided, override the credential's bit
  // This represents the RP's intent at registration time, even if the authenticator lost the bit (issue #273)
  const credForVC = intendedThirdPartyPayment !== undefined
    ? { ...credential, thirdPartyPaymentBit: intendedThirdPartyPayment }
    : credential;
  const vc = vcIssuer.issueSPCCredential(credForVC, { subjectRole: 'originator' }, { authorizedOrigins });
  const vcStore = new VCStore();
  vcStore.store(credential.id, vc);
  const vcVerifier = new VCVerifier([`did:web:${credential.rpId}`]);
  return { vc, vcStore, vcVerifier, vcIssuer };
}

// ============================================================
// TEST GROUP 7: VC-Based Detection Strategy
// ============================================================
describe('VC-Based Detection Strategy', () => {
  it('detects credential availability for ALL authenticator types (including non-queryable)', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const authTypes = [
      { type: 'gpm' as const, platform: 'android' as const },
      { type: 'windows-hello' as const, platform: 'windows' as const },
      { type: 'icloud-keychain' as const, platform: 'macos' as const },
      { type: 'chrome-internal' as const, platform: 'macos' as const },
      { type: 'credman' as const, platform: 'android' as const },
      { type: 'third-party' as const, platform: 'macos' as const },
      { type: 'roaming-usb' as const, platform: 'windows' as const },
      { type: 'roaming-nfc' as const, platform: 'android' as const },
      { type: 'roaming-bluetooth' as const, platform: 'windows' as const },
      { type: 'hybrid' as const, platform: 'android' as const },
    ];

    for (const { type, platform } of authTypes) {
      const cred = rp.registerCredential('user1', type, platform, { thirdPartyPayment: true });
      const { vcStore } = setupVCPipeline(rp, cred, ['https://merchant.example']);

      const result = silentlyDetermineCredentialAvailability(
        cred.id, rp.getCredentials(), 'vc-based', new Map(), { vcStore },
      );
      expect(result).toBe(true);
    }
  });

  it('detects third-party payment authorization via VC (not CTAP bit)', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    // iCloud Keychain — non-queryable, no CTAP bit support
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: true });
    // The CTAP bit is lost on iCloud Keychain (issue #273), but the VC preserves it
    expect(cred.thirdPartyPaymentBit).toBe(false); // CTAP bit lost

    // VC carries the intended bit (true), not the lost one (false)
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example'], true);

    const result = silentlyDetermineThirdPartyEnabled(
      cred.id, rp.getCredentials(), 'vc-based', new Map(),
      { vcStore, vcVerifier, callingOrigin: 'https://merchant.example' },
    );
    // VC-based detection succeeds even though CTAP bit was lost!
    expect(result).toBe(true);
  });

  it('fails when VC does not exist for credential', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    // No VC stored — empty VC store
    const emptyStore = new VCStore();

    const result = silentlyDetermineCredentialAvailability(
      cred.id, rp.getCredentials(), 'vc-based', new Map(), { vcStore: emptyStore },
    );
    expect(result).toBe(false);
  });

  it('fails when VC is from untrusted issuer', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const { vcStore } = setupVCPipeline(rp, cred, ['https://merchant.example']);

    // Verifier that doesn't trust the issuer
    const untrustedVerifier = new VCVerifier(['did:web:different-bank.example']);

    const result = silentlyDetermineThirdPartyEnabled(
      cred.id, rp.getCredentials(), 'vc-based', new Map(),
      { vcStore, vcVerifier: untrustedVerifier, callingOrigin: 'https://merchant.example' },
    );
    expect(result).toBe(false);
  });

  it('fails when calling origin is not authorized', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example']);

    // Unauthorized origin
    const result = silentlyDetermineThirdPartyEnabled(
      cred.id, rp.getCredentials(), 'vc-based', new Map(),
      { vcStore, vcVerifier, callingOrigin: 'https://evil.example' },
    );
    expect(result).toBe(false);
  });

  it('succeeds when calling origin is in authorized list', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example', 'https://psp.example']);

    const result = silentlyDetermineThirdPartyEnabled(
      cred.id, rp.getCredentials(), 'vc-based', new Map(),
      { vcStore, vcVerifier, callingOrigin: 'https://psp.example' },
    );
    expect(result).toBe(true);
  });
});

// ============================================================
// TEST GROUP 8: VC-Enhanced SPC Flow (3p case unblocked)
// ============================================================
describe('VC-Enhanced SPC Flow', () => {
  it('3p case: non-queryable authenticator reaches Transaction UX with VC', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    // iCloud Keychain — non-queryable, no CTAP bit support
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: true });
    // VC carries the intended bit (true), not the lost one (false)
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example'], true);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.example',
      },
      'verify',
    );

    // With VC-based detection, the non-queryable authenticator reaches Transaction UX!
    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
    expect(result.definitelyAvailable).toContain(cred.id);
  });

  it('3p case: roaming authenticator (disconnected) reaches Transaction UX with VC', () => {
    const rp = new MockRPServer('eu-bank.example', 'EU Bank');
    const cred = rp.registerCredential('user-eu', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.latam.example']);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'LatAm Merchant', 'https://merchant.latam.example', '500.00', 'USD',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.latam.example',
      },
      'verify',
    );

    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
  });

  it('3p case: CredMan authenticator reaches Transaction UX with VC', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'credman', 'android', { thirdPartyPayment: true });
    // VC carries the intended bit (true), not the lost one (false)
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example'], true);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '50.00', 'EUR',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: false,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.example',
      },
      'verify',
    );

    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
  });

  it('1p case: all authenticator types work with VC', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const authTypes = [
      { type: 'icloud-keychain' as const, platform: 'macos' as const },
      { type: 'credman' as const, platform: 'android' as const },
      { type: 'roaming-nfc' as const, platform: 'android' as const },
      { type: 'hybrid' as const, platform: 'android' as const },
    ];

    for (const { type, platform } of authTypes) {
      const cred = rp.registerCredential('user1', type, platform, { thirdPartyPayment: false });
      const { vcStore } = setupVCPipeline(rp, cred);

      const challenge = rp.generateAuthenticationChallenge(
        [cred.id], 'Test Bank', 'https://bank.example', '100.00', 'EUR',
      );

      const result = simulateSPCFlow(
        challenge, rp.getCredentials(),
        {
          detectionStrategy: 'vc-based',
          isThirdParty: false,
          alwaysShowTransactionDialog: false,
          enableProposal1: false,
          enableBBK: false,
          browserProfileCache: new Map(),
          vcStore,
        },
        'verify',
      );

      expect(result.uxFlow).toBe('transaction-ux');
      expect(result.assertion).not.toBeNull();
    }
  });
});

// ============================================================
// TEST GROUP 9: BBS+ Selective Disclosure
// ============================================================
describe('BBS+ Selective Disclosure', () => {
  it('VC issuer creates valid VC with BBS+ proof', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const vc = vcIssuer.issueSPCCredential(cred, { subjectRole: 'originator' }, { authorizedOrigins: ['https://merchant.example'] });

    expect(vc.proof.type).toBe('BbsSignature2020');
    expect(vc.proof.proofValue).toBeDefined();
    expect(vc.credentialSubject.thirdPartyPayment).toBe(true);
    expect(vc.credentialSubject.rpId).toBe('bank.example');
  });

  it('VC verifier validates BBS+ signature', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const vc = vcIssuer.issueSPCCredential(cred, {}, { authorizedOrigins: ['https://merchant.example'] });
    const verifier = new VCVerifier([`did:web:${cred.rpId}`]);

    const result = verifier.verifyVC(vc);
    expect(result.valid).toBe(true);
    expect(result.claims).toBeDefined();
  });

  it('selective disclosure: merchant only sees thirdPartyPayment, not AML risk', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const vc = vcIssuer.issueSPCCredential(cred, {
      amlRiskCategory: 'medium',
      legalPersonIdentifier: 'did:web:user1.example',
    }, { authorizedOrigins: ['https://merchant.example'] });

    const verifier = new VCVerifier([`did:web:${cred.rpId}`]);
    // Merchant only needs to see: thirdPartyPayment, rpId, credentialId
    // NOT: amlRiskCategory, legalPersonIdentifier (privacy-preserving)
    const presentation = verifier.createPresentation(vc, ['thirdPartyPayment', 'rpId', 'credentialId']);

    const revealed = presentation.verifiableCredential.credentialSubject;
    expect(revealed.thirdPartyPayment).toBe(true);
    expect(revealed.rpId).toBe('bank.example');
    expect(revealed.credentialId).toBeDefined();
    // Sensitive claims NOT revealed
    expect(revealed.amlRiskCategory).toBeUndefined();
    expect(revealed.legalPersonIdentifier).toBeUndefined();
  });

  it('selective disclosure: regulator sees AML risk and identity, not SPC details', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const vc = vcIssuer.issueSPCCredential(cred, {
      amlRiskCategory: 'high',
      legalPersonIdentifier: 'did:web:user1.example',
    }, { authorizedOrigins: ['https://merchant.example'] });

    const verifier = new VCVerifier([`did:web:${cred.rpId}`]);
    // Regulator needs: legalPersonIdentifier, amlRiskCategory
    // NOT: thirdPartyPayment, authenticatorType (not relevant for compliance)
    const presentation = verifier.createPresentation(vc, ['legalPersonIdentifier', 'amlRiskCategory', 'subjectRole']);

    const revealed = presentation.verifiableCredential.credentialSubject;
    expect(revealed.legalPersonIdentifier).toBe('did:web:user1.example');
    expect(revealed.amlRiskCategory).toBe('high');
    expect(revealed.thirdPartyPayment).toBeUndefined();
    expect(revealed.authenticatorType).toBeUndefined();
  });

  it('VC verifier verifies presentation proof', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const vc = vcIssuer.issueSPCCredential(cred, {}, { authorizedOrigins: ['https://merchant.example'] });
    const verifier = new VCVerifier([`did:web:${cred.rpId}`]);

    const presentation = verifier.createPresentation(vc, ['thirdPartyPayment', 'rpId']);
    const result = verifier.verifyPresentation(presentation);
    expect(result.valid).toBe(true);
    expect(result.revealedClaims?.thirdPartyPayment).toBe(true);
  });
});

// ============================================================
// TEST GROUP 10: ISO 20022 Mapping
// ============================================================
describe('ISO 20022 Mapping', () => {
  it('maps SPC assertion + VC to SupplementaryData', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example']);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.example',
      },
      'verify',
    );

    expect(result.assertion).not.toBeNull();
    const vc = vcStore.retrieve(cred.id)!;
    const supData = mapToSupplementaryData(result.assertion!, challenge, vc);

    expect(supData.complianceEvidence.vcJwt).toBeDefined();
    expect(supData.spcAuthenticationEvidence).toBeDefined();
    expect(supData.spcAuthenticationEvidence!.credentialId).toBe(cred.id);
    expect(supData.spcAuthenticationEvidence!.thirdPartyPayment).toBe(true);
  });

  it('maps to pacs.008 with DLT asset metadata', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example']);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.example',
      },
      'verify',
    );

    const vc = vcStore.retrieve(cred.id)!;
    const supData = mapToSupplementaryData(result.assertion!, challenge, vc, {
      dltAsset: {
        assetType: 'Stablecoin',
        assetId: 'EUROC',
        issuer: 'Circle SAS',
        ledger: 'ethereum',
      },
    });

    const pacs008 = mapToPacs008(challenge, result.assertion!, vc, supData, {
      debtorName: 'Alice Consumer',
      creditorName: 'Merchant GmbH',
    });

    expect(pacs008.grpHdr.msgId).toBeDefined();
    expect(pacs008.cdtTrfTxInf.amt.instdAmt.ccy).toBe('EUR');
    expect(pacs008.cdtTrfTxInf.amt.instdAmt.value).toBe('100.00');
    expect(pacs008.cdtTrfTxInf.supplementaryData.dltAsset?.assetType).toBe('Stablecoin');
    expect(pacs008.cdtTrfTxInf.supplementaryData.complianceEvidence.vcJwt).toBeDefined();
  });

  it('validates pacs.008 required fields', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example']);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.example',
      },
      'verify',
    );

    const vc = vcStore.retrieve(cred.id)!;
    const supData = mapToSupplementaryData(result.assertion!, challenge, vc);
    const pacs008 = mapToPacs008(challenge, result.assertion!, vc, supData);

    const validation = validatePacs008(pacs008);
    expect(validation.valid).toBe(true);
    expect(validation.errors).toHaveLength(0);
  });

  it('maps assurance level to ISO 20022 AssrncLvl', () => {
    expect(mapAssuranceToISO20022('low')).toBe('LOW');
    expect(mapAssuranceToISO20022('substantial')).toBe('SUBST');
    expect(mapAssuranceToISO20022('high')).toBe('HIGH');
  });

  it('maps authenticator type to ISO 20022 AuthntcnMtd', () => {
    expect(mapAuthenticatorToISO20022('gpm')).toBe('PWDMGR');
    expect(mapAuthenticatorToISO20022('windows-hello')).toBe('BIOM');
    expect(mapAuthenticatorToISO20022('roaming-usb')).toBe('HKSTK');
    expect(mapAuthenticatorToISO20022('hybrid')).toBe('CDEV');
  });
});

// ============================================================
// TEST GROUP 11: VC + BBK Combined Flow
// ============================================================
describe('VC + BBK Combined Flow', () => {
  it('VC + BBK: roaming authenticator with device binding in 3p case', () => {
    const rp = new MockRPServer('eu-bank.example', 'EU Bank');
    const cred = rp.registerCredential('user-eu', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.latam.example']);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'LatAm Merchant', 'https://merchant.latam.example', '500.00', 'USD',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.latam.example',
      },
      'verify',
    );

    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
    expect(result.bbkCreated).toBe(true);
    expect(result.bbkUsed).toBe(true);
    expect(result.assertion?.bbkPublicKey).toBeDefined();
    expect(result.assertion?.bbkSignature).toBeDefined();
  });

  it('VC carries BBK public key in claims', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });

    // First auth creates BBK
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example']);
    const challenge1 = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    simulateSPCFlow(
      challenge1, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based', isThirdParty: true, alwaysShowTransactionDialog: false,
        enableProposal1: false, enableBBK: true, browserProfileCache: new Map(),
        vcStore, vcVerifier, callingOrigin: 'https://merchant.example',
      }, 'verify',
    );

    // Re-issue VC now that BBK exists
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const updatedVC = vcIssuer.issueSPCCredential(cred, {}, { authorizedOrigins: ['https://merchant.example'] });
    vcStore.store(cred.id, updatedVC);

    expect(updatedVC.credentialSubject.bbkPublicKey).toBeDefined();
    expect(updatedVC.credentialSubject.deviceBound).toBe(true);
    expect(updatedVC.credentialSubject.authenticatorAssuranceLevel).toBe('substantial');
  });

  it('VC + BBK: hardware-backed roaming key gets high assurance', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'roaming-usb', 'windows', { thirdPartyPayment: true });

    // Create BBK first
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.example']);
    const challenge1 = rp.generateAuthenticationChallenge(
      [cred.id], 'Merchant', 'https://merchant.example', '100.00', 'EUR',
    );
    simulateSPCFlow(
      challenge1, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based', isThirdParty: true, alwaysShowTransactionDialog: false,
        enableProposal1: false, enableBBK: true, browserProfileCache: new Map(),
        vcStore, vcVerifier, callingOrigin: 'https://merchant.example',
      }, 'verify',
    );

    // Re-issue VC with BBK
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const updatedVC = vcIssuer.issueSPCCredential(cred, {}, { authorizedOrigins: ['https://merchant.example'] });

    // Roaming (non-platform) + BBK = high assurance
    expect(updatedVC.credentialSubject.authenticatorAssuranceLevel).toBe('high');
  });
});

// ============================================================
// TEST GROUP 12: Cross-Border with VC
// ============================================================
describe('Cross-Border with VC', () => {
  it('EU user authenticates LatAm merchant via VC-based SPC with roaming key', () => {
    const rp = new MockRPServer('eu-bank.example', 'EU Bank');
    const cred = rp.registerCredential('user-eu', 'roaming-usb', 'windows', { thirdPartyPayment: true });
    const { vcStore, vcVerifier } = setupVCPipeline(rp, cred, ['https://merchant.latam.example']);

    const challenge = rp.generateAuthenticationChallenge(
      [cred.id], 'LatAm Merchant', 'https://merchant.latam.example', '500.00', 'USD',
    );

    const result = simulateSPCFlow(
      challenge, rp.getCredentials(),
      {
        detectionStrategy: 'vc-based',
        isThirdParty: true,
        alwaysShowTransactionDialog: false,
        enableProposal1: false,
        enableBBK: true,
        browserProfileCache: new Map(),
        vcStore,
        vcVerifier,
        callingOrigin: 'https://merchant.latam.example',
      },
      'verify',
    );

    expect(result.uxFlow).toBe('transaction-ux');
    expect(result.assertion).not.toBeNull();
    expect(result.bbkUsed).toBe(true);

    // Re-issue VC now that BBK was created (roaming + BBK = high assurance)
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const updatedVC = vcIssuer.issueSPCCredential(cred, {}, { authorizedOrigins: ['https://merchant.latam.example'] });

    // Map to ISO 20022 for cross-border payment message
    const supData = mapToSupplementaryData(result.assertion!, challenge, updatedVC, {
      dltAsset: {
        assetType: 'Stablecoin',
        assetId: 'USDC',
        issuer: 'Circle',
        ledger: 'stellar:testnet',
      },
    });
    const pacs008 = mapToPacs008(challenge, result.assertion!, updatedVC, supData);

    expect(pacs008.cdtTrfTxInf.supplementaryData.dltAsset?.assetId).toBe('USDC');
    expect(pacs008.cdtTrfTxInf.supplementaryData.spcAuthenticationEvidence?.assuranceLevel).toBe('high');
  });

  it('VC solves issue #273: third-party payment bit preserved via VC even on non-supporting authenticator', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    // Create on iCloud Keychain — bit is lost
    const cred = rp.registerCredential('user1', 'icloud-keychain', 'macos', { thirdPartyPayment: true });
    expect(cred.thirdPartyPaymentBit).toBe(false); // CTAP bit lost (issue #273)

    // But VC preserves the authorization
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    // VC issuer knows the RP requested thirdPartyPayment at registration time
    // Even though the authenticator couldn't store it, the VC carries it
    const vc = vcIssuer.issueSPCCredential(
      { ...cred, thirdPartyPaymentBit: true }, // VC carries the intended bit, not the lost one
      {}, { authorizedOrigins: ['https://merchant.example'] },
    );

    expect(vc.credentialSubject.thirdPartyPayment).toBe(true); // Preserved in VC!
  });
});

// ============================================================
// TEST GROUP 13: VC Revocation
// ============================================================
describe('VC Revocation', () => {
  it('VC includes W3C Status List 2021 revocation mechanism', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const vc = vcIssuer.issueSPCCredential(cred, {}, { authorizedOrigins: ['https://merchant.example'] });

    expect(vc.credentialStatus).toBeDefined();
    expect(vc.credentialStatus!.type).toBe('StatusList2021');
    expect(vc.credentialStatus!.statusPurpose).toBe('revocation');
  });

  it('VC verifier checks revocation status', () => {
    const rp = new MockRPServer('bank.example', 'Test Bank');
    const cred = rp.registerCredential('user1', 'gpm', 'android', { thirdPartyPayment: true });
    const vcIssuer = new VCIssuer(`did:web:${cred.rpId}`);
    const vc = vcIssuer.issueSPCCredential(cred, {}, { authorizedOrigins: ['https://merchant.example'] });
    const verifier = new VCVerifier([`did:web:${cred.rpId}`]);

    const status = verifier.checkRevocationStatus(vc);
    expect(status.revoked).toBe(false);
    expect(status.suspended).toBe(false);
  });
});
