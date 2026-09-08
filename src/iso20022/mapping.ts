import { SPCAssertionResult, SPCChallenge } from '../types.js';
import { VerifiableCredential, SupplementaryData, Pacs008Message, AssuranceLevel } from '../vc/types.js';
import * as crypto from 'crypto';

// ISO 20022 mapping module
// Maps SPC assertion + VC claims to ISO 20022 SupplementaryData per Olvis's harmonisation framework
// Reference: "Harmonising DLT Retail Payment Models" Section 7.1 (SupplementaryData schema)

export function mapToSupplementaryData(
  assertion: SPCAssertionResult,
  challenge: SPCChallenge,
  vc: VerifiableCredential,
  options: {
    dltAsset?: {
      assetType: 'Stablecoin' | 'CBDC' | 'TokenisedDeposit' | 'Fiat';
      assetId: string;
      issuer?: string;
      ledger?: string;
    };
    settlementEvidence?: {
      blockHash?: string;
      confirmationCount?: number;
      finalityStatus?: 'Final' | 'Pending';
    };
  } = {},
): SupplementaryData {
  const claims = vc.credentialSubject;

  // Encode VC as simulated JWT
  const vcJwt = simulateVCasJWT(vc);

  return {
    dltAsset: options.dltAsset,
    complianceEvidence: {
      vcJwt,
    },
    settlementEvidence: options.settlementEvidence,
    spcAuthenticationEvidence: {
      credentialId: assertion.credentialId,
      authenticatorType: claims.authenticatorType,
      assuranceLevel: claims.authenticatorAssuranceLevel,
      bbkPublicKey: assertion.bbkPublicKey,
      bbkSignature: assertion.bbkSignature,
      thirdPartyPayment: assertion.thirdPartyPaymentBit,
    },
  };
}

export function mapToPacs008(
  challenge: SPCChallenge,
  assertion: SPCAssertionResult,
  vc: VerifiableCredential,
  supplementaryData: SupplementaryData,
  options: {
    msgId?: string;
    endToEndId?: string;
    debtorName?: string;
    debtorId?: string;
    creditorName?: string;
    creditorId?: string;
  } = {},
): Pacs008Message {
  const now = new Date().toISOString();

  return {
    grpHdr: {
      msgId: options.msgId ?? `SPC${Date.now()}`,
      creDtTm: now,
      nbOfTxs: 1,
    },
    cdtTrfTxInf: {
      pmtId: {
        endToEndId: options.endToEndId ?? `E${Date.now()}`,
      },
      amt: {
        instdAmt: {
          ccy: challenge.totalCurrency,
          value: challenge.totalAmount,
        },
      },
      dbtr: {
        nm: options.debtorName,
        id: options.debtorId
          ? { orgId: { othr: [{ id: options.debtorId }] } }
          : undefined,
      },
      cdtr: {
        nm: options.creditorName ?? challenge.payeeName,
        id: options.creditorId
          ? { orgId: { othr: [{ id: options.creditorId }] } }
          : undefined,
      },
      supplementaryData,
    },
  };
}

// Simulate encoding a VC as a JWT (header.payload.signature)
function simulateVCasJWT(vc: VerifiableCredential): string {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: vc.issuer,
    iat: new Date(vc.issuanceDate).getTime() / 1000,
    exp: vc.expirationDate ? new Date(vc.expirationDate).getTime() / 1000 : undefined,
    vc: {
      '@context': vc['@context'],
      type: vc.type,
      credentialSubject: vc.credentialSubject,
    },
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', 'simulated-secret').update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

// Validate a pacs.008 message against required fields
export function validatePacs008(msg: Pacs008Message): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!msg.grpHdr.msgId) errors.push('Missing GrpHdr.MsgId');
  if (!msg.grpHdr.creDtTm) errors.push('Missing GrpHdr.CreDtTm');
  if (!msg.cdtTrfTxInf.pmtId.endToEndId) errors.push('Missing CdtTrfTxInf.PmtId.EndToEndId');
  if (!msg.cdtTrfTxInf.amt.instdAmt.ccy) errors.push('Missing CdtTrfTxInf.Amt.InstdAmt.Ccy');
  if (!msg.cdtTrfTxInf.amt.instdAmt.value) errors.push('Missing CdtTrfTxInf.Amt.InstdAmt.value');
  if (!msg.cdtTrfTxInf.supplementaryData.complianceEvidence.vcJwt) {
    errors.push('Missing SupplementaryData/ComplianceEvidence/VcJwt');
  }

  return { valid: errors.length === 0, errors };
}

// Map SPC assurance level to ISO 20022 AssrncLvl
export function mapAssuranceToISO20022(level: AssuranceLevel): string {
  switch (level) {
    case 'low': return 'LOW';
    case 'substantial': return 'SUBST';
    case 'high': return 'HIGH';
    default: return 'LOW';
  }
}

// Map SPC authenticator type to ISO 20022 AuthntcnMtd
export function mapAuthenticatorToISO20022(authenticatorType: string): string {
  const mapping: Record<string, string> = {
    'gpm': 'PWDMGR',
    'windows-hello': 'BIOM',
    'icloud-keychain': 'CLOUD',
    'chrome-internal': 'LOCAL',
    'credman': 'PWDMGR',
    'third-party': 'THIRD',
    'roaming-usb': 'HKSTK',
    'roaming-nfc': 'NFC',
    'roaming-bluetooth': 'BLTH',
    'hybrid': 'CDEV',
  };
  return mapping[authenticatorType] ?? 'UNKN';
}
