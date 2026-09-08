// SPC-specific Verifiable Credential types
// Extends Olvis's VC compliance profile (ISO/TC 307) with SPC claims

// Base claims from Olvis's compliance profile (Section 3.1)
export interface BaseComplianceClaims {
  legalPersonIdentifier?: string;    // Legal/natural person ID
  amlRiskCategory?: string;           // AML risk score category
  subjectRole: 'originator' | 'beneficiary' | 'intermediary';
  transactionPurposeCode?: string;    // ISO 20022 purpose code
  consentProof?: string;              // GDPR consent proof
}

// SPC-specific extension claims (new — additive to base profile)
export interface SPCExtensionClaims {
  thirdPartyPayment: boolean;           // Replaces CTAP thirdPartyPayment bit
  authenticatorAssuranceLevel: AssuranceLevel;  // Graduated assurance (not binary)
  deviceBound: boolean;                 // Whether BBK device binding is active
  bbkPublicKey?: string;               // BBK public key (base64url)
  authenticatorType: string;            // e.g., 'gpm', 'icloud-keychain', 'roaming-usb'
  rpId: string;                         // Relying Party ID
  credentialId: string;                 // WebAuthn credential ID
  authorizedOrigins?: string[];         // Origins authorized for 3p SPC (replaces CTAP bit scope)
}

// Assurance levels aligned with ISO 20022 AssrncLvl and eIDAS
export type AssuranceLevel =
  | 'low'           // Single-factor, no device binding
  | 'substantial'   // Two-factor with device binding (BBK)
  | 'high';         // Hardware-backed authenticator + BBK + user verification

// Combined VC claims for SPC
export interface SPCCredentialClaims extends BaseComplianceClaims, SPCExtensionClaims {}

// W3C Verifiable Credential structure (simplified)
export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  issuer: string;                        // DID of issuer (RP or trusted third party)
  issuanceDate: string;                  // ISO 8601
  expirationDate?: string;              // ISO 8601
  credentialSubject: SPCCredentialClaims;
  proof: BBSPlusProof;                  // BBS+ signature proof
  credentialStatus?: {                   // W3C Status List 2021
    type: 'StatusList2021';
    id: string;                          // URL to status list
    statusPurpose: 'revocation' | 'suspension';
    statusListIndex: number;
  };
}

// BBS+ proof structure (simplified simulation)
export interface BBSPlusProof {
  type: 'BbsSignature2020';
  created: string;
  verificationMethod: string;            // DID key reference
  proofPurpose: 'assertionMethod';
  proofValue: string;                    // Simulated BBS+ signature (base64url)
  revealedAttributes?: string[];         // Selective disclosure: which claims were revealed
}

// VC presentation with selective disclosure
export interface VCPresentation {
  '@context': string[];
  type: 'VerifiablePresentation';
  holder: string;                        // Browser/user agent DID
  verifiableCredential: {
    '@context'?: string[];
    type?: string[];
    issuer?: string;
    issuanceDate?: string;
    credentialSubject: Partial<SPCCredentialClaims>;  // Only revealed claims
  };
  proof: BBSPlusProof;
}

// ISO 20022 SupplementaryData mapping (per Olvis's harmonisation framework, Section 7.1)
export interface SupplementaryData {
  dltAsset?: {
    assetType: 'Stablecoin' | 'CBDC' | 'TokenisedDeposit' | 'Fiat';
    assetId: string;
    issuer?: string;
    ledger?: string;
  };
  complianceEvidence: {
    vcJwt: string;                       // VC encoded as JWT
  };
  settlementEvidence?: {
    blockHash?: string;
    confirmationCount?: number;
    finalityStatus?: 'Final' | 'Pending';
  };
  spcAuthenticationEvidence?: {
    credentialId: string;
    authenticatorType: string;
    assuranceLevel: AssuranceLevel;
    bbkPublicKey?: string;
    bbkSignature?: string;
    thirdPartyPayment: boolean;
  };
}

// ISO 20022 pacs.008 message (simplified)
export interface Pacs008Message {
  grpHdr: {
    msgId: string;
    creDtTm: string;
    nbOfTxs?: number;
  };
  cdtTrfTxInf: {
    pmtId: {
      endToEndId: string;
    };
    amt: {
      instdAmt: { ccy: string; value: string };
    };
    dbtr: {
      nm?: string;
      id?: { orgId?: { othr?: { id: string }[] } };
    };
    cdtr: {
      nm?: string;
      id?: { orgId?: { othr?: { id: string }[] } };
    };
    supplementaryData: SupplementaryData;
  };
}
