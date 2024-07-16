//! Logic for decoding and validating the Nitro Secure Module Attestation
//! Document.

use attestation_doc_validation::{
    parse_cert, validate_attestation_doc, validate_attestation_doc_against_cert,
};
use base64;
use ciborium::de::from_reader;
use coset::CborSerializable;
// use coset::CoseSign1;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;

use aws_nitro_enclaves_cose::{
    crypto::{Hash, MessageDigest, SignatureAlgorithm, SigningPublicKey},
    error::CoseError,
    CoseSign1,
};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use p384::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    PublicKey,
};
use serde_bytes::ByteBuf;

mod error;
mod syntactic_validation;
mod types;

pub use error::AttestError;

/// Signing algorithms we expect the certificates to use. Any other
/// algorithms will be considered invalid. NOTE: this list was deduced just
/// by trial and error and thus its unclear if it should include more types.
static AWS_NITRO_CERT_SIG_ALG: &[&webpki::SignatureAlgorithm] = &[&webpki::ECDSA_P384_SHA384];

/// AWS Nitro root CA certificate.
///
/// The root certificate can be downloaded from
/// <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>,
/// and it can be verified using the following SHA256 checksum:
/// `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`.
/// This official hash checksum is over the AWS-provided zip file.
/// For context and additional verification details, see
/// <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html/>.
///
/// The `aws_root_cert.pem` contents hash as follows via SHA256:
/// `6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0`.
pub const AWS_ROOT_CERT_PEM: &[u8] = std::include_bytes!("../root.pem");

/// Extract a DER encoded certificate from bytes representing a PEM encoded
/// certificate.
pub fn cert_from_pem(pem: &[u8]) -> Result<Vec<u8>, AttestError> {
    let (_, doc) = x509_cert::der::Document::from_pem(&String::from_utf8_lossy(pem))
        .map_err(|_| AttestError::PemDecodingError)?;
    Ok(doc.to_vec())
}

/// Verify that `attestation_doc` matches the specified parameters.
///
/// To learn more about the attestation document fields see:
/// <https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#22-attestation-document-specification/>.
///
/// # Arguments
///
/// * `attestation_doc` - the attestation document to verify.
/// * `user_data` - expected value of the `user_data` field.
/// * `pcr0` - expected value of PCR index 0.
/// * `pcr1` - expected value of PCR index 1.
/// * `pcr2` - expected value of PCR index 3.
///
/// # Panics
///
/// Panics if any part of verification fails.
pub fn verify_attestation_doc_against_user_input(
    attestation_doc: &AttestationDoc,
    user_data: &[u8],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    pcr3: &[u8],
) -> Result<(), AttestError> {
    if user_data
        != attestation_doc
            .user_data
            .as_ref()
            .ok_or(AttestError::MissingUserData)?
            .to_vec()
    {
        return Err(AttestError::DifferentUserData);
    }

    // nonce is none
    if attestation_doc.nonce.is_some() {
        return Err(AttestError::UnexpectedAttestationDocNonce);
    }

    if pcr0
        != attestation_doc
            .pcrs
            .get(&0)
            .ok_or(AttestError::MissingPcr0)?
            .clone()
            .into_vec()
    {
        return Err(AttestError::DifferentPcr0);
    }

    // pcr1 matches
    if pcr1
        != attestation_doc
            .pcrs
            .get(&1)
            .ok_or(AttestError::MissingPcr1)?
            .clone()
            .into_vec()
    {
        return Err(AttestError::DifferentPcr1);
    }

    // pcr2 matches
    if pcr2
        != attestation_doc
            .pcrs
            .get(&2)
            .ok_or(AttestError::MissingPcr2)?
            .clone()
            .into_vec()
    {
        return Err(AttestError::DifferentPcr2);
    }

    // pcr3 matches
    if pcr3
        != attestation_doc
            .pcrs
            .get(&3)
            .ok_or(AttestError::MissingPcr3)?
            .clone()
            .into_vec()
    {
        return Err(AttestError::DifferentPcr3);
    }

    Ok(())
}

/// Extract the DER encoded `AttestationDoc` from the nitro secure module
/// (nsm) provided COSE Sign1 structure.
///
/// WARNING: This will not perform any validation of the attestation doc and
/// should not be used directly in production; instead use
/// [`attestation_doc_from_der`].
///
/// # Arguments
///
/// * `cose_sign1_der` - the DER encoded COSE Sign1 structure containing the
///   attestation document payload.
pub fn unsafe_attestation_doc_from_der(
    cose_sign1_der: &[u8],
) -> Result<AttestationDoc, AttestError> {
    let cose_sign1 = CoseSign1::from_bytes(cose_sign1_der)
        .map_err(|_| AttestError::InvalidCOSESign1Structure)?;

    let raw_attestation_doc = cose_sign1
        .get_payload::<Sha2>(None)
        .map_err(|_| AttestError::InvalidCOSESign1Structure)?;

    AttestationDoc::from_binary(&raw_attestation_doc[..]).map_err(Into::into)
}

/// Extract the DER encoded `AttestationDoc` from the nitro secure module
/// (nsm) provided COSE Sign1 structure. This function will verify the the
/// root certificate authority via the CA bundle and verify that the end
/// entity certificate signed the COSE Sign1 structure.
///
/// While this does some basic verification, it is up to the user to verify
///
/// # Arguments
///
/// * `cose_sign1_der` - the DER encoded COSE Sign1 structure containing the
///   attestation document payload.
/// * `root_cert` - the DER encoded root certificate. This should be a hardcoded
///   root certificate from amazon and its authenticity should be validated out
///   of band.
/// * `validation_time` - a moment in time that the certificates should be
///   valid. This is measured in seconds since the unix epoch. Most likely this
///   will be the current time.
pub fn attestation_doc_from_der(
    cose_sign1_der: &[u8],
    root_cert: &[u8],
    validation_time: u64, // seconds since unix epoch
) -> Result<AttestationDoc, AttestError> {
    let attestation_doc = unsafe_attestation_doc_from_der(cose_sign1_der)?;
    let cose_sign1 = CoseSign1::from_bytes(cose_sign1_der)
        .map_err(|_| AttestError::InvalidCOSESign1Structure)?;

    syntactic_validation::module_id(&attestation_doc.module_id)?;
    syntactic_validation::digest(attestation_doc.digest)?;
    syntactic_validation::pcrs(&attestation_doc.pcrs)?;
    syntactic_validation::cabundle(&attestation_doc.cabundle)?;
    syntactic_validation::timestamp(attestation_doc.timestamp)?;
    syntactic_validation::public_key(&attestation_doc.public_key)?;
    syntactic_validation::user_data(&attestation_doc.user_data)?;
    syntactic_validation::nonce(&attestation_doc.nonce)?;

    verify_certificate_chain(
        &attestation_doc.cabundle,
        root_cert,
        &attestation_doc.certificate,
        validation_time,
    )?;
    verify_cose_sign1_sig(&attestation_doc.certificate, &cose_sign1)?;
    Ok(attestation_doc)
}

/// Verify the certificate chain against the root & end entity certificates.
fn verify_certificate_chain(
    cabundle: &[ByteBuf],
    root_cert: &[u8],
    end_entity_certificate: &[u8],
    validation_time: u64,
) -> Result<(), AttestError> {
    // Bundle starts with root certificate - we want to replace the root
    // with our hardcoded known certificate, so we remove the root
    // (first element). Ordering is: root cert .. intermediate certs ..
    // end entity cert.
    let intermediate_certs: Vec<_> = cabundle[1..].iter().map(|x| x.as_slice()).collect();

    let anchor = vec![webpki::TrustAnchor::try_from_cert_der(root_cert)?];
    let anchors = webpki::TlsServerTrustAnchors(&anchor);

    let cert = webpki::EndEntityCert::try_from(end_entity_certificate)?;
    cert.verify_is_valid_tls_server_cert(
        AWS_NITRO_CERT_SIG_ALG,
        &anchors,
        &intermediate_certs,
        webpki::Time::from_seconds_since_unix_epoch(validation_time),
    )
    .map_err(AttestError::InvalidCertChain)?;

    Ok(())
}

// Check that cose sign1 structure is signed with the key in the end
// entity certificate.
fn verify_cose_sign1_sig(
    end_entity_certificate: &[u8],
    cose_sign1: &CoseSign1,
) -> Result<(), AttestError> {
    use x509_cert::der::Decode;

    let ee_cert = x509_cert::certificate::Certificate::from_der(end_entity_certificate)
        .map_err(|_| AttestError::FailedToParseCert)?;

    // Expect v3
    if ee_cert.tbs_certificate.version != x509_cert::certificate::Version::V3 {
        return Err(AttestError::InvalidEndEntityCert);
    }

    let pub_key = ee_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key;
    let key =
        PublicKey::from_sec1_bytes(pub_key).map_err(|_| AttestError::FailedDecodeKeyFromCert)?;
    let key_wrapped = P384PubKey(key);

    // Verify the signature against the extracted public key
    let is_valid_sig = cose_sign1
        .verify_signature::<Sha2>(&key_wrapped)
        .map_err(|_| AttestError::InvalidCOSESign1Signature)?;
    if is_valid_sig {
        Ok(())
    } else {
        Err(AttestError::InvalidCOSESign1Signature)
    }
}

struct P384PubKey(p384::PublicKey);
impl SigningPublicKey for P384PubKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        let signature_wrapped =
            Signature::try_from(signature).map_err(|e| CoseError::SignatureError(Box::new(e)))?;

        let verifier = VerifyingKey::from(self.0);
        verifier
            .verify_prehash(digest, &signature_wrapped)
            .map(|_| true)
            .map_err(|e| CoseError::SignatureError(Box::new(e)))
    }
}

struct Sha2;
impl Hash for Sha2 {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        use sha2::Digest as _;
        match digest {
            MessageDigest::Sha256 => Ok(sha2::Sha256::digest(data).to_vec()),
            MessageDigest::Sha384 => Ok(sha2::Sha384::digest(data).to_vec()),
            MessageDigest::Sha512 => Ok(sha2::Sha512::digest(data).to_vec()),
        }
    }
}

fn main() {
    let doc = "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";

    // Decode the base64 string
    let decoded_bytes = base64::decode(doc).expect("Failed to decode base64 string");

    // Decode the COSE structure
    // let cose = aws_nitro_enclaves_cose::CoseSign1::from_bytes(decoded_bytes.as_slice())
    // .expect("Failed to decode COSE structure");

    // Extract the CBOR payload
    // let cbor_payload = cose.clone().payload.unwrap();

    // let cert_pem = read_pem_file("./src/root.pem");

    // let trusted_root_certificate = cert_from_pem(cert_pem.as_slice()).unwrap();
    let trusted_root_certificate = cert_from_pem(AWS_ROOT_CERT_PEM).unwrap();

    let val_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let att_doc = attestation_doc_from_der(
        decoded_bytes.as_slice(),
        trusted_root_certificate.as_slice(),
        val_time,
    );

    // let attestation_doc = unsafe_attestation_doc_from_der(cose_sign1_der)?;
    // let cose_sign1 = CoseSign1::from_bytes(cose_sign1_der)
    //     .map_err(|_| AttestError::InvalidCOSESign1Structure)?;

    // syntactic_validation::module_id(&attestation_doc.module_id)?;
    // syntactic_validation::digest(attestation_doc.digest)?;
    // syntactic_validation::pcrs(&attestation_doc.pcrs)?;
    // syntactic_validation::cabundle(&attestation_doc.cabundle)?;
    // syntactic_validation::timestamp(attestation_doc.timestamp)?;
    // syntactic_validation::public_key(&attestation_doc.public_key)?;
    // syntactic_validation::user_data(&attestation_doc.user_data)?;
    // syntactic_validation::nonce(&attestation_doc.nonce)?;

    // verify_certificate_chain(
    //     &attestation_doc.cabundle,
    //     root_cert,
    //     &attestation_doc.certificate,
    //     validation_time,
    // )?;
    // verify_cose_sign1_sig(&attestation_doc.certificate, &cose_sign1)?;

    print!("att doc: {:?}", att_doc);
}

fn read_pem_file(file_path: &str) -> Vec<u8> {
    let mut file = File::open(file_path).expect("Unable to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Unable to read data");
    buffer
}
