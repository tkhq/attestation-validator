# Attestation Validator

A simple utility to parse and verify a Turnkey enclave's attestation document against a root certificate associated with AWS Nitro Attestation PKI (located in `root.pem`). This certificate can be downloaded from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip.

Additional details on Turnkey's usage of secure enclaves can be found [here](https://docs.turnkey.com/security/secure-enclaves).

Resources on AWS Nitro Enclaves, attestations, and verifying attestations can be found at the following:

- https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html
- https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
- https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/
- https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

## Usage

Update `turnkey_attestation.txt` to include the response from a Turnkey API call. For example, you can request a Turnkey enclave's attestation document via a request like:

```
$ turnkey request --host api.turnkey.com --path /public/v1/query/get_attestation --body '{ "organizationId": "<your organization ID>", "enclaveType": "signer" }' --organization <your organization ID>

{
   "attestationDocument": "<base64-encoded attestation document -- copy and paste this into turnkey_attestation.txt>"
}
```

Note the above utilizes Turnkey's CLI. Installation instructions can be found [here](https://github.com/tkhq/tkcli)
