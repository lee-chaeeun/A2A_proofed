# Why root an A2A identity key in hardware?

This prototype connects TPM attestation to an A2A requester. The weekend implementation uses a software TPM so the message flow, quote checks and task-delivery rules can be exercised without a physical device. The intended deployment is an enrolled identity key protected by a physical TPM.

## Three separate protections

| Mechanism | Question it addresses | Implemented here |
|---|---|---|
| TLS server authentication | Is the connection using an accepted server credential? | Yes, with a lab CA and enrolled names |
| TPM attestation | Can the peer produce fresh evidence under the enrolled attestation key, with an accepted measurement? | Yes, using swtpm and a synthetic PCR reference |
| Connection binding and guarded dispatch | Does that proof apply to the connection receiving the task? | Yes, for the bound identity policies |

The TLS private key is a separate software-managed lab credential. This prototype does **not** put the TLS certificate's private key inside a physical TPM. Its TPM-based credential is the extra attestation key. An A2A endpoint is not automatically hardware-backed simply because it returns a quote: enrollment and evidence appraisal must establish why the key is trusted.

## Expected benefits of a physical TPM

With an appropriately provisioned non-migratable key and a trusted enrollment process, a physical TPM can make the identity credential substantially harder to copy than an ordinary key file. This is the motivation for the design, rather than a result measured on physical hardware here. See [Microsoft's TPM fundamentals](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals) and the [TCG overview of device identification and attestation](https://trustedcomputinggroup.org/resource/overview-of-tcg-technologies-for-device-identification-and-attestation/).

| Attacker capability | Ordinary exportable key stored with the application | Expected physical-TPM protection | Important condition |
|---|---|---|---|
| Copies an application directory or container image | May obtain a usable private key | Copying application files need not copy signing capability | Key generated/protected by the TPM, without an exportable duplicate |
| Steals a disk image or backup | May obtain key material, depending on encryption and access controls | TPM-bound key objects should not become usable on another TPM merely by copying the disk | Correct key attributes and enrollment; physical extraction resistance is device-specific |
| Reads application memory | May recover a software private key loaded into that process | TPM private key material need not enter application memory | Does not prevent abuse of authorized TPM calls |
| Tries to use a key under an unapproved platform state | Software controls can be modified if their boundary is compromised | Measurement appraisal or TPM policy can support state-dependent authorization | Trusted measurement collection and reference policy; not just an arbitrary PCR value |
| Controls an authorized signer client on the original machine | May request signatures | Can still request permitted TPM operations | Caller authorization and workload isolation remain necessary |
| Relays a fresh proof from the original machine | May succeed with a valid remote signature | A TPM alone does not establish the delivery endpoint | Own-connection binding and proof-to-delivery continuity are still required |

“Software key” is not one threat model. An isolated signing service, HSM or other hardware-backed keystore changes the comparison. The strongest supported claim is against specified exportable-key/copy threats, not every possible software architecture.

The measured software-envelope comparison controls for the authentication protocol. It prevents us from attributing connection binding's effect to hardware. It does not imply that exportable keys and physical TPM keys have equal resistance to key theft.

## What the emulator demonstrates

The implementation produces and checks genuine TPM-format evidence through real TPM commands. It demonstrates protocol integration, freshness, policy handling and connection-bound task delivery. The clone fixtures also make a useful boundary visible: copying emulator state can reproduce its key capability.

The PCR reference is an operator-supplied configuration value. It is not a measurement chain proving which agent executable or model is running. Physical-device cloning resistance, measured boot and actual workload integrity are unmeasured. Moving to a physical TPM requires device provisioning/enrollment and trustworthy measurement/authorization policies, as well as adapting the transport to the device; it is not only replacing a socket path.

## Relationship to PTV

The [PTV draft-01](https://datatracker.ietf.org/doc/html/draft-anandakrishnan-rats-ptv-agent-identity-01) proposes exercise-time binding to an enrolled attestation key and an authorized configuration. It separates identity binding from behavioral continuity. It is an individual Experimental Internet-Draft, not an adopted A2A standard.

This repository implements a routine-response slice: a fresh TPM quote carried inside a checked COSE response. It adopts the evidence/appraisal idea and tests strict schema and session handling. It does not implement the draft's complete transform flow, establish ongoing behavior, or use the RISC Zero component as the draft's transform proof.

PTV motivates the hardware-rooted design; citing it does not turn the emulator measurements into physical-hardware evidence. The separate ZK component proves a small task computation, not the identity or platform state of the prover.

## TPM protection and post-quantum cryptography are different axes

TPM protection concerns where keys live and who can use them. Post-quantum cryptography concerns the mathematical algorithms' resistance to quantum attacks. A hardware-protected classical elliptic-curve key does not become post-quantum secure because it is inside a TPM. Conversely, a post-quantum private key stored in an ordinary file can still be copied. [NIST's PQC explanation](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography).

This implementation uses classical P-256 signatures. It does not implement or evaluate PQC, and neither the TPM nor ZK component should be advertised as establishing end-to-end post-quantum security.

## A defensible description

> An A2A prototype integrating TPM-based identity attestation, connection-bound task delivery and a separate RISC Zero task-result verification component. TPM integration is evaluated with swtpm; physical key-protection benefits are motivated by established TPM properties and remain outside the measured hardware scope.
