# Legal and Ethical Usage

> Made by **Monish Paramasivam**

## Purpose

BTAudit is a **defensive, educational** tool designed to help authorized security
professionals and system administrators identify Bluetooth security misconfigurations
in environments they own or have explicit written permission to assess.

---

## Authorized Use

You may use BTAudit only if **all** of the following conditions are met:

1. **Ownership or authorization.** You own the Bluetooth infrastructure and devices
   being scanned, OR you have explicit written authorization from the owner.

2. **Defined scope.** The scan scope is clearly defined and agreed upon with the
   device/network owner before scanning begins.

3. **Defensive purpose.** Findings are used solely to improve the security posture
   of the authorized environment.

4. **No harm.** You will not use the tool to harass, stalk, track, or harm individuals
   or organizations.

---

## Prohibited Uses

The following uses are strictly prohibited:

- Scanning Bluetooth devices, networks, or environments without explicit written authorization
- Using scan results to exploit, attack, or compromise devices or systems
- Tracking individuals via their Bluetooth device signatures without their consent
- Using the tool in violation of any applicable law or regulation
- Modifying the tool to transmit malicious or crafted Bluetooth packets
- Using the tool to facilitate unauthorized access to any system or network

---

## Applicable Law

Unauthorized Bluetooth scanning may violate (non-exhaustive list):

| Jurisdiction | Law                                                          |
|--------------|--------------------------------------------------------------|
| United States | Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030      |
| United States | Electronic Communications Privacy Act (ECPA)                |
| United Kingdom | Computer Misuse Act 1990                                   |
| European Union | Directive 2013/40/EU on Attacks Against Information Systems |
| European Union | General Data Protection Regulation (GDPR) – Art. 5, 6      |
| Canada        | Criminal Code § 342.1 (Unauthorized use of computer)        |
| Australia     | Criminal Code Act 1995 – Part 10.7                          |

This list is illustrative, not exhaustive. Consult a qualified legal professional
in your jurisdiction before conducting any security assessment.

---

## Technical Safeguards

BTAudit enforces several hard technical safeguards:

| Safeguard | Description |
|-----------|-------------|
| Consent gate | Every scan requires explicit operator acknowledgement |
| Audit log | All consent records are saved with SHA-256 hash |
| Passive only | No outbound Bluetooth packets are transmitted |
| No connections | The tool never initiates Bluetooth connections or pairing |
| No exploitation | No known vulnerability exploitation is attempted |
| Transmission guard | `TransmissionGuard.assert_passive()` is called before every BT API call |

---

## Responsible Disclosure

If you discover a security finding during an authorized assessment, follow responsible
disclosure best practices:

1. Document the finding clearly with evidence (use BTAudit reports)
2. Report privately to the affected device/network owner
3. Agree on a remediation timeline before disclosure
4. Follow your organization's vulnerability management policy

---

## Disclaimer

BTAudit is provided "as is" without warranty of any kind. The author (Monish Paramasivam)
accepts no liability for misuse of this software. Users are solely responsible for
ensuring their use of BTAudit complies with all applicable laws and regulations.

By using this software, you agree to these terms.
