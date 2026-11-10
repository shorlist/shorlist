**sbom-tools 0.3.0** on the ShorList declaration axis (60 rows, rows sha256 `fd4daaf39186`, fingerprint `241b540d18474e32`)

Of 33 non-consistent pairs on the ShorList declaration axis, sbom-tools 0.3.0 reproduces 3 verdicts (0 partial); of 25 consistent pairs (20 of them decoys), it raises 12 false alarms. 2 SSH rows are not scored (no_spec_structure, CycloneDX #1162).

*By verdict class*

| verdict | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| consistent | 25 | 0 | 0 | 0 | 12 | 13 | 0 |
| overclaimed | 13 | 2 | 0 | 11 | 0 | 0 | 0 |
| parameter_mismatch | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| undeclared | 14 | 1 | 0 | 13 | 0 | 0 | 0 |

*By server*

| server | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| apache | 16 | 1 | 0 | 9 | 3 | 3 | 0 |
| nginx | 21 | 2 | 0 | 10 | 5 | 4 | 0 |
| s_server | 21 | 0 | 0 | 11 | 4 | 6 | 0 |

*By decoy class (consistent rows)*

| decoy | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| - | 5 | 0 | 0 | 0 | 0 | 5 | 0 |
| hybrid_spelling | 3 | 0 | 0 | 0 | 3 | 0 | 0 |
| identifier_spelling | 8 | 0 | 0 | 0 | 0 | 8 | 0 |
| inactive_scope | 3 | 0 | 0 | 0 | 3 | 0 | 0 |
| parent_child | 6 | 0 | 0 | 0 | 6 | 0 | 0 |

*By category*

| category | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| cipher_suite | 25 | 2 | 0 | 12 | 3 | 8 | 0 |
| group | 33 | 1 | 0 | 18 | 9 | 5 | 0 |

*By exposure label*

| exposure | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| hides_exposure | 8 | 1 | 0 | 7 | 0 | 0 | 0 |
| immaterial | 44 | 2 | 0 | 17 | 12 | 13 | 0 |
| overstates_protection | 2 | 0 | 0 | 2 | 0 | 0 | 0 |
| understates | 4 | 0 | 0 | 4 | 0 | 0 | 0 |

*Listener preference (hybrid and classical offered together)*

| listener | hybrid first | classical first | harvest path |
|---|---|---|---|
| L-APA-1 | X25519MLKEM768 | secp256r1 | yes |
| L-APA-2 | secp256r1 | secp256r1 | yes |
| L-APA-3 | no handshake | no handshake | no |
| L-NGX-1 | X25519MLKEM768 | X25519MLKEM768 | no |
| L-NGX-2 | X25519MLKEM768 | secp256r1 | yes |
| L-NGX-3 | no handshake | no handshake | no |
| L-NGX-4 | no handshake | no handshake | no |
| L-SSV-1 | no handshake | no handshake | no |
| L-SSV-2 | no handshake | no handshake | no |
| L-SSV-3 | secp256r1 | secp256r1 | yes |
| L-SSV-4 | X25519MLKEM768 | secp256r1 | yes |
| L-SSV-5 | TLSv1.2, no offered group | TLSv1.2, no offered group | yes |

