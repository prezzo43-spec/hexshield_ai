# HexShield AI Capstone Research and Evaluation Plan

## Refined Title

**A Multi-Layered Digital Forensics Framework for Automated Evidence Analysis and Threat Detection**

## Concise Abstract

Digital evidence may be disguised, corrupted, manipulated, or presented without a complete chain of custody. These challenges make it difficult for investigators to establish file integrity, identify suspicious binary characteristics, assess manipulated media, and produce consistent forensic reports. This project presents HexShield AI, a web-based digital forensics framework that integrates evidence ingestion, cryptographic hashing, binary triage, AI-assisted media analysis, chain-of-custody tracking, and forensic reporting. The first layer examines magic bytes, entropy, file headers, and MIME inconsistencies. The second layer assesses image, video, and audio manipulation indicators and can use an OpenAI-compatible reasoning provider to structure findings. The third layer preserves audit records and generates hash-verifiable JSON and PDF reports. A prototype evaluation uses labelled binary test cases and measures accuracy, precision, recall, F1-score, specificity, false-positive rate, processing time, reproducibility, and evidence preservation. The results demonstrate the feasibility of integrating these capabilities into one investigator workflow, while the study recognises that AI outputs are decision support rather than conclusive legal determinations. Future work should expand datasets, calibrate multimodal models, add immutable object storage, and conduct independent validation.

## Research Gap

Existing forensic tools commonly specialise in one activity, such as disk acquisition, file inspection, malware triage, or media authenticity analysis. This creates a workflow gap: evidence integrity, binary triage, media assessment, custody records, and report production may be handled in separate tools with limited shared traceability. Deepfake detectors also tend to report model scores without integrating those scores into an evidence-preservation and examiner-review workflow. HexShield AI addresses this gap by connecting these activities through a case, evidence, custody, analysis, certification, and reporting lifecycle. The contribution is therefore system integration and auditable workflow design, not a claim to invent a universally accurate deepfake model.

## Problem Statement

Digital evidence is increasingly exposed to file-type spoofing, obfuscation, manipulation, and synthetic-media generation. These threats make it difficult to determine whether an item is structurally consistent, technically suspicious, or suitable for further forensic examination. Existing workflows often lack a single environment that links the original evidence hash, binary findings, media-analysis results, chain-of-custody events, examiner review, and final report. The research problem is the absence of an integrated and auditable framework for automated evidence triage and threat detection. HexShield AI addresses this problem by combining cryptographic integrity checks, layered analysis, role-controlled review, and verifiable forensic reporting in one web-based system.

## Aim

To design, implement, and evaluate a secure multi-layered digital forensics framework for automated evidence analysis, threat detection, chain-of-custody management, and forensic reporting.

## SMART Objectives

1. To design a FastAPI, Next.js, and PostgreSQL architecture that supports authenticated case and evidence management.
2. To implement evidence ingestion that records metadata and SHA-256/SHA-512 integrity hashes for each accepted file.
3. To implement Layer 1 binary triage using magic-byte comparison, entropy analysis, file-header validation, and MIME-spoof detection.
4. To implement Layer 2 image, video, and audio analysis that returns documented indicators, confidence values, model information, and an inconclusive state when evidence is insufficient.
5. To implement role-controlled chain-of-custody, report certification, and case status transitions from `OPEN` through `UNDER_ANALYSIS`, `PENDING_REVIEW`, and `CLOSED`.
6. To evaluate Layer 1 using a labelled test set and report accuracy, precision, recall, F1-score, specificity, false-positive rate, false-negative rate, processing time, reproducibility, and evidence-preservation results.
7. To evaluate usability and workflow completeness through task-based testing covering authentication, case creation, evidence submission, analysis, report certification, report download, and case closure.
8. To document limitations and recommend improvements for model calibration, independent validation, secure object storage, and production deployment.

## Research Questions

1. How can evidence integrity, binary triage, media analysis, chain of custody, and reporting be integrated into one auditable workflow?
2. How effectively can magic-byte, entropy, MIME, and header indicators identify labelled suspicious binary files?
3. How consistently does the framework preserve evidence hashes and chain-of-custody records during analysis and report generation?
4. How usable is the integrated workflow for completing common investigator tasks?
5. What are the accuracy, reliability, ethical, legal, and operational limitations of AI-assisted media analysis in a forensic context?

## Evaluation Methodology

### Layer 1 Classification Evaluation

The repository includes `backend/tests/evaluation.py` and a labelled test set covering MIME spoofing, high entropy, mixed entropy, executable content, macro-capable documents, header anomalies, and benign files. A file is counted as detected when the engine returns `SUSPICIOUS` or `MALICIOUS`.

The evaluation report currently contains 10 test files with the following prototype results:

| Metric | Result |
|---|---:|
| Accuracy | 90.00% |
| Precision | 87.50% |
| Recall | 100.00% |
| F1-score | 93.33% |
| Specificity | 66.67% |
| False-positive rate | 33.33% |
| False-negative rate | 0.00% |
| Confusion matrix | TP=7, TN=2, FP=1, FN=0 |

These results are preliminary and must be reported as a small prototype benchmark, not as a universal accuracy claim. The false-positive rate is especially important: clean files may be flagged for further review, so the system should support examiner verification rather than automatic condemnation.

### Integrity and Reproducibility Tests

The evaluation should record:

- hash length and algorithm correctness
- unchanged evidence hash after analysis
- repeatability of entropy and risk results on repeated runs
- presence of acquisition and analysis custody events
- actor, role, timestamp, sequence, and hash fields
- report hash verification before download
- rejection of unauthenticated or unauthorized requests

### Performance Tests

Record at least five runs for representative file sizes and report:

- ingestion duration
- Layer 1 processing time
- external AI latency
- report-generation time
- average, minimum, maximum, and standard deviation
- behaviour when an external provider is unavailable

Do not report invented values. Capture measurements from the deployed or local test environment and identify the hardware, network, file size, and provider used.

### Usability Tests

Ask representative testers to complete these tasks:

1. Log in and reach the dashboard.
2. Create a case.
3. Submit evidence.
4. Locate the evidence hash.
5. Run analysis.
6. Generate a report.
7. Certify the report as an authorised investigator.
8. Download the report.
9. Move the case to review and close it.
10. Recover from an invalid route using the in-app 404 page.

Record task completion rate, task duration, observed errors, and a short usability questionnaire. State the number and profile of testers.

## AI Methodology and Validity

The primary media-analysis result should be treated as a technical signal, not ground truth. Hugging Face inference is used for the current primary media path. The optional Nebius or Groq OpenAI-compatible provider is used for structured reasoning over detector outputs, not for replacing file hashing or independently proving manipulation. The system falls back to the primary result if no reasoning provider is configured or if the provider is unavailable.

For a stronger future validation, use disjoint training and test data, document dataset provenance and licensing, include authentic and manipulated examples, test unseen manipulation methods, and report per-media-type precision, recall, F1-score, ROC-AUC where appropriate, and calibration. Audio claims should use a voice-spoofing dataset such as ASVspoof or another documented benchmark. Video claims should include temporal manipulations rather than only a few sampled frames. The report must identify the actual model name, version, dataset, preprocessing, thresholds, and hardware used.

## Design Justifications

### Entropy thresholds

The current elevated and critical thresholds are triage thresholds, not proof of maliciousness. Entropy varies by file format and compression. Thresholds should therefore be justified using the benign and suspicious validation distributions, documented by media/file type, and reviewed for false positives.

### Security enforcement

Sensitive report endpoints require authenticated investigator dependencies. Certification uses the authenticated investigator identity rather than trusting a user-supplied certifier ID. Role checks restrict certification and case-status changes. Production secrets remain in backend environment variables and are never exposed through public frontend variables.

### Evidence integrity

Database timestamps remain timezone-aware audit values. Reports display Kenya time (`Africa/Nairobi`) for examiner readability, while hashes and custody records preserve the underlying evidence relationship. Report downloads verify the stored report hash before serving the file.

## Legal and Standards Mapping

| Requirement or principle | HexShield AI implementation | Evidence for evaluation |
|---|---|---|
| Identification and preservation | Evidence metadata, storage path, SHA-256/SHA-512 hashes | Submission record and hash comparison |
| Documentation of handling | Custody events with actor, role, time, sequence, and hash | Custody query and generated report |
| Integrity verification | Hash recalculation for reports and evidence | Integrity test and tamper test |
| Controlled access | Secure cookies, authentication dependencies, RBAC | Unauthenticated and unauthorized request tests |
| Examination traceability | Layer results, engine/model version, analysis event | Analysis records and custody timeline |
| Reporting | Hash-linked JSON/PDF output with legal disclaimer | Generated report and download test |
| Kenya context | Jurisdiction and applicable-law fields | Case and report metadata |

This mapping demonstrates design alignment; it should not be described as formal legal certification or a substitute for expert testimony and institutional evidence-handling policy.

## Literature Review Structure

Organise the literature review around comparison and critique:

1. Digital forensic process models: acquisition, preservation, examination, analysis, and reporting.
2. Evidence integrity and chain-of-custody systems: strengths of hash-based verification and limitations of mutable storage.
3. File and binary triage: magic bytes, entropy, MIME validation, and false-positive trade-offs.
4. Image and video manipulation detection: spatial artefacts, temporal consistency, datasets, generalisation, and adversarial limitations.
5. Audio deepfake detection: spectral features, spoofing benchmarks, and cross-dataset generalisation.
6. AI-assisted forensic decision support: explainability, human review, bias, privacy, and evidentiary limits.
7. Gap synthesis: existing approaches often specialise in one layer; HexShield AI contributes an integrated, auditable workflow.

Use recent peer-reviewed deepfake and digital-forensics sources, official standards, and primary dataset/model papers. Verify every source and format the final list consistently in APA 7th edition. Do not cite a model or dataset unless it was actually used or clearly label it as proposed future work.

## Limitations and Ethics

- A small labelled test set cannot establish general-world detection accuracy.
- False positives may cause unnecessary investigation or reputational harm.
- Synthetic-media detectors may fail on unseen generators, compression, or adversarial manipulation.
- External AI providers introduce latency, availability, data-transfer, and confidentiality considerations.
- Evidence should not be sent to external providers without an approved policy and data-protection assessment.
- AI output must remain reviewable, explainable, and subordinate to qualified examiner judgement.
- Render local storage is not suitable as the final long-term evidence-retention strategy; immutable object storage and backup controls are required for production.

## Defense Answers in Brief

- **Problem:** The project unifies evidence integrity, binary triage, media analysis, custody, and reporting in one auditable workflow.
- **Research gap:** Existing tools commonly specialise in separate forensic activities and do not provide one shared evidence-to-report lifecycle.
- **Why this method:** A layered architecture separates deterministic integrity checks from probabilistic AI signals and preserves graceful fallback behaviour.
- **Validation:** Layer 1 has a labelled prototype evaluation; integrity, reproducibility, performance, usability, and security tests are separate evaluation dimensions.
- **AI limitation:** AI is decision support, not proof. The examiner reviews the evidence, model outputs, hashes, and custody trail.
- **Scalability:** The API/database design can scale horizontally, but production requires object storage, queues, model-serving infrastructure, monitoring, and retention controls.
- **404 handling:** The frontend now provides an in-app navigation page for invalid routes instead of leaving the user at a dead end.

## Selected APA-Style Reference Starting Points

Verify publication details and add recent peer-reviewed sources before submission:

- National Institute of Standards and Technology. (2006). *Guide to integrating forensic techniques into incident response* (Special Publication 800-86). U.S. Department of Commerce.
- National Institute of Standards and Technology. (2014). *Guide to integrating forensic techniques into incident response* [Use the exact edition and URL required by your department].
- International Organization for Standardization. (2012). *Guidelines for identification, collection, acquisition and preservation of digital evidence* (ISO/IEC 27037:2012).
- Korshunov, P., & Marcel, S. (2018). DeepFakes: A new threat to face recognition? Assessment and detection. *arXiv preprint arXiv:1812.08685*.
- Rossler, A., Cozzolino, D., Verdoliva, L., Riess, C., Thies, J., & Nießner, M. (2019). FaceForensics++: Learning to detect manipulated facial images. In *Proceedings of the IEEE/CVF International Conference on Computer Vision*.

Replace or supplement these starting points with sources you have actually read and used. Confirm APA capitalization, DOI/URL, edition, and access details against the original publisher or proceedings page.
