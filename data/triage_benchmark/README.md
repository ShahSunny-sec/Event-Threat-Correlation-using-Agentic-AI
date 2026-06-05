# Triage benchmark (optional labels)

Use this folder for **gold labels** when you evaluate the evidence triage system against human judgment.

Suggested `incident_labels.json` schema (list of objects):

- `incident_id` — must match enriched `Incident.incident_id` after you run the pipeline on a fixed seed/dataset
- `gold_decision` — `close` | `escalate` | `defer`
- `defer_appropriate` — boolean (for ambiguous cases)
- `notes` — analyst notes
- `required_evidence_id_patterns` — optional list of substring patterns that should appear in model citations

Start with **12** hand-labeled incidents (malicious / benign lookalike / ambiguous), then expand. The app logs every triage run to `experiments/logs/triage_runs.jsonl` for offline scoring.
