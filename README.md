# Automated Forensic Triage Tool (Windows)

An automated forensic triage tool designed to support rapid, early-stage digital investigations on Windows systems.

The tool focuses on **fast, repeatable collection and preliminary analysis of high-value forensic artefacts** to help investigators assess potential security incidents and prioritise systems for deeper examination. It is intentionally scoped to triage rather than full forensic reconstruction.

---

## Overview

Digital forensic investigations often begin with time-critical decisions:  

This project aims to streamline that initial decision-making phase by automating the collection and basic triage of commonly used Windows forensic artefacts.
The tool performs **read-only artefact collection**, applies **simple rule-based triage logic**, and produces **clear, structured reports** suitable for quick reviews.

---

## Key Features

- Automated collection of selected Windows forensic artefacts
- Read-only operation to preserve forensic integrity
- parses of artefacts into inisght
- Rule-based identification of potentially suspicious artifacts
- structured triage reports
- audit logging

---

## Artefacts in Scope

The current scope focuses on artefacts that provide high investigative value during early triage:

- **Windows Event Logs**  
  Security and System logs for authentication events, system activity, and errors

- **USB & Removable Media History**  
  Registry-based artefacts indicating device connections and timestamps

- **User Activity Artefacts**  
  Registry and system artefacts related to user sessions and activity

- **Browser History (limited scope)**  
  Supported browsers only (initially limited to a single, widely used browser)

Additional artefacts may be added if they can be supported without expanding scope beyond triage.

---

## Output

The tool generates:
- A structured triage report summarising:
  - Collected artefacts
  - Observed data
  - Flagged indicators
- An audit log detailing:
  - Tool actions
  - Timestamps
  - Successes and failures

Reports are designed for **rapid human interpretation**, not automated decision-making.

---

## Current Status

This project is under active development.  

---

## Disclaimer

This tool is intended to support forensic triage and decision-making.  
It should not be relied upon as the sole source of evidence or analysis in an investigation.

Always follow applicable legal, procedural, and professional standards when handling digital evidence.
