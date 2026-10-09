# Elastic-Lab20-False-Positive-Analysis-Detection-Tuning
## Overview
False positive analysis is the process of reviewing detection results that match suspicious conditions but may represent legitimate or expected activity. In a SOC, detections must produce useful security signals without overwhelming analysts with alerts caused by normal administrative or system activity.

Detection tuning improves the quality of a detection by adding relevant context and narrowing the conditions where appropriate. Instead of treating every matching event as malicious, the analyst examines the user, host, process, command line, event type, frequency, and surrounding activity before deciding whether the result is suspicious.

This lab focuses on reviewing Windows endpoint detection results in Elastic Security, distinguishing suspicious-looking activity from confirmed threats, and evaluating whether detection logic can be improved without losing meaningful security visibility.

The investigation uses PowerShell process telemetry, Windows successful logon events, and ES|QL queries to establish a baseline, identify command-line indicators, compare results, and document limitations. The analysis is performed on a single Windows endpoint monitored by Elastic Agent.

## Lab Objectives

- Understand the role of false positive analysis in SOC detection engineering.
- Establish a baseline of available PowerShell process telemetry in Elastic Security.
- Identify suspicious-looking PowerShell command-line indicators using ES|QL.
- Compare indicator matches against baseline PowerShell activity.
- Investigate repeated process events and assess their available context.
- Review Windows Event ID 4624 without assuming successful logons are suspicious.
- Distinguish confirmed observations, potential false positives, and inconclusive findings.
- Evaluate the impact of detection tuning on both alert noise and security visibility.
- Avoid broad exclusions based solely on usernames, process names, or event counts.
- Compare detection results using consistent time ranges and query conditions.
- Identify field gaps, query warnings, and telemetry limitations that affect analysis.
- Document tuning decisions, supporting evidence, and remaining validation requirements.
- Determine whether a detection is validated, partially validated, or requires further investigation.
  
## Lab Environment

| Component | Details |
|---|---|
| SIEM | Elastic Security / ES|QL |
| Endpoint | Windows 11 |
| Hostname | `DESKTOP-9MMM37V` |
| Endpoint telemetry | Elastic Agent and Sysmon |
| Process investigation | PowerShell process telemetry |
| Authentication investigation | Windows Security Event ID 4624 |
| Detection approach | Query-based analysis and baseline comparison |

## Lab Scenario

A Windows endpoint monitored by Elastic Security is generating PowerShell process telemetry and Windows authentication events. During routine detection review, an analyst identifies PowerShell command lines containing indicators such as `EncodedCommand`, `ExecutionPolicy Bypass`, and `-WindowStyle Hidden`. Although these options can appear in suspicious activity, they may also be used by legitimate scripts, administrative tools, or system processes.

The analyst must determine whether the available evidence supports further investigation or whether some results may represent expected activity. The goal is to evaluate the detection logic without assuming that every indicator match is malicious or that every unmatched event is benign.

### Investigation Tasks

- Review Elastic Agent health and verify the available endpoint telemetry.
- Establish a baseline of PowerShell process activity using ES|QL.
- Identify command lines matching the selected indicators and inspect the available process context.
- Compare indicator matches with baseline-only records using consistent query conditions.
- Review Windows Event ID `4624` as supporting authentication evidence without treating successful logons as inherently suspicious.
- Identify missing fields, query warnings, and limitations that prevent reliable event classification.
- Evaluate whether any proposed tuning is supported by evidence and whether it could suppress meaningful security activity.

### Expected Outcome

The investigation should produce an evidence-based assessment of the detection results, distinguish observed activity from confirmed findings, and identify whether further tuning or validation is required. Any exclusion must be justified by verified legitimate behavior and tested against relevant activity. If the available evidence is insufficient to confirm a false positive, the result should remain inconclusive rather than being classified as benign.


## Step 1 — Verify Elastic Agent Health

Run the following command in PowerShell:

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
```

**Observed result:** Elastic Agent and Fleet reported healthy status, with the agent running and connected.

## Step 2 — Review Available Telemetry

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY data_stream.dataset
| SORT event_count DESC
```

**Observed result:** The query processed 993 documents. The visible results included:

- `windows.sysmon_operational`: 810 documents
- `elastic_agent.metricbeat`: 68 documents
- `system.system`: 47 documents

These figures describe the query's result window. Dataset counts can change with the selected time range and incoming events.

## Step 3 — Establish the PowerShell Baseline

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
| SORT @timestamp DESC
```

**Observed result:** One query returned 341 documents. A separate query using the `Last 15 minutes` time range returned 261 documents.

The different counts reflect different query windows or data available at execution time. They should not be treated as a direct before-and-after tuning comparison.

Some results showed `SYSTEM` as the user, and some command-line values were empty or represented as `-`. These records require context before classification.

## Step 4 — Identify Command-Line Indicators

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| WHERE process.command_line LIKE "*EncodedCommand*"
    OR process.command_line LIKE "*ExecutionPolicy Bypass*"
    OR process.command_line LIKE "*-WindowStyle Hidden*"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

**Observed result:** The query returned 100 results, with 100 documents processed in the displayed query execution.

The results included PowerShell processes running under `SYSTEM`. This is not sufficient evidence to label the activity malicious or benign. The command line, initiating process, execution purpose, and surrounding activity must be considered where available.

## Step 5 — Compare Baseline and Indicator Matches

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| EVAL detection_match = CASE(
    process.command_line LIKE "*EncodedCommand*", "Indicator match",
    process.command_line LIKE "*ExecutionPolicy Bypass*", "Indicator match",
    process.command_line LIKE "*-WindowStyle Hidden*", "Indicator match",
    "Baseline only"
)
| STATS event_count = COUNT(*) BY detection_match
| SORT event_count DESC
```

**Observed result:**

| Classification | Count |
|---|---:|
| Baseline only | 172 |
| Indicator match | 169 |
| Total | 341 |

The displayed comparison classified 169 records as matching at least one selected indicator and 172 as baseline-only records.

These are query classifications, not confirmed false-positive or malicious-event counts. The comparison also uses an ordered `CASE` expression, which assigns each record to the first matching category.

## Step 6 — Review Authentication Context

```esql
FROM logs-*
| WHERE event.code == "4624"
| KEEP @timestamp, host.name, user.name, event.code, event.dataset, message
| SORT @timestamp DESC
| LIMIT 20
```

**Observed result:** The results included successful logon events from `system.security` for `DESKTOP-9MMM37V`. Both `SYSTEM` and `Dell` appeared in the displayed results.

Event ID `4624` confirms a successful logon event. It does not, by itself, establish that the logon was unauthorized or suspicious. The logon type, account context, source information, and related events should be reviewed when those fields are available.

## Analysis and Findings

- **Confirmed:** Elastic Agent and Fleet reported healthy status during the check.
- **Observed in Elastic:** PowerShell process telemetry was available, and the baseline query returned 341 documents in one execution.
- **Observed in Elastic:** The comparison query reported 169 indicator matches and 172 baseline-only events.
- **Observed in Elastic:** Successful logon events with Event ID `4624` were available.
- **Not established:** The indicator matches were not proven malicious.
- **Not established:** A confirmed false positive was not demonstrated by the supplied results.
- **Not established:** The analysis did not establish that a tuning exclusion reduced false positives without suppressing useful detections.

## Tuning Principles

1. Review the full command line and surrounding activity before classifying an event.
2. Treat suspicious-looking PowerShell options as investigation indicators, not proof of compromise.
3. Do not exclude all `SYSTEM` activity or all PowerShell activity without evidence.
4. Compare query results using the same time range and equivalent filters.
5. Test any proposed tuning against both known legitimate activity and controlled suspicious-looking activity.
6. Preserve visibility into meaningful security events.
7. Document unavailable fields and telemetry limitations instead of assuming the activity did not occur.

