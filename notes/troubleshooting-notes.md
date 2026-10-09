# Troubleshooting Notes — Lab 20: False Positive Analysis & Detection Tuning

## 1. Elastic Agent Status

**Command:**

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
```

**Observed result:**

- Fleet reported `HEALTHY` and `Connected`.
- Elastic Agent reported `HEALTHY` and `Running`.

**Assessment:** No agent health issue was indicated by this status output. Agent health alone does not guarantee that every required event field or dataset is being collected.

## 2. Different PowerShell Document Counts

**Observed results:**

- Baseline query: 341 documents.
- Another baseline query using `Last 15 minutes`: 261 documents.
- Indicator query: 100 results displayed.
- Comparison query: 341 documents processed, with 169 indicator matches and 172 baseline-only records.

**Explanation:** These results came from separate executions, and at least one query used a specific time range. New incoming events, time-range changes, and result limits can affect the displayed counts.

**Recommended approach:**

- Select a fixed time range before comparing queries.
- Use the same filters and index pattern for both runs.
- Avoid comparing a limited result set with an unrestricted baseline.
- Record the query execution time and the number of documents processed.
- Treat a change in document count as meaningful only after verifying that the query conditions are equivalent.

## 3. Indicator Matches Are Not Automatically Malicious

The indicator query searched for:

- `EncodedCommand`
- `ExecutionPolicy Bypass`
- `-WindowStyle Hidden`

These strings may be useful hunting indicators, but their presence does not independently prove malicious activity.

**Recommended approach:**

- Review the complete command line.
- Check the process parent and related process events if available.
- Identify the account and execution context.
- Correlate with nearby activity and the purpose of the script.
- Classify the event as confirmed, suspicious, benign with supporting evidence, or inconclusive.

Do not label all matching events as attacks simply because they match a string.

## 4. PowerShell Records Running as SYSTEM

Several visible records showed `SYSTEM` as the user.

**Potential explanation:** Windows services and management components can launch PowerShell under the SYSTEM account. That fact alone does not confirm that the activity is legitimate.

**Recommended approach:** Investigate the process command line, parent process, timing, and expected administrative activity before assigning a classification. Avoid excluding all SYSTEM PowerShell activity from detection.

## 5. Event ID 4624 Requires Context

The authentication query returned successful logon events with Event ID `4624`.

**Important distinction:** A successful logon is not automatically suspicious.

**Recommended approach:**

- Inspect the logon type.
- Review the account and logon context.
- Check source information when available.
- Correlate with relevant process or authentication events.
- Avoid inferring unauthorized access from the event ID alone.

## 6. Query Warnings

The displayed baseline and comparison queries reported a warning.

The supplied screenshots do not identify the exact warning message, so its cause cannot be determined from the available evidence.

**Recommended approach:**

- Open the query warning details in Elastic.
- Record the full warning text.
- Check whether the warning relates to field availability, data types, or query execution.
- Confirm whether the intended fields are populated.
- Retest after addressing any identified issue.

Do not claim that the warning was resolved without checking the actual message and retesting.

## 7. Empty or Placeholder Command-Line Values

Some PowerShell records displayed `-` for `process.command_line`.

**Assessment:** Those records do not provide a usable command line in the displayed field. They should not be assumed benign or malicious based on the placeholder.

**Recommended approach:** Review the raw event and available process fields. If the command line was not collected for a particular event, document that as a visibility limitation.

## 8. False Positive Tuning Risks

Broad exclusions can suppress useful security telemetry. Examples of risky tuning include excluding every event from `SYSTEM`, excluding all PowerShell processes, or ignoring all events from the lab endpoint.

**Recommended approach:**

1. Establish the legitimate behavior with evidence.
2. Identify the narrowest condition that distinguishes it.
3. Apply the proposed condition in a test query or detection.
4. Compare results over an identical time range.
5. Confirm that relevant controlled suspicious-looking activity still appears.
6. Document the rationale and any remaining limitations.

## 9. Current Troubleshooting Conclusion

Elastic Agent health and PowerShell telemetry were available during the investigation. However, the screenshots do not provide the full warning details or enough event context to confirm a false positive. The next step is to inspect the warning, validate individual matching records, and retest any evidence-based tuning under consistent query conditions.
