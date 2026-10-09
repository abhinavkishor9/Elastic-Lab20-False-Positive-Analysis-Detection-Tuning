# Investigation Notes — Lab 20: False Positive Analysis & Detection Tuning

## Investigation Overview

**Platform:** Elastic Security  
**Endpoint:** `DESKTOP-9MMM37V`  
**Operating System:** Windows 11  
**Primary telemetry:** PowerShell process events  
**Supporting telemetry:** Windows Security Event ID `4624`  
**Investigation date:** October 9, 2026

## 1. Investigation Objective

The objective was to examine PowerShell process telemetry, identify command lines matching selected suspicious-looking indicators, compare those results with the broader baseline, and determine whether the available evidence supported detection tuning.

The investigation also reviewed successful logon events to understand the authentication telemetry available on the endpoint.

## 2. Agent Health

The Elastic Agent status command reported:

- Fleet: Healthy and connected.
- Elastic Agent: Healthy and running.

This confirmed the reported agent status at the time of the check. It did not independently verify the completeness of every event type or integration.

## 3. Telemetry Baseline

The dataset summary query processed 993 documents. The visible results included 810 documents from `windows.sysmon_operational`, 68 from `elastic_agent.metricbeat`, and 47 from `system.system`.

The PowerShell process query returned 341 documents in one execution. Another execution with the `Last 15 minutes` time range returned 261 documents.

These counts were captured under different query executions and should not be used as a controlled tuning comparison. A valid comparison requires the same time range, filters, and query logic.

## 4. PowerShell Indicator Review

The investigation used these command-line patterns:

- `EncodedCommand`
- `ExecutionPolicy Bypass`
- `-WindowStyle Hidden`

The indicator query returned 100 displayed results. The visible records included PowerShell processes running under `SYSTEM`, with command lines partly truncated in the supplied results.

These strings can be associated with suspicious execution, but they can also appear in administrative scripts, automation, or other legitimate workflows. The username `SYSTEM` is not enough to determine whether an event is benign.

The supplied results did not include enough complete command-line and process-context evidence to classify the matching records conclusively.

## 5. Baseline Comparison

The ES|QL comparison query returned the following counts:

| Query category | Count |
|---|---:|
| Indicator match | 169 |
| Baseline only | 172 |
| Total | 341 |

The query used an ordered `CASE` expression to classify a record as an indicator match when its command line matched one of the selected patterns. Other records were classified as baseline-only.

The labels describe the query's matching logic. They do not represent a verified malicious-versus-benign classification. In particular, a baseline-only record could still require investigation for reasons not covered by these three indicators.

## 6. Authentication Event Review

The authentication query returned Event ID `4624` records from `system.security`. The visible results included the accounts `SYSTEM` and `Dell` on `DESKTOP-9MMM37V`.

Event ID `4624` records successful logons. To assess whether any event is suspicious, additional context may be needed, including logon type, account details, source network information, and related events.

The supplied output did not establish unauthorized access or a connection between the logon events and the PowerShell indicator matches.

## 7. Evidence Classification

### Confirmed

- Elastic Agent reported healthy and running status.
- PowerShell process telemetry was available in Elastic.
- The baseline query returned 341 documents in one execution.
- The comparison query classified 169 documents as indicator matches and 172 as baseline-only.
- Event ID `4624` records were present in the reviewed results.

### Not Established

- That the PowerShell indicator matches were malicious.
- That all baseline-only events were benign.
- That any specific record was a confirmed false positive.
- That the `SYSTEM` PowerShell events were necessarily legitimate.
- That the successful logons were suspicious or related to the PowerShell activity.
- That a tuning change reduced false positives without suppressing useful detections.

## 8. Tuning Assessment

No arbitrary account, host, or process exclusion should be introduced on the basis of these counts alone.

Before applying a tuning change:

1. Inspect complete matching command lines and relevant process context.
2. Determine whether the repeated pattern has a documented, legitimate purpose.
3. Identify a narrow condition supported by the evidence.
4. Compare the original and tuned queries over the same time range.
5. Verify that relevant controlled test activity remains detectable.
6. Record any change in results and its rationale.

## 9. Investigation Conclusion

The investigation successfully established a query-based PowerShell baseline and identified records matching selected command-line indicators. It also confirmed that successful logon events were available for supporting context. However, the current evidence does not establish a confirmed false positive or justify a specific exclusion. The detection should remain under investigation until individual events can be validated and any proposed tuning can be retested consistently.
