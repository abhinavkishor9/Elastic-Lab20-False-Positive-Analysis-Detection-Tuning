# Timeline — Lab 20: False Positive Analysis & Detection Tuning

**Investigation date:** October 9, 2026  
**Endpoint:** `DESKTOP-9MMM37V`  
**Platform:** Elastic Security

> Times below are the timestamps visible in the supplied screenshots. They describe query observations, not necessarily the original execution time of every activity.

| Time (local) | Activity | Evidence / Result | Assessment |
|---|---|---|---|
| Before 05:19 | Elastic Agent health check | Fleet reported Healthy and Connected; Elastic Agent reported Healthy and Running. | Agent health confirmed at check time. |
| 05:19:46 | Successful logon events reviewed | Event ID `4624` results included `SYSTEM` and `Dell`. | Successful logons observed; suspiciousness not established. |
| 05:19:57–05:19:58 | Additional successful logon events | More Event ID `4624` records appeared for the endpoint. | Requires contextual review if relevant to an alert. |
| 05:28:53 | Successful logon event | Event ID `4624`, user `SYSTEM`. | No standalone evidence of unauthorized access. |
| 05:29:17 | Successful logon event | Event ID `4624`, user `SYSTEM`. | No standalone evidence of unauthorized access. |
| 05:30:49–05:30:55 | PowerShell baseline query | A query with the `Last 15 minutes` range returned 261 documents. Some command-line values appeared as `-`. | PowerShell telemetry available; incomplete displayed command lines require care. |
| 05:35:17–05:35:23 | PowerShell baseline query | Records included `SYSTEM` PowerShell activity, with both populated and placeholder command-line values. | Account context alone is insufficient for classification. |
| 05:37:07–05:37:18 | Indicator query results | The visible records included PowerShell command lines with truncated `-NoProfile` / `-ExecutionPolicy` content. | Candidate events require full command-line review. |
| During the comparison | Baseline and indicator categories calculated | 341 documents processed; 169 indicator matches and 172 baseline-only records. | Query classifications observed; not confirmed malicious/benign counts. |
| During telemetry review | Dataset summary query | 993 documents processed; visible datasets included `windows.sysmon_operational`, `elastic_agent.metricbeat`, and `system.system`. | Telemetry availability reviewed. |

## Timeline Assessment

The investigation established that Elastic was receiving PowerShell process telemetry and successful logon events. The ES|QL comparison classified records based on three command-line patterns, but it did not establish that the matching records were malicious or that the baseline-only records were benign.

The baseline counts varied between query executions and time ranges, so they should not be interpreted as evidence that tuning reduced event volume. No confirmed false positive or validated exclusion was established from the supplied screenshots.

## Final Status

**Partially validated — telemetry and query-based indicator matching demonstrated; false-positive classification and tuning effectiveness not yet validated.**
