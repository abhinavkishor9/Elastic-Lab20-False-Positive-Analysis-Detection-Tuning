# Timeline

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

