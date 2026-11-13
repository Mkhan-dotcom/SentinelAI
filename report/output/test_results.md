| Attack | Trials | Detected | Detection rate | Avg time to alert |
|---|---|---|---|---|
| Port Scan | 5 | 5 | 100.0% | 0.24 s |
| ICMP Flood | 5 | 5 | 100.0% | 0.18 s |
| Brute Force (SSH port) | 5 | 5 | 100.0% | 0.15 s |
| SYN Flood | 5 | 5 | 100.0% | 0.21 s |

| Normal activity | Trials | False alarms |
|---|---|---|
| Idle (5 s, no activity) | 5 | 0 |
| Normal ping (5 packets) | 5 | 0 |
| 3 SSH-port connections | 5 | 0 |
| Single port check | 5 | 0 |

**Overall:** 20/20 attacks detected (100.0%), 0/20 normal-activity trials raised a false alarm (0.0%).
