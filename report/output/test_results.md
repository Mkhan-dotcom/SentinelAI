| Attack | Trials | Detected | Detection rate | Avg time to alert |
|---|---|---|---|---|
| Port Scan | 5 | 5 | 100.0% | 0.1 s |
| Slow Port Scan | 5 | 5 | 100.0% | 8.06 s |
| ICMP Flood | 5 | 5 | 100.0% | 0.16 s |
| Brute Force (SSH port) | 5 | 5 | 100.0% | 0.1 s |
| SYN Flood | 5 | 5 | 100.0% | 0.16 s |

| Normal activity | Trials | False alarms |
|---|---|---|
| Idle (5 s, no activity) | 5 | 0 |
| Normal ping (5 packets) | 5 | 0 |
| 3 SSH-port connections | 5 | 0 |
| Single port check | 5 | 0 |
| Quick scan of 15 ports (below limit) | 5 | 0 |
| 8 SSH-port connections (below limit) | 5 | 0 |
| 40 pings in 4 s (below limit) | 5 | 0 |

**Overall:** 25/25 attacks detected (100.0%), 0/35 normal-activity trials raised a false alarm (0.0%).
