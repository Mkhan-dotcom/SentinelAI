| Attack | Trials | Detected | Detection rate | Avg time to alert |
|---|---|---|---|---|
| Port Scan | 1 | 1 | 100.0% | 0.15 s |
| Slow Port Scan | 1 | 1 | 100.0% | 8.09 s |
| FIN Scan (stealth) | 1 | 1 | 100.0% | 0.07 s |
| NULL Scan (stealth) | 1 | 1 | 100.0% | 0.08 s |
| Xmas Scan (stealth) | 1 | 1 | 100.0% | 0.06 s |
| ICMP Flood | 1 | 1 | 100.0% | 0.1 s |
| Brute Force (SSH port) | 1 | 1 | 100.0% | 0.11 s |
| SYN Flood | 1 | 1 | 100.0% | 0.17 s |

| Normal activity | Trials | False alarms |
|---|---|---|
| Idle (5 s, no activity) | 1 | 0 |
| Normal ping (5 packets) | 1 | 0 |
| 3 SSH-port connections | 1 | 0 |
| Single port check | 1 | 0 |
| Quick scan of 15 ports (below limit) | 1 | 0 |
| 8 SSH-port connections (below limit) | 1 | 0 |
| 40 pings in 4 s (below limit) | 1 | 0 |

**Overall:** 8/8 attacks detected (100.0%), 0/7 normal-activity trials raised a false alarm (0.0%).
