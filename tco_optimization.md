# ⚡ TCO Optimization Strategy

## Main Cost Drivers
- Compute: ~45%
- Dojo Real-Time: ~27%

## Optimization Moves

### 1. Compute (EKS/ECS)
- Savings Plans: -30–50%
- Spot for stateless: -70% on 40% of load
- Pod right-sizing: -10–15%

**Savings:** ~$1,900/month

---

### 2. Databases
- Aurora Serverless v2: -30–40%
- MongoDB auto-scaling: -20%

**Savings:** ~$400/month

---

### 3. Dojo Real-Time
- Replace IVS with **Kinesis Video/WebRTC** for small groups
- Keep IVS for large sessions

**Savings:** ~$1,400–1,700/month

---

### 4. Storage & Video Jobs
- Move yearly videos → S3 Glacier Deep Archive
- MediaConvert reserved pricing: -20%

**Savings:** ~$40/month

---

### 5. Networking & Security
- CloudFront savings bundles: -30%
- Optimize WAF rules

**Savings:** ~$160/month

---

### 6. Monitoring & Ops
- Reduce CloudWatch granularity
- Store metrics in Prometheus, forward aggregates only

**Savings:** ~$75/month

---

## 📉 Optimized Cost Projection

| Category              | Before | After | Savings |
|-----------------------|--------|-------|---------|
| Compute               | $4,900 | ~$3,000 | ~$1,900 |
| Databases             | $1,950 | ~$1,550 | ~$400 |
| Dojo Streaming        | $2,900 | ~$1,500 | ~$1,400 |
| Storage + Video       | $100   | ~$60   | ~$40 |
| Networking + Security | $580   | ~$420  | ~$160 |
| Monitoring + Ops      | $500   | ~$425  | ~$75 |
| **Total**             | $10,930 | **~$6,955** | **~$3,975 (~36%)** |

**Optimized TCO:** ~$7K/month (~$84K/year)  
vs baseline **$131K/year**
