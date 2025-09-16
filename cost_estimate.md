# 💰 Cost Estimate & Sizing

## Assumptions
- 50 tenants
- ~10,000 total users (2,000 DAU)
- 100 concurrent Dojo sessions
- ~2M POC entries
- 10,000 yearly video jobs

## Monthly Cost Breakdown

| Category              | Cost (USD/month) |
|-----------------------|------------------|
| Compute (EKS/ECS)     | ~$4,900 |
| Databases             | ~$1,950 |
| Storage + Video Jobs  | ~$100 |
| Dojo Real-Time (IVS)  | ~$2,900 |
| Networking + Security | ~$580 |
| Monitoring + Ops      | ~$500 |
| **Total**             | **~$10,930/month** |

**Yearly:** ~$131K OPEX

## Scaling Guidance
- +5K users → +1 Aurora read replica (~$800) + 1 Mongo shard (~$1,000)
- +50 Dojo sessions → +$1,450/month
- +10K yearly videos → +$600 MediaConvert + +2TB S3 ($46)
