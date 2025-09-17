# 📐 System Architecture for Bill's POC Tracker

## 1. Requirements Recap
- Mobile app (native → **Ionic**)
- Multi-tenant (Bill will resell in Brazil)
- Search POCs by **name, language, tags**
- Generate **reports**
- Generate **yearly video** with all user POCs
- Secure login, user/tenant isolation
- **Realtime Dojos** (collaborative sessions)

## 2. Constraints
- ❌ No Lambda
- ❌ No Monolith
- ❌ No Single-AZ solutions
- ❌ No other clouds besides AWS
- ❌ Only **MongoDB** as NoSQL
- ❌ Only one relational DB
- ✅ Mobile: Ionic with single language (native)

## 3. High-Level Architecture

### Mobile
- Ionic mobile app (iOS/Android, single codebase)
- Auth → AWS Cognito SDK
- Real-time → WebRTC/IVS SDK
- REST + GraphQL → API Gateway

### Backend (EKS / ECS Fargate)
- **Tenant Service** → manages multi-tenant model
- **POC Service** → CRUD, search, tagging
- **Search Service** → indexing (MongoDB + Postgres queries)
- **Reporting Service** → PDF/CSV
- **Video Orchestration** → AWS MediaConvert
- **Dojo Service** → real-time collaboration (IVS / Kinesis Video)

### Databases
- **Aurora PostgreSQL (Multi-AZ)** → tenants, auth, transactions
- **MongoDB Atlas** → unstructured POC documents, tags, metadata

### Storage
- **S3** → POCs files, reports, yearly videos
- **CloudFront** → global delivery

### Security
- AWS Cognito (OIDC, MFA, JWT)
- AWS WAF (tenant-level isolation at API Gateway)

### Monitoring
- CloudWatch + X-Ray
- Prometheus + Grafana

### Diagram (conceptual)
```
[Ionic Mobile App]
       |
    [API Gateway + WAF + Cognito]
       |
     [EKS/ECS Microservices]
       |           |            \
 [Aurora RDS] [MongoDB Atlas]  [MediaConvert + S3]
```
