# 🧬 POC Tracker System - Architecture Document

## 1. 🎯 Problem Statement and Context

The problem is to create a comprehensive POC (Proof of Concept) tracking system for Mr. Bill and his customers in Brazil. The main challenge is building a scalable, multi-tenant platform that allows users to register, organize, search, and analyze their POCs while supporting real-time collaborative features like Dojos. The system needs to handle diverse POC metadata (languages, tags, descriptions), generate comprehensive reports, create annual video summaries, and maintain high security standards across multiple tenants. Additionally, the platform must support real-time collaboration features for conducting Dojos, making it both a repository and an interactive learning platform.

## 2. 🎯 Goals

1. **Multi-tenant Architecture**: Secure tenant isolation with shared infrastructure to optimize costs while maintaining data privacy and customization capabilities.
2. **High Performance Search**: Sub-second search capabilities across POCs by name, language, tags, and content with advanced filtering and sorting options.
3. **Real-time Collaboration**: Support live Dojos with real-time code sharing, chat, screen sharing, and collaborative editing features.
4. **Comprehensive Reporting**: Generate detailed analytics, usage reports, and trend analysis with exportable formats (PDF, Excel, JSON).
5. **Video Generation**: Automated annual video creation showcasing user POCs with customizable templates and branding options.
6. **Native Mobile Experience**: High-performance native mobile apps for iOS and Android with offline capabilities and seamless sync.
7. **Enterprise Security**: End-to-end encryption, OAuth 2.0/OIDC integration, role-based access control, and audit logging.
8. **High Availability**: 99.9% uptime with multi-AZ deployment, automated failover, and disaster recovery capabilities.
9. **Scalability**: Handle 10,000+ concurrent users and millions of POCs with horizontal scaling capabilities.
10. **Brazilian Market Focus**: Portuguese localization, Brazilian payment integration, and compliance with LGPD regulations.

## 3. 🎯 Non-Goals

1. **Perfect Offline Mode**: Basic offline viewing only, complex operations require connectivity to maintain data consistency.
2. **Legacy System Integration**: No support for migrating from legacy non-standard POC formats or proprietary systems.
3. **Unlimited Storage**: Storage quotas per tenant tier to manage costs and prevent abuse.
4. **Real-time Video Processing**: Video generation is asynchronous, not real-time to optimize resource usage.
5. **Custom Mobile Development**: Standard native apps only, no white-label or custom-branded mobile solutions.
6. **Multi-cloud Deployment**: AWS-only deployment to reduce complexity and operational overhead.
7. **Blockchain Integration**: No decentralized features or cryptocurrency payments.
8. **AI Code Generation**: POC creation assistance only, not full automated code generation.

## 📐 3. Principles

1. **Tenant Isolation**: Complete data and security isolation between tenants with shared infrastructure for cost efficiency.
2. **API-First Design**: All functionality accessible via well-documented RESTful APIs with comprehensive SDK support.
3. **Event-Driven Architecture**: Asynchronous processing for heavy operations like video generation and report creation.
4. **Microservices with Domain Boundaries**: Clear service boundaries aligned with business domains (User Management, POC Management, Search, Reporting).
5. **Observability by Design**: Comprehensive logging, metrics, and tracing across all services with automated alerting.
6. **Security by Default**: Zero-trust architecture with encryption everywhere and principle of least privilege.
7. **Mobile-First UX**: Responsive design prioritizing mobile experience while maintaining desktop functionality.
8. **Fail-Fast Validation**: Early input validation and clear error messages to improve user experience.
9. **Eventual Consistency**: Accept eventual consistency for better performance while ensuring strong consistency where critical.
10. **Cost Optimization**: Efficient resource utilization with auto-scaling and appropriate service sizing.

## 🏗️ 4. Overall Diagrams

### 🗂️ 4.1 Overall Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   iOS Native    │    │ Android Native  │
│      App        │    │      App        │
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          └──────────┬───────────┘
                     │
          ┌─────────────────┐
          │   API Gateway   │
          │  (AWS API GW)   │
          └─────────┬───────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
┌───▼────┐  ┌──────▼──────┐  ┌────▼─────┐
│User    │  │POC          │  │Search    │
│Service │  │Service      │  │Service   │
│        │  │             │  │(OpenSearch)
└───┬────┘  └──────┬──────┘  └────┬─────┘
    │              │               │
┌───▼────┐  ┌──────▼──────┐  ┌────▼─────┐
│Report  │  │Video        │  │Dojo      │
│Service │  │Service      │  │Service   │
└───┬────┘  └──────┬──────┘  └────┬─────┘
    │              │               │
    └──────────────┼───────────────┘
                   │
        ┌─────────▼──────────┐
        │   Event Bus        │
        │   (Amazon SQS)     │
        └─────────┬──────────┘
                  │
    ┌────────────────────────┐
    │   Data Layer           │
    │ ┌────────┐ ┌─────────┐ │
    │ │RDS     │ │S3       │ │
    │ │Multi-AZ│ │Storage  │ │
    │ └────────┘ └─────────┘ │
    └────────────────────────┘
```

### 🗂️ 4.2 Deployment Architecture

```
┌─────────────────────────────────────────────────────┐
│                     AWS Cloud                       │
│  ┌─────────────┐              ┌─────────────┐      │
│  │   us-east-1 │              │  us-east-2  │      │
│  │     (AZ-A)  │              │    (AZ-B)   │      │
│  │ ┌─────────┐ │              │ ┌─────────┐ │      │
│  │ │ ECS     │ │              │ │ ECS     │ │      │
│  │ │ Cluster │ │◄────────────►│ │ Cluster │ │      │
│  │ └─────────┘ │              │ └─────────┘ │      │
│  │ ┌─────────┐ │              │ ┌─────────┐ │      │
│  │ │ RDS     │ │              │ │ RDS     │ │      │
│  │ │ Primary │ │◄────────────►│ │ Replica │ │      │
│  │ └─────────┘ │              │ └─────────┘ │      │
│  └─────────────┘              └─────────────┘      │
│                                                     │
│  ┌─────────────────────────────────────────────────┐│
│  │              CloudFront CDN                     ││
│  └─────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────┐│
│  │                   WAF                           ││
│  └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘
```

### 🗂️ 4.3 Use Cases

```
┌─────────────────────────────────────────────────────┐
│                 POC Tracker System                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Registration & Authentication                      │
│  • User Registration/Login                          │
│  • Multi-tenant Setup                               │
│  • OAuth Integration                                │
│                                                     │
│  POC Management                                     │
│  • Create/Edit/Delete POCs                          │
│  • Upload Code Files                                │
│  • Tag Management                                   │
│  • Version Control                                  │
│                                                     │
│  Search & Discovery                                 │
│  • Search by Name/Language/Tags                     │
│  • Advanced Filtering                               │
│  • Favorites and Collections                        │
│                                                     │
│  Reporting & Analytics                              │
│  • Usage Reports                                    │
│  • Trend Analysis                                   │
│  • Export Capabilities                              │
│                                                     │
│  Video Generation                                   │
│  • Annual POC Videos                                │
│  • Custom Templates                                 │
│  • Sharing and Distribution                         │
│                                                     │
│  Real-time Collaboration                            │
│  • Live Dojos                                       │
│  • Screen Sharing                                   │
│  • Real-time Chat                                   │
│  • Collaborative Editing                            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 🧭 5. Trade-offs

### Major Decisions:
1. Native Mobile Apps vs Cross-platform
2. Microservices vs Modular Monolith
3. Multi-tenant Single DB vs Separate DBs per Tenant
4. Real-time Features Implementation
5. Video Generation Approach

### Trade-offs Analysis:

#### 1. Native Mobile Apps (iOS Swift + Android Kotlin) vs React Native/Flutter

**PROS (+)**
* **Performance**: Native apps provide optimal performance, especially for complex UI interactions and real-time features
* **Platform Features**: Full access to platform-specific APIs and latest OS features
* **User Experience**: Platform-native UI/UX patterns provide familiar user experience
* **Offline Capabilities**: Better offline data synchronization and caching mechanisms

**CONS (-)**
* **Development Cost**: Requires separate codebases and specialized developers for each platform
* **Maintenance Overhead**: Updates and bug fixes need to be implemented twice
* **Time to Market**: Longer development cycles due to parallel development streams
* **Resource Requirements**: Need iOS and Android expertise in the development team

#### 2. Microservices vs Modular Monolith

**PROS (+)**
* **Scalability**: Independent scaling of services based on demand patterns
* **Technology Diversity**: Different services can use optimal tech stacks
* **Team Independence**: Teams can develop and deploy services independently
* **Fault Isolation**: Service failures don't bring down the entire system

**CONS (-)**
* **Complexity**: Distributed system complexity with network calls and service coordination
* **Operational Overhead**: More services to monitor, deploy, and maintain
* **Data Consistency**: Eventual consistency challenges across service boundaries
* **Testing Complexity**: Integration testing becomes more complex

#### 3. OpenSearch vs Traditional Database Search

**PROS (+)**
* **Search Performance**: Optimized for full-text search and complex queries
* **Scalability**: Horizontal scaling for large datasets
* **Analytics**: Built-in analytics and aggregation capabilities
* **Flexibility**: Support for various data types and search patterns

**CONS (-)**
* **Consistency**: Eventual consistency model may cause search delays
* **Complexity**: Additional infrastructure component to manage
* **Cost**: Higher resource requirements compared to basic database search
* **Learning Curve**: Team needs to learn OpenSearch query DSL and optimization

#### 4. WebSocket vs Server-Sent Events for Real-time Features

**PROS (+)**
* **Bidirectional Communication**: Full-duplex communication for interactive features
* **Low Latency**: Minimal overhead for real-time updates
* **Protocol Flexibility**: Can handle various message types efficiently
* **Mobile Support**: Good mobile client library support

**CONS (-)**
* **Connection Management**: Complex connection state management and reconnection logic
* **Scaling Challenges**: Sticky sessions and connection pooling complexity
* **Resource Usage**: Persistent connections consume server resources
* **Firewall Issues**: Some corporate networks may block WebSocket connections

#### 5. Asynchronous Video Generation vs Real-time Processing

**PROS (+)**
* **Resource Optimization**: Background processing doesn't impact user-facing operations
* **Cost Efficiency**: Can use spot instances or batch processing for cost savings
* **Reliability**: Retry mechanisms and error handling for complex video operations
* **User Experience**: Non-blocking operations with progress notifications

**CONS (-)**
* **User Wait Time**: Users must wait for video generation completion
* **Complexity**: Queue management and job processing infrastructure required
* **Storage Requirements**: Temporary storage for video processing artifacts
* **Error Handling**: Complex error scenarios and user notification systems

## 🌏 6. Major Components

### 6.1 User Service

#### Class Diagram
```
┌─────────────────────────────────┐
│           UserService           │
├─────────────────────────────────┤
│ - userRepository: UserRepository│
│ - tenantService: TenantService  │
│ - authProvider: AuthProvider    │
├─────────────────────────────────┤
│ + registerUser(userData): User  │
│ + authenticateUser(creds): Token│
│ + updateProfile(userId, data)   │
│ + getTenantUsers(tenantId): User[]│
│ + assignRole(userId, role)      │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│              User               │
├─────────────────────────────────┤
│ - id: UUID                      │
│ - email: String                 │
│ - name: String                  │
│ - tenantId: UUID                │
│ - roles: Set<Role>              │
│ - createdAt: DateTime           │
│ - lastLoginAt: DateTime         │
├─────────────────────────────────┤
│ + hasRole(role): Boolean        │
│ + belongsToTenant(tenantId): Boolean│
│ + updateLastLogin()             │
└─────────────────────────────────┘
```

#### Contract Documentation
```yaml
POST /api/v1/users/register
Input:
  email: string (required)
  password: string (required, min 8 chars)
  name: string (required)
  tenantId: UUID (required)
Output:
  userId: UUID
  accessToken: string
  refreshToken: string
  expiresIn: number

GET /api/v1/users/profile
Headers:
  Authorization: Bearer {token}
Output:
  user: User object
  tenant: Tenant object
  permissions: string[]
```

#### Persistence Model
```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    roles JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
```

#### Algorithms/Data Structures
- **Password Hashing**: bcrypt with salt rounds = 12
- **JWT Token Management**: RS256 algorithm with 15-minute access token expiry
- **Rate Limiting**: Token bucket algorithm (100 requests/minute per user)

### 6.2 POC Service

#### Class Diagram
```
┌─────────────────────────────────┐
│           POCService            │
├─────────────────────────────────┤
│ - pocRepository: POCRepository  │
│ - searchService: SearchService  │
│ - fileService: FileService     │
│ - eventPublisher: EventPublisher│
├─────────────────────────────────┤
│ + createPOC(pocData): POC       │
│ + updatePOC(id, data): POC      │
│ + searchPOCs(criteria): POC[]   │
│ + deletePOC(id): void           │
│ + addTag(pocId, tag): void      │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│               POC               │
├─────────────────────────────────┤
│ - id: UUID                      │
│ - name: String                  │
│ - description: String           │
│ - language: String              │
│ - tags: Set<String>             │
│ - files: List<File>             │
│ - tenantId: UUID                │
│ - userId: UUID                  │
│ - createdAt: DateTime           │
│ - updatedAt: DateTime           │
├─────────────────────────────────┤
│ + addFile(file): void           │
│ + removeFile(fileId): void      │
│ + updateTags(tags): void        │
└─────────────────────────────────┘
```

#### Contract Documentation
```yaml
POST /api/v1/pocs
Input:
  name: string (required, max 100 chars)
  description: string (optional, max 2000 chars)
  language: string (required)
  tags: string[] (optional, max 10 tags)
  files: multipart/form-data (optional)
Output:
  pocId: UUID
  status: string
  createdAt: DateTime

GET /api/v1/pocs/search
Query Parameters:
  q: string (search query)
  language: string (filter by language)
  tags: string[] (filter by tags)
  page: number (default 1)
  limit: number (default 20, max 100)
Output:
  pocs: POC[]
  totalCount: number
  hasMore: boolean
```

#### Persistence Model
```sql
-- POCs table
CREATE TABLE pocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    language VARCHAR(50) NOT NULL,
    tags JSONB DEFAULT '[]',
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    search_vector tsvector GENERATED ALWAYS AS (
        to_tsvector('english', 
                   coalesce(name, '') || ' ' || 
                   coalesce(description, '') || ' ' || 
                   coalesce(language, ''))
    ) STORED
);

CREATE INDEX idx_pocs_search ON pocs USING GIN (search_vector);
CREATE INDEX idx_pocs_tenant_id ON pocs(tenant_id);
CREATE INDEX idx_pocs_language ON pocs(language);
CREATE INDEX idx_pocs_tags ON pocs USING GIN (tags);
```

#### Algorithms/Data Structures
- **Search Ranking**: TF-IDF scoring with boost for exact matches in name/tags
- **Tag Suggestion**: Trie data structure for autocomplete with fuzzy matching
- **File Indexing**: Merkle tree for file change detection and efficient sync

### 6.3 Search Service

#### Class Diagram
```
┌─────────────────────────────────┐
│          SearchService          │
├─────────────────────────────────┤
│ - openSearchClient: Client      │
│ - indexManager: IndexManager    │
│ - queryBuilder: QueryBuilder    │
├─────────────────────────────────┤
│ + indexPOC(poc): void           │
│ + searchPOCs(query): SearchResult│
│ + suggestTags(prefix): string[] │
│ + getPopularTags(tenantId): Tag[]│
│ + updatePOCIndex(pocId): void    │
└─────────────────────────────────┘
```

#### Contract Documentation
```yaml
GET /api/v1/search/pocs
Query Parameters:
  q: string (search query)
  filters: object {
    language: string[],
    tags: string[],
    dateRange: { from: Date, to: Date },
    userId: UUID
  }
  sort: string (relevance|date|name)
  page: number
  size: number
Output:
  hits: POCSearchResult[]
  totalHits: number
  aggregations: object
  searchTime: number
```

#### Persistence Model
```json
// OpenSearch Index Mapping
{
  "mappings": {
    "properties": {
      "pocId": { "type": "keyword" },
      "tenantId": { "type": "keyword" },
      "name": { 
        "type": "text",
        "analyzer": "standard",
        "fields": {
          "keyword": { "type": "keyword" }
        }
      },
      "description": { "type": "text" },
      "language": { "type": "keyword" },
      "tags": { "type": "keyword" },
      "content": { "type": "text" },
      "createdAt": { "type": "date" },
      "userId": { "type": "keyword" }
    }
  }
}
```

#### Algorithms/Data Structures
- **Query Processing**: Query parser with boolean logic and phrase matching
- **Relevance Scoring**: BM25 algorithm with custom field boosting
- **Faceted Search**: Aggregation buckets for filters with count statistics

### 6.4 Real-time Dojo Service

#### Class Diagram
```
┌─────────────────────────────────┐
│           DojoService           │
├─────────────────────────────────┤
│ - sessionManager: SessionManager│
│ - webSocketHandler: WSHandler   │
│ - collaborationEngine: Engine   │
├─────────────────────────────────┤
│ + createSession(userId): Session│
│ + joinSession(sessionId): void  │
│ + broadcastMessage(msg): void   │
│ + shareScreen(sessionId): void  │
│ + endSession(sessionId): void   │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│            DojoSession          │
├─────────────────────────────────┤
│ - id: UUID                      │
│ - hostId: UUID                  │
│ - participants: Set<UUID>       │
│ - pocId: UUID                   │
│ - isActive: Boolean             │
│ - createdAt: DateTime           │
├─────────────────────────────────┤
│ + addParticipant(userId): void  │
│ + removeParticipant(userId): void│
│ + broadcastToAll(message): void │
└─────────────────────────────────┘
```

#### Contract Documentation
```yaml
WebSocket /api/v1/dojo/session/{sessionId}
Authentication: JWT token in query parameter

Message Types:
  - join_session: { type: 'join', userId: UUID }
  - code_change: { type: 'code', content: string, position: number }
  - chat_message: { type: 'chat', message: string, userId: UUID }
  - screen_share: { type: 'screen', action: 'start'|'stop' }
  - cursor_move: { type: 'cursor', x: number, y: number, userId: UUID }

Response Format:
  success: boolean
  type: string
  data: object
  timestamp: DateTime
```

#### Algorithms/Data Structures
- **Operational Transform**: For real-time collaborative editing
- **Event Sourcing**: For session history and replay capabilities
- **CRDT (Conflict-free Replicated Data Types)**: For distributed collaboration

## 🖹 7. Migrations

### Migration Strategy

Since this is a greenfield project, initial migrations focus on data structure evolution and tenant onboarding:

#### Phase 1: Core Infrastructure (Weeks 1-2)
- Deploy base AWS infrastructure with Terraform
- Set up CI/CD pipelines with GitHub Actions
- Configure monitoring and logging systems
- Create initial database schemas

#### Phase 2: Service Rollout (Weeks 3-6)
- Deploy User Service and basic authentication
- Launch POC Service with file storage
- Implement Search Service with OpenSearch
- Basic mobile app deployment

#### Phase 3: Advanced Features (Weeks 7-10)
- Real-time Dojo functionality
- Video generation service
- Comprehensive reporting system
- Full multi-tenant capabilities

#### Migration Considerations
```sql
-- Schema versioning strategy
CREATE TABLE schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT NOW(),
    description TEXT
);

-- Tenant data isolation validation
CREATE OR REPLACE FUNCTION check_tenant_isolation()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.tenant_id != OLD.tenant_id THEN
        RAISE EXCEPTION 'Tenant ID cannot be changed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

## 🖹 8. Testing Strategy

### Testing Approach

#### Unit Testing (70% coverage minimum)
- **Frameworks**: Jest for Node.js services, XCTest for iOS, JUnit for Android
- **Mock Strategy**: Mock external dependencies and databases
- **Test Data**: Factory pattern for generating test entities
- **Assertion Libraries**: Comprehensive assertion libraries for all platforms

#### Integration Testing
- **Database Testing**: Use TestContainers for real database integration tests
- **API Testing**: Postman collections with automated Newman runs
- **Service Communication**: Test service-to-service communication with contract testing
- **Event Testing**: Verify event publishing and consumption

#### End-to-End Testing
- **Mobile Testing**: Detox for React Native components, native testing frameworks
- **Browser Testing**: Cypress for web interfaces
- **User Journey Testing**: Complete user workflows from registration to POC creation
- **Performance Testing**: JMeter for load testing APIs

#### Chaos Engineering
- **Service Failure**: Random service shutdowns during peak hours
- **Network Partitions**: Simulate network splits between availability zones
- **Database Failures**: Test RDS failover scenarios
- **Resource Exhaustion**: Memory and CPU stress testing

#### Testing Data Strategy
```javascript
// Mock data factory example
class POCFactory {
    static create(overrides = {}) {
        return {
            id: faker.uuid(),
            name: faker.lorem.words(3),
            language: faker.random.arrayElement(['JavaScript', 'Python', 'Java']),
            tags: faker.random.arrayElements(['web', 'api', 'testing'], 2),
            tenantId: faker.uuid(),
            ...overrides
        };
    }
}
```

## 🖹 9. Observability Strategy

### Monitoring and Observability

#### Metrics Collection
- **Application Metrics**: Custom metrics using CloudWatch and Prometheus
- **Business Metrics**: POC creation rates, user engagement, Dojo session duration
- **Infrastructure Metrics**: CPU, memory, disk usage, network throughput
- **Database Metrics**: Connection pool usage, query performance, replication lag

#### Logging Strategy
```json
// Structured logging format
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "service": "poc-service",
  "traceId": "abc123",
  "tenantId": "tenant-456",
  "userId": "user-789",
  "event": "poc_created",
  "details": {
    "pocId": "poc-101112",
    "language": "JavaScript",
    "tags": ["web", "api"]
  }
}
```

#### Distributed Tracing
- **AWS X-Ray**: End-to-end request tracing across services
- **Trace Sampling**: 10% sampling rate for high-traffic endpoints
- **Custom Spans**: Business operation tracking (search queries, video generation)

#### Alerting Strategy
- **Critical Alerts**: Service down, high error rates (>5%), database failures
- **Warning Alerts**: High response times (>2s), low disk space (<20%)
- **Business Alerts**: Unusual tenant activity, failed video generations
- **Escalation**: PagerDuty integration with on-call rotation

#### Dashboard Design
- **Executive Dashboard**: High-level business metrics and system health
- **Operational Dashboard**: Service-level metrics and alert status
- **Performance Dashboard**: Response times, throughput, and error rates
- **Tenant Dashboard**: Per-tenant usage and activity metrics

## 🖹 10. Data Store Designs

### PostgreSQL (Primary Database)

#### Schema Design
```sql
-- Tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(100) UNIQUE NOT NULL,
    plan_type VARCHAR(50) NOT NULL DEFAULT 'basic',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- POC files storage reference
CREATE TABLE poc_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    poc_id UUID NOT NULL REFERENCES pocs(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    s3_key VARCHAR(500) NOT NULL,
    mime_type VARCHAR(100),
    uploaded_at TIMESTAMP DEFAULT NOW()
);
```

#### Partitioning Strategy
- **Time-based Partitioning**: POCs table partitioned by created_at (monthly partitions)
- **Tenant-based Sharding**: Consider horizontal sharding when reaching 100M+ records
- **Archival Strategy**: Archive POCs older than 3 years to separate tables

#### Performance Optimization
- **Connection Pooling**: PgBouncer with 100 max connections per service
- **Query Optimization**: Regular EXPLAIN ANALYZE for slow queries
- **Index Strategy**: Composite indexes for common query patterns
- **Read Replicas**: 2 read replicas for search and reporting queries

### Amazon S3 (File Storage)

#### Bucket Structure
```
poc-tracker-files-{environment}/
├── tenants/
│   ├── {tenant-id}/
│   │   ├── pocs/
│   │   │   ├── {poc-id}/
│   │   │   │   ├── source-files/
│   │   │   │   └── generated-content/
│   │   └── videos/
│   │       ├── annual/
│   │       └── custom/
└── system/
    ├── templates/
    └── assets/
```

#### Storage Classes and Lifecycle
- **Standard**: Active files accessed within 30 days
- **Standard-IA**: Files accessed 30-90 days ago
- **Glacier**: Archive files older than 90 days
- **Deep Archive**: Long-term archive (>1 year)

#### Security and Access
- **Bucket Policies**: Strict tenant-based access control
- **Pre-signed URLs**: Temporary access for file uploads/downloads (15-minute expiry)
- **Encryption**: S3-managed encryption (SSE-S3) for all objects
- **Versioning**: Enabled with lifecycle policy to clean old versions

### OpenSearch (Search and Analytics)

#### Index Design
```json
// POC Index Template
{
  "index_patterns": ["poc-*"],
  "template": {
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 1,
      "analysis": {
        "analyzer": {
          "code_analyzer": {
            "type": "custom",
            "tokenizer": "keyword",
            "filters": ["lowercase", "trim"]
          }
        }
      }
    },
    "mappings": {
      "dynamic": false,
      "properties": {
        "tenant_id": { "type": "keyword" },
        "poc_id": { "type": "keyword" },
        "name": { 
          "type": "text",
          "analyzer": "standard",
          "fields": {
            "keyword": { "type": "keyword" },
            "suggest": { 
              "type": "completion",
              "analyzer": "simple"
            }
          }
        },
        "description": { "type": "text" },
        "language": { "type": "keyword" },
        "tags": { 
          "type": "keyword",
          "fields": {
            "suggest": { "type": "completion" }
          }
        },
        "file_content": { 
          "type": "text",
          "analyzer": "code_analyzer"
        },
        "created_at": { "type": "date" },
        "updated_at": { "type": "date" },
        "user_id": { "type": "keyword" },
        "popularity_score": { "type": "float" }
      }
    }
  }
}
```

#### Index Management
- **Time-based Indices**: Monthly indices for better performance and lifecycle management
- **Index Aliases**: Use aliases for zero-downtime index updates
- **Rollover Policy**: Automatic rollover when index reaches 50GB or 30 days
- **Snapshot Strategy**: Daily snapshots retained for 30 days

#### Query Patterns
```javascript
// Complex search query example
{
  "query": {
    "bool": {
      "must": [
        {
          "multi_match": {
            "query": "react authentication",
            "fields": ["name^3", "description^2", "file_content"],
            "type": "best_fields"
          }
        }
      ],
      "filter": [
        { "term": { "tenant_id": "tenant-123" } },
        { "terms": { "language": ["JavaScript", "TypeScript"] } },
        { "range": { "created_at": { "gte": "2023-01-01" } } }
      ]
    }
  },
  "aggs": {
    "languages": {
      "terms": { "field": "language", "size": 10 }
    },
    "popular_tags": {
      "terms": { "field": "tags", "size": 20 }
    }
  },
  "highlight": {
    "fields": {
      "name": {},
      "description": {},
      "file_content": { "fragment_size": 150 }
    }
  }
}
```

### Redis (Caching and Sessions)

#### Cache Structure
```
# User sessions
session:{session-id} -> {user_data, tenant_id, permissions, expires_at}

# POC cache (frequently accessed)
poc:{tenant-id}:{poc-id} -> {poc_data}

# Search result cache
search:{tenant-id}:{query-hash} -> {search_results}

# Popular tags cache
tags:popular:{tenant-id} -> {tag_list_with_counts}

# Rate limiting
rate_limit:{user-id}:{endpoint} -> {request_count, window_start}

# Real-time Dojo sessions
dojo:session:{session-id} -> {participants, poc_id, state}
dojo:user:{user-id} -> {active_sessions[]}
```

#### Cache Strategies
- **Cache-Aside**: Application manages cache population and invalidation
- **Write-Through**: POC updates write to cache and database simultaneously
- **TTL Strategy**: Different expiration times based on data volatility
  - User sessions: 24 hours
  - POC data: 1 hour
  - Search results: 15 minutes
  - Popular tags: 6 hours

#### Redis Cluster Configuration
- **3-node cluster**: Master-replica setup across availability zones
- **Memory Optimization**: Use Redis compression for large objects
- **Persistence**: RDB snapshots every 6 hours, AOF for durability
- **Monitoring**: Memory usage, hit/miss ratios, connection counts

## 🖹 11. Technology Stack

### Backend Services
- **Programming Language**: Node.js with TypeScript for consistency and type safety
- **Framework**: Express.js with Helmet for security, Morgan for logging
- **Container Runtime**: Docker containers on Amazon ECS with Fargate
- **API Gateway**: AWS API Gateway with request/response validation
- **Authentication**: AWS Cognito with custom JWT handling
- **Message Queue**: Amazon SQS for async processing, SNS for notifications

### Mobile Applications
- **iOS**: Swift with UIKit, Combine for reactive programming
- **Android**: Kotlin with Jetpack Compose for modern UI development
- **Networking**: URLSession (iOS), Retrofit with OkHttp (Android)
- **Local Storage**: Core Data (iOS), Room Database (Android)
- **Real-time**: Socket.IO clients for both platforms

### Databases and Storage
- **Primary Database**: PostgreSQL 14+ on Amazon RDS with Multi-AZ deployment
- **Search Engine**: Amazon OpenSearch Service (Elasticsearch 7.x compatible)
- **Cache Layer**: Redis 6.x on Amazon ElastiCache with cluster mode
- **File Storage**: Amazon S3 with CloudFront CDN distribution
- **Data Warehouse**: Amazon Redshift for analytics (future consideration)

### Infrastructure and DevOps
- **Cloud Provider**: Amazon Web Services (AWS) exclusively
- **Infrastructure as Code**: Terraform with modular structure
- **Container Orchestration**: Amazon ECS with Application Load Balancer
- **CI/CD Pipeline**: GitHub Actions with multi-stage deployments
- **Monitoring**: CloudWatch, X-Ray for tracing, custom Grafana dashboards
- **Security**: AWS WAF, GuardDuty, Security Hub, VPC with private subnets

### Frontend and APIs
- **API Design**: RESTful APIs with OpenAPI 3.0 specification
- **API Documentation**: Swagger UI with interactive documentation
- **Validation**: Joi for request validation, custom middleware for business rules
- **Rate Limiting**: Express-rate-limit with Redis backend
- **CORS**: Configurable cross-origin resource sharing policies

### Development Tools
- **Version Control**: Git with GitHub, feature branch workflow
- **Code Quality**: ESLint, Prettier, SonarQube for static analysis
- **Testing**: Jest for unit tests, Supertest for API testing
- **Database Migrations**: Knex.js for schema migrations and seeding
- **Environment Management**: Docker Compose for local development

### Prohibited Technologies (As per restrictions)
- ❌ **AWS Lambda**: Using ECS containers instead for better performance control
- ❌ **Monolithic Architecture**: Implementing microservices for scalability
- ❌ **Single AZ**: Multi-AZ deployment for high availability
- ❌ **Ionic**: Using native mobile development (Swift/Kotlin)
- ❌ **MongoDB**: Using PostgreSQL for ACID compliance and relationships
- ❌ **Non-AWS Clouds**: Exclusive AWS deployment for operational simplicity

### Third-Party Integrations
- **Payment Processing**: Stripe for subscription management (Brazilian market support)
- **Email Service**: Amazon SES for transactional emails, SendGrid as backup
- **Video Processing**: FFmpeg for video generation, AWS MediaConvert for encoding
- **Analytics**: Custom analytics with OpenSearch, Google Analytics for web tracking
- **Error Tracking**: Sentry for error monitoring and performance tracking

### Security Stack
- **Encryption**: TLS 1.3 for transport, AES-256 for data at rest
- **Identity Management**: OAuth 2.0 / OpenID Connect integration
- **Secrets Management**: AWS Secrets Manager for API keys and credentials
- **Vulnerability Scanning**: Snyk for dependency scanning, AWS Inspector
- **Compliance**: LGPD compliance tools, audit logging with CloudTrail

### Performance and Scalability
- **Load Balancing**: Application Load Balancer with health checks
- **Auto Scaling**: Target tracking scaling policies based on CPU/memory
- **CDN**: CloudFront for static assets and API caching
- **Database Optimization**: Connection pooling, read replicas, query optimization
- **Caching Strategy**: Multi-layer caching (Redis, CloudFront, application-level)

## 🖹 12. References

### Architecture Patterns and Best Practices
- **Architecture Anti-Patterns**: https://architecture-antipatterns.tech/
- **Microservices Patterns**: https://microservices.io/patterns/
- **AWS Well-Architected Framework**: https://aws.amazon.com/architecture/well-architected/
- **Domain-Driven Design**: Eric Evans - "Domain-Driven Design: Tackling Complexity"
- **Building Microservices**: Sam Newman - O'Reilly Media

### API and Integration Patterns
- **Enterprise Integration Patterns**: https://www.enterpriseintegrationpatterns.com/
- **RESTful API Design**: https://restfulapi.net/
- **OpenAPI Specification**: https://swagger.io/specification/
- **GraphQL Best Practices**: https://graphql.org/learn/best-practices/
- **WebSocket Protocol**: RFC 6455 - The WebSocket Protocol

### Database and Data Patterns
- **Database Refactoring Patterns**: https://databaserefactoring.com/
- **PostgreSQL Documentation**: https://www.postgresql.org/docs/
- **Redis Data Modeling**: https://redis.com/blog/nosql-data-modeling/
- **OpenSearch Documentation**: https://opensearch.org/docs/
- **Data Mesh Principles**: Zhamak Dehghani - O'Reilly Media

### Mobile Development
- **iOS Human Interface Guidelines**: https://developer.apple.com/design/human-interface-guidelines/
- **Android Material Design**: https://material.io/design
- **Mobile API Security**: OWASP Mobile Security Testing Guide
- **Offline-First Architecture**: https://offlinefirst.org/
- **React Native Performance**: https://reactnative.dev/docs/performance

### Security and Compliance
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **AWS Security Best Practices**: https://aws.amazon.com/security/
- **LGPD Compliance**: Brazilian General Data Protection Law guidelines
- **OAuth 2.0 Security**: RFC 6819 - OAuth 2.0 Threat Model
- **JWT Best Practices**: RFC 8725 - JSON Web Token Best Current Practices

### DevOps and Operations
- **12-Factor App**: https://12factor.net/
- **Site Reliability Engineering**: Google SRE Book
- **Infrastructure as Code**: Terraform Best Practices
- **Container Security**: CIS Docker Benchmark
- **Monitoring and Observability**: The Three Pillars of Observability

### Performance and Scalability
- **High Scalability**: http://highscalability.com/
- **Performance Testing**: JMeter and Load Testing Best Practices
- **Caching Strategies**: Various caching patterns and implementations
- **Database Performance**: PostgreSQL Performance Tuning Guide
- **CDN Best Practices**: CloudFront and content delivery optimization

### Business and Product
- **Lean Startup**: Eric Ries methodology for product development
- **User Story Mapping**: Jeff Patton - story mapping techniques
- **Product Management**: Inspired by Marty Cagan
- **SaaS Metrics**: Key performance indicators for SaaS businesses
- **Multi-tenant Architecture**: Patterns for SaaS applications

---

**Document Version**: 1.0  
**Last Updated**: September 16, 2025  
**Author**: Software Architecture Team  
**Review Status**: Ready for Implementation