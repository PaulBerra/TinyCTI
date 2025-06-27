# TinyCTI Framework: Technical Implementation Guide

The research reveals a mature ecosystem of Python libraries and architectural patterns perfectly suited for building TinyCTI. The threat intelligence community has established robust standards and open-source tools that provide a solid foundation for your modular CTI framework.

## Core library recommendations for TinyCTI

**STIX/TAXII Integration**: The **stix2** library (version 3.0.1+) emerges as the definitive choice for STIX 2.1 operations, offering official OASIS maintenance and comprehensive STIX compliance. Partner this with **taxii2-client** for TAXII 2.1 server integration. Notably, CybOX is now deprecated and integrated directly into STIX 2.x as Cyber Observable Objects, simplifying your architecture.

**IOC Extraction**: **iocextract** by InQuest provides the most robust solution for your needs, handling "defanged" IOCs (like `127[.]0[.]0[.]1` → `127.0.0.1`) and supporting all required IOC types including IPv4/IPv6, URLs, domains, hashes (MD5/SHA1/SHA256/SHA512), and email addresses. Its iterator-based approach ensures memory efficiency for large datasets.

**HTTP/API Management**: **HTTPX** stands out as the optimal choice over traditional requests library, offering HTTP/2 support, async/sync dual compatibility, built-in connection pooling, and robust retry mechanisms with exponential backoff - all essential for reliable threat feed consumption.

## Plugin architecture design patterns

Research into established CTI tools reveals that **ThreatIngestor's dual-plugin architecture** provides an excellent blueprint for TinyCTI. The pattern separates:

- **Source plugins** (input): Collect data from CSV, JSON, STIX, TAXII, RSS, and text sources
- **Operator plugins** (output): Process and export IOCs to storage systems

For plugin framework implementation, **Pluggy** (pytest's underlying framework) offers the most suitable hook-based system for CTI workflows, enabling multiple plugins to respond to data ingestion events. The framework supports sophisticated configuration management through YAML with built-in validation schemas:

```python
# ThreatIngestor-inspired plugin pattern
class SourcePlugin:
    def run(self, saved_state):
        """Return (saved_state, list(Artifacts))"""
        return saved_state, artifact_list

class OperatorPlugin:
    def handle_artifact(self, artifact):
        """Process individual IOC"""
        pass
```

## Security-first implementation approach

**Secure parsing practices** are critical given TinyCTI's multi-format support. Research reveals essential protections:

- **XML Security**: Disable DTD processing entirely to prevent XXE attacks
- **JSON Security**: Use `JSON.parse()` exclusively, implement input size limits
- **CSV Security**: Sanitize cells starting with `=`, `+`, `-`, `@` to prevent formula injection

**Data validation**: **Pydantic** emerges as the superior choice for IOC validation, offering type-hint based validation with built-in support for IPv4Address, IPv6Address, HttpUrl, and EmailStr types, plus automatic type conversion and comprehensive error reporting.

**API key security**: Implement **python-keyring** for production API key storage, integrating with OS-native secure storage (macOS Keychain, Windows Credential Store, Linux Secret Service). For key rotation, the research reveals that cloud secret management services (AWS Secrets Manager, Azure Key Vault) provide automated rotation capabilities essential for production CTI systems.

## Data management architecture

**4-tier data retention** (live/hot/warm/cold) is well-established in CTI platforms, particularly in Elasticsearch implementations. The optimal pattern for TinyCTI:

- **Live/Hot tier**: Recently ingested IOCs (1-7 days) on high-performance SSDs with fast access
- **Warm tier**: Less frequent access (30-90 days) on high-capacity storage  
- **Cold tier**: Long-term storage (months to years) on low-cost storage
- **Frozen tier**: Archival data on ultra-low-cost object stores (S3)

**Hybrid storage approach** proves most effective: PostgreSQL for structured IOC relationships, Elasticsearch for full-text search and analytics, and Redis for hot cache of frequently accessed indicators.

**Configuration management**: Sophisticated YAML patterns with environment variable templating, validation schemas using Cerberus, and multi-environment configuration inheritance provide the flexibility TinyCTI requires.

## Production-ready implementation patterns

**Error handling and logging**: Implement structured logging with **structlog** and sensitive data masking to prevent API key exposure in logs. Use fail-fast principles with specific exception handling rather than broad exception catching.

**Rate limiting and retry**: The research shows that exponential backoff with jitter, circuit breaker patterns using libraries like `pybreaker`, and respect for individual API provider limits (e.g., VirusTotal's 4 requests/minute for public APIs) are essential for reliable threat feed consumption.

**Security sandboxing**: For plugin safety, container-based isolation using Docker provides the most robust protection, with resource limits (CPU, memory, execution time) and network restrictions for untrusted plugins.

## Standards compliance and integration

**STIX 2.1 specification** (OASIS Standard approved June 2021) defines the current standard with 18 STIX Domain Objects and 19 Cyber Observable Objects. TinyCTI should implement full STIX 2.1 compliance for maximum interoperability with existing CTI platforms like MISP, OpenCTI, and commercial threat intelligence services.

**TAXII 2.1** provides the transport layer, with enhanced filtering capabilities and improved pagination support essential for large-scale IOC distribution. The official **taxii2-client** library handles all TAXII 2.x API services with proper authentication and error handling.

## Architectural synthesis for TinyCTI

The research reveals that successful CTI frameworks combine established patterns:

1. **Plugin discovery** using entry points or file-based discovery
2. **Configuration-driven operation** with YAML validation
3. **State management** using SQLite or Redis for plugin resumability  
4. **Queue-based processing** for long-running tasks
5. **Comprehensive error handling** with graceful degradation
6. **Security-first design** with input validation and sandboxing

Your TinyCTI implementation should leverage the **stix2 + taxii2-client + iocextract + httpx + pydantic** stack as the core foundation, with Pluggy for plugin architecture and proper security controls throughout. This combination provides production-ready capabilities while maintaining the modularity and extensibility your specifications require.

The mature CTI ecosystem offers battle-tested libraries and patterns that will significantly accelerate TinyCTI development while ensuring compliance with industry standards and security best practices.
