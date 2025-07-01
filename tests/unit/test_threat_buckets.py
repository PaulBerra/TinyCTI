"""
Tests unitaires pour le nouveau système de buckets de threat intelligence
"""

from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from tinycti import (IOC, ConfidenceLevel, IOCType, RetentionBucket,
                     RetentionManager, ThreatBucket, ThreatBucketManager,
                     ThreatLevel)


class TestThreatBucketManager:
    """Tests pour la classe ThreatBucketManager"""

    def test_bucket_manager_initialization(self):
        """Test l'initialisation du gestionnaire de buckets"""
        manager = ThreatBucketManager()

        assert manager.bucket_priorities[ThreatBucket.CRITICAL] == 1
        assert manager.bucket_priorities[ThreatBucket.ACTIVE] == 2
        assert manager.bucket_priorities[ThreatBucket.WATCH] == 3
        assert manager.bucket_priorities[ThreatBucket.ARCHIVE] == 6
        assert manager.bucket_priorities[ThreatBucket.DEPRECATED] == 7

    def test_determine_bucket_false_positive(self):
        """Test la détermination de bucket pour un faux positif"""
        manager = ThreatBucketManager()

        ioc = IOC(
            value="192.168.1.1", type=IOCType.IPV4, source="test", false_positive=True
        )

        bucket = manager.determine_bucket(ioc)
        assert bucket == ThreatBucket.DEPRECATED

    def test_determine_bucket_expired_ioc(self):
        """Test la détermination de bucket pour un IOC expiré"""
        manager = ThreatBucketManager()

        ioc = IOC(
            value="malware.com",
            type=IOCType.DOMAIN,
            source="test",
            ttl_hours=24,
            last_seen=datetime.now() - timedelta(hours=48),  # Expiré
        )

        bucket = manager.determine_bucket(ioc)
        assert bucket == ThreatBucket.ARCHIVE

    def test_determine_bucket_verified_high_threat(self):
        """Test la détermination de bucket pour un IOC vérifié à haute menace"""
        manager = ThreatBucketManager()

        ioc = IOC(
            value="sha256hash",
            type=IOCType.HASH_SHA256,
            source="verified_source",
            verified=True,
            confidence_level=ConfidenceLevel.CONFIRMED,
            threat_level=ThreatLevel.HIGH,
        )

        bucket = manager.determine_bucket(ioc)
        assert bucket == ThreatBucket.CRITICAL

    def test_determine_bucket_new_high_confidence(self):
        """Test la détermination de bucket pour un nouvel IOC de haute confiance"""
        manager = ThreatBucketManager()

        ioc = IOC(
            value="evil.com",
            type=IOCType.DOMAIN,
            source="high_reputation_source",
            confidence_level=ConfidenceLevel.HIGH,
            threat_level=ThreatLevel.HIGH,
        )

        bucket = manager.determine_bucket(ioc)
        assert bucket == ThreatBucket.ACTIVE

    def test_determine_bucket_low_confidence(self):
        """Test la détermination de bucket pour un IOC de faible confiance"""
        manager = ThreatBucketManager()

        ioc = IOC(
            value="suspicious.net",
            type=IOCType.DOMAIN,
            source="unknown_source",
            confidence_level=ConfidenceLevel.LOW,
        )

        bucket = manager.determine_bucket(ioc)
        assert bucket == ThreatBucket.EMERGING

    def test_should_transition_age_based(self):
        """Test la logique de transition basée sur l'âge"""
        manager = ThreatBucketManager()

        # IOC dans bucket EMERGING depuis 5 jours (limite: 3 jours)
        ioc = IOC(
            value="old.com",
            type=IOCType.DOMAIN,
            source="test",
            last_seen=datetime.now() - timedelta(days=5),
        )

        should_transition = manager.should_transition(ioc, ThreatBucket.EMERGING)
        assert should_transition is True

    def test_should_transition_verified_promotion(self):
        """Test la logique de transition pour promotion d'IOC vérifié"""
        manager = ThreatBucketManager()

        ioc = IOC(
            value="confirmed.malware",
            type=IOCType.DOMAIN,
            source="test",
            verified=True,
            confidence_level=ConfidenceLevel.CONFIRMED,
        )

        should_transition = manager.should_transition(ioc, ThreatBucket.WATCH)
        assert should_transition is True

    def test_get_next_bucket_promotion(self):
        """Test l'obtention du prochain bucket pour promotion"""
        manager = ThreatBucketManager()

        ioc = IOC(
            value="confirmed.threat",
            type=IOCType.DOMAIN,
            source="test",
            verified=True,
            confidence_level=ConfidenceLevel.CONFIRMED,
        )

        next_bucket = manager.get_next_bucket(ioc, ThreatBucket.ACTIVE)
        assert next_bucket == ThreatBucket.CRITICAL

    def test_get_next_bucket_fallback(self):
        """Test l'obtention du prochain bucket pour rétrogradation"""
        manager = ThreatBucketManager()

        # IOC ancien dans bucket EMERGING
        ioc = IOC(
            value="old.com",
            type=IOCType.DOMAIN,
            source="test",
            last_seen=datetime.now() - timedelta(days=5),
        )

        next_bucket = manager.get_next_bucket(ioc, ThreatBucket.EMERGING)
        assert next_bucket == ThreatBucket.ARCHIVE

    def test_bucket_priority_comparison(self):
        """Test la comparaison des priorités de buckets"""
        manager = ThreatBucketManager()

        assert manager.should_promote(ThreatBucket.WATCH, ThreatBucket.CRITICAL)
        assert not manager.should_promote(ThreatBucket.CRITICAL, ThreatBucket.WATCH)
        assert not manager.should_promote(ThreatBucket.ACTIVE, ThreatBucket.ACTIVE)


class TestIOCEnhancedFunctionality:
    """Tests pour les nouvelles fonctionnalités de la classe IOC"""

    def test_ioc_initialization_with_new_fields(self):
        """Test l'initialisation d'un IOC avec les nouveaux champs"""
        ioc = IOC(
            value="192.168.1.1",
            type=IOCType.IPV4,
            source="test_source",
            bucket=ThreatBucket.CRITICAL,
            threat_level=ThreatLevel.HIGH,
            confidence_level=ConfidenceLevel.CONFIRMED,
            tags=["malware", "botnet"],
            ttl_hours=48,
            verified=True,
        )

        assert ioc.bucket == ThreatBucket.CRITICAL
        assert ioc.threat_level == ThreatLevel.HIGH
        assert ioc.confidence_level == ConfidenceLevel.CONFIRMED
        assert "malware" in ioc.tags
        assert ioc.ttl_hours == 48
        assert ioc.verified is True

        # Test compatibilité ascendante
        assert ioc.retention == RetentionBucket.LIVE  # Mapping CRITICAL -> LIVE
        assert ioc.confidence == 1.0  # Mapping CONFIRMED -> 1.0

    def test_ioc_is_operational(self):
        """Test la méthode is_operational"""
        critical_ioc = IOC(
            "evil.com", IOCType.DOMAIN, "test", bucket=ThreatBucket.CRITICAL
        )
        active_ioc = IOC("bad.com", IOCType.DOMAIN, "test", bucket=ThreatBucket.ACTIVE)
        watch_ioc = IOC(
            "suspicious.com", IOCType.DOMAIN, "test", bucket=ThreatBucket.WATCH
        )
        archive_ioc = IOC(
            "old.com", IOCType.DOMAIN, "test", bucket=ThreatBucket.ARCHIVE
        )

        assert critical_ioc.is_operational() is True
        assert active_ioc.is_operational() is True
        assert watch_ioc.is_operational() is True
        assert archive_ioc.is_operational() is False

    def test_ioc_is_expired(self):
        """Test la méthode is_expired"""
        # IOC avec TTL défini et expiré
        expired_ioc = IOC(
            "expired.com",
            IOCType.DOMAIN,
            "test",
            ttl_hours=24,
            last_seen=datetime.now() - timedelta(hours=48),
        )

        # IOC avec TTL défini mais pas expiré
        valid_ioc = IOC(
            "valid.com",
            IOCType.DOMAIN,
            "test",
            ttl_hours=24,
            last_seen=datetime.now() - timedelta(hours=12),
        )

        # IOC sans TTL
        no_ttl_ioc = IOC("notl.com", IOCType.DOMAIN, "test")

        assert expired_ioc.is_expired() is True
        assert valid_ioc.is_expired() is False
        assert no_ttl_ioc.is_expired() is False

    def test_ioc_should_be_archived(self):
        """Test la méthode should_be_archived"""
        # Faux positif
        false_positive = IOC("fp.com", IOCType.DOMAIN, "test", false_positive=True)

        # IOC expiré
        expired = IOC(
            "expired.com",
            IOCType.DOMAIN,
            "test",
            ttl_hours=24,
            last_seen=datetime.now() - timedelta(hours=48),
        )

        # IOC ancien avec faible confiance
        old_low_confidence = IOC(
            "old.com",
            IOCType.DOMAIN,
            "test",
            confidence_level=ConfidenceLevel.LOW,
            last_seen=datetime.now() - timedelta(days=35),
        )

        # IOC récent avec haute confiance
        recent_high_confidence = IOC(
            "recent.com",
            IOCType.DOMAIN,
            "test",
            confidence_level=ConfidenceLevel.HIGH,
            last_seen=datetime.now() - timedelta(days=5),
        )

        assert false_positive.should_be_archived() is True
        assert expired.should_be_archived() is True
        assert old_low_confidence.should_be_archived() is True
        assert recent_high_confidence.should_be_archived() is False


class TestRetentionManagerEnhancement:
    """Tests pour les améliorations du RetentionManager"""

    def test_retention_manager_with_threat_buckets(self):
        """Test l'initialisation du RetentionManager avec les nouveaux buckets"""
        config = {
            "retention": {},
            "use_intelligent_buckets": True,
            "source_confidence": {"spamhaus": "confirmed", "experimental": "unknown"},
            "ioc_threats": {"hash_sha256": "high", "email": "low"},
        }

        storage = Mock()
        logger = Mock()

        manager = RetentionManager(config, storage, logger)

        assert hasattr(manager, "threat_bucket_manager")
        assert (
            manager.source_confidence_mapping["spamhaus"] == ConfidenceLevel.CONFIRMED
        )
        assert manager.ioc_threat_mapping[IOCType.EMAIL] == ThreatLevel.LOW

    def test_enrich_ioc_metadata_source_confidence(self):
        """Test l'enrichissement automatique selon la source"""
        config = {
            "retention": {},
            "source_confidence": {"spamhaus": "confirmed", "phishtank": "medium"},
        }

        manager = RetentionManager(config, Mock(), Mock())

        # IOC de source fiable
        ioc1 = IOC("evil.com", IOCType.DOMAIN, "spamhaus_blacklist")
        enriched1 = manager.enrich_ioc_metadata(ioc1)
        assert enriched1.confidence_level == ConfidenceLevel.CONFIRMED

        # IOC de source modérément fiable
        ioc2 = IOC("phish.com", IOCType.DOMAIN, "phishtank_feed")
        enriched2 = manager.enrich_ioc_metadata(ioc2)
        assert enriched2.confidence_level == ConfidenceLevel.MEDIUM

    def test_enrich_ioc_metadata_threat_level(self):
        """Test l'enrichissement automatique du niveau de menace"""
        config = {
            "retention": {},
            "ioc_threats": {"hash_sha256": "high", "email": "low"},
        }

        manager = RetentionManager(config, Mock(), Mock())

        # Hash SHA256 (haute menace)
        ioc1 = IOC("abcd1234", IOCType.HASH_SHA256, "test")
        enriched1 = manager.enrich_ioc_metadata(ioc1)
        assert enriched1.threat_level == ThreatLevel.HIGH

        # Email (faible menace)
        ioc2 = IOC("spam@test.com", IOCType.EMAIL, "test")
        enriched2 = manager.enrich_ioc_metadata(ioc2)
        assert enriched2.threat_level == ThreatLevel.LOW

    def test_enrich_ioc_metadata_auto_tagging(self):
        """Test le tagging automatique"""
        config = {"retention": {}}
        manager = RetentionManager(config, Mock(), Mock())

        # IOC avec source phishing
        ioc = IOC(
            "phish.com",
            IOCType.DOMAIN,
            "phishtank_feed",
            confidence_level=ConfidenceLevel.HIGH,
            threat_level=ThreatLevel.MEDIUM,
        )

        enriched = manager.enrich_ioc_metadata(ioc)

        assert "phishing" in enriched.tags
        assert "web-ioc" in enriched.tags  # Domain/URL
        assert "verified" not in enriched.tags  # Pas confirmé

    def test_enrich_ioc_metadata_ttl_assignment(self):
        """Test l'assignation automatique du TTL"""
        config = {"retention": {}}
        manager = RetentionManager(config, Mock(), Mock())

        # IOC critique - Doit avoir les bonnes propriétés pour rester CRITICAL
        critical_ioc = IOC(
            "critical.malware",
            IOCType.DOMAIN,
            "test",
            bucket=ThreatBucket.CRITICAL,
            verified=True,
            confidence_level=ConfidenceLevel.CONFIRMED,
            threat_level=ThreatLevel.HIGH,
        )
        enriched_critical = manager.enrich_ioc_metadata(critical_ioc)
        assert enriched_critical.ttl_hours == 24 * 7  # 1 semaine

        # IOC émergent
        emerging_ioc = IOC(
            "emerging.threat", IOCType.DOMAIN, "test", bucket=ThreatBucket.EMERGING
        )
        enriched_emerging = manager.enrich_ioc_metadata(emerging_ioc)
        assert enriched_emerging.ttl_hours == 24 * 3  # 3 jours
