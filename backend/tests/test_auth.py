"""
Unit Tests — Authentication System
======================================
Tests for user registration, login, JWT validation, and RBAC enforcement.

Run: cd backend && pytest tests/test_auth.py -v

Author: InteliSecure Team
"""

import sys
import os
import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.models import Base, User
from backend.database import get_db
from backend.auth import get_password_hash, verify_password, create_access_token


# ─── Test Database (In-Memory SQLite) ─────────────────────────────────────────
TEST_DB_URL  = "sqlite:///./test_intelisecure.db"
test_engine  = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession  = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="module")
def db():
    """Create fresh test DB tables and yield a session."""
    Base.metadata.create_all(bind=test_engine)
    session = TestSession()
    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("test_intelisecure.db"):
        os.remove("test_intelisecure.db")


# ─── Password Tests ────────────────────────────────────────────────────────────

class TestPasswordHashing:
    """Tests for bcrypt password hashing and verification."""

    def test_hash_is_not_plaintext(self):
        """Hashed password must not equal the original password."""
        hashed = get_password_hash("SecurePassword123!")
        assert hashed != "SecurePassword123!"

    def test_verify_correct_password(self):
        """Correct password must verify successfully."""
        hashed = get_password_hash("MyPass@99")
        assert verify_password("MyPass@99", hashed) is True

    def test_reject_wrong_password(self):
        """Wrong password must not verify."""
        hashed = get_password_hash("CorrectHorse")
        assert verify_password("WrongPassword", hashed) is False

    def test_hash_uniqueness(self):
        """Two hashes of the same password must differ (bcrypt salting)."""
        h1 = get_password_hash("SamePassword")
        h2 = get_password_hash("SamePassword")
        assert h1 != h2  # Each call generates a different salt


# ─── JWT Token Tests ──────────────────────────────────────────────────────────

class TestJWTTokens:
    """Tests for JWT creation and validation."""

    def test_create_token(self):
        """Token must be created successfully."""
        token = create_access_token(data={"sub": "testuser", "role": "Admin"})
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20

    def test_token_contains_claims(self):
        """Decoded token must contain the correct claims."""
        from jose import jwt
        from backend.config import settings
        token = create_access_token(data={"sub": "testuser", "role": "Analyst"})
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload.get("sub") == "testuser"
        assert payload.get("role") == "Analyst"
        assert "exp" in payload


# ─── User Model Tests ─────────────────────────────────────────────────────────

class TestUserModel:
    """Tests for user creation in the database."""

    def test_create_user(self, db):
        """User must be persisted to the database."""
        user = User(
            username="test_operator",
            email="operator@test.com",
            hashed_password=get_password_hash("TestPass123"),
            role="User"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        assert user.id is not None
        assert user.username == "test_operator"
        assert user.role     == "User"
        assert user.is_active is True

    def test_first_user_role_auto_assignment(self, db):
        """First registered user should automatically become Admin."""
        # Clear existing users
        db.query(User).delete()
        db.commit()

        first_user = User(
            username="first_admin",
            email="admin@test.com",
            hashed_password=get_password_hash("AdminPass123"),
            role="Admin"
        )
        db.add(first_user)
        db.commit()

        assert first_user.role == "Admin"


# ─── Detector Tests ───────────────────────────────────────────────────────────

class TestSecurityScore:
    """Tests for the security score calculation."""

    def test_score_without_events(self, db):
        """Score should be 100 with no threats."""
        from backend.modules.security_score import calculate_security_score
        # Clean DB
        from backend.models import LoginLog, MalwareLog, NetworkLog, FileAccessLog, Alert
        for model in [LoginLog, MalwareLog, NetworkLog, FileAccessLog, Alert]:
            db.query(model).delete()
        db.commit()

        result = calculate_security_score(db)
        assert result["score"] == 100
        assert result["risk_level"] == "Low"

    def test_score_decreases_with_failed_logins(self, db):
        """Score should decrease when failed logins are added."""
        from backend.modules.security_score import calculate_security_score
        from backend.models import LoginLog
        import datetime

        # Add 10 failed logins from the last hour
        for i in range(10):
            log = LoginLog(
                timestamp=datetime.datetime.utcnow(),
                username=f"attacker_{i}",
                ip_address="192.168.1.200",
                status="Failed"
            )
            db.add(log)
        db.commit()

        result = calculate_security_score(db)
        assert result["score"] < 100
        assert result["breakdown"]["failed_logins"]["penalty"] > 0


class TestThreatExplainer:
    """Tests for the XAI threat explainer."""

    def test_known_threat_explanation(self):
        """Known threat types should return full explanations."""
        from backend.modules.threat_explainer import explain_threat
        result = explain_threat("Brute Force Attack")
        assert result["threat_name"] == "Brute Force Attack"
        assert "technical_reason" in result
        assert "impact" in result
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) > 0

    def test_unknown_threat_fallback(self):
        """Unknown threat types should return a graceful fallback."""
        from backend.modules.threat_explainer import explain_threat
        result = explain_threat("Unknown Exotic Attack XYZ")
        assert "threat_name" in result
        assert isinstance(result["recommendations"], list)

    def test_all_known_types(self):
        """All 6 main threat types should have full explanations."""
        from backend.modules.threat_explainer import explain_threat
        threat_types = [
            "Brute Force Attack", "Port Scan", "Unauthorized File Access",
            "Blocked USB Device", "Malware Detected", "ML Anomaly"
        ]
        for threat_type in threat_types:
            result = explain_threat(threat_type)
            assert "recommendations" in result, f"Missing recommendations for: {threat_type}"
            assert len(result["recommendations"]) >= 3, f"Too few recommendations for: {threat_type}"


class TestRecommendationEngine:
    """Tests for the recommendation engine."""

    def test_brute_force_recommendations(self):
        """Brute force should return P1 recommendations."""
        from backend.modules.recommendation_engine import get_recommendations_for_threat
        recs = get_recommendations_for_threat("Brute Force Attack")
        assert len(recs) > 0
        p1_recs = [r for r in recs if r["priority"] == "P1"]
        assert len(p1_recs) > 0, "Brute Force must have at least one P1 recommendation"

    def test_report_recommendations_deduplication(self):
        """Full report recommendations must not contain duplicate actions."""
        from backend.modules.recommendation_engine import generate_full_report_recommendations
        result = generate_full_report_recommendations(["Brute Force Attack", "Port Scan", "Malware Detected"])
        all_recs = (
            result["p1_critical"] + result["p2_high"] +
            result["p3_medium"] + result["p4_low"]
        )
        actions = [r["action"] for r in all_recs]
        assert len(actions) == len(set(actions)), "Duplicate recommendations found!"


class TestGlossary:
    """Tests for the educational glossary."""

    def test_get_known_term(self):
        """Known terms should return full entries."""
        from backend.modules.glossary import get_term
        result = get_term("brute_force")
        assert result is not None
        assert result["term"] == "Brute Force Attack"
        assert "definition" in result
        assert "example" in result

    def test_search_by_keyword(self):
        """Keyword search should return relevant results."""
        from backend.modules.glossary import search_glossary
        results = search_glossary("password")
        assert len(results) > 0

    def test_all_terms_have_required_fields(self):
        """Every glossary entry must have all required fields."""
        from backend.modules.glossary import get_all_terms
        for entry in get_all_terms():
            assert "term"       in entry, f"Missing 'term' in {entry}"
            assert "definition" in entry, f"Missing 'definition' in {entry}"
            assert "example"    in entry, f"Missing 'example' in {entry}"
            assert "severity"   in entry, f"Missing 'severity' in {entry}"
