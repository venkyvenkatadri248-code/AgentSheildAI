import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.session import Base
from app.database.seed import seed_database
from app.models.entities import User, Agent

TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture(scope="function")
def db_session():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    
    # Seed initial test data
    seed_database(session)
    
    yield session
    
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def admin_user(db_session):
    return db_session.query(User).filter(User.email == "admin@agentshield.ai").first()


@pytest.fixture
def regular_user(db_session):
    return db_session.query(User).filter(User.email == "analyst@agentshield.ai").first()


@pytest.fixture
def research_agent(db_session):
    return db_session.query(Agent).filter(Agent.key == "research_agent").first()


@pytest.fixture
def mail_agent(db_session):
    return db_session.query(Agent).filter(Agent.key == "mail_agent").first()


@pytest.fixture
def file_agent(db_session):
    return db_session.query(Agent).filter(Agent.key == "file_agent").first()


@pytest.fixture
def data_agent(db_session):
    return db_session.query(Agent).filter(Agent.key == "data_analysis_agent").first()

