from sqlalchemy import Boolean, Column, Integer, String, DateTime, func
from datetime import datetime

from core.database import Base


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100))
    email = Column(String(255), unique=True, index=True)
    instituition_name = Column(String(255), index=True)
    course_of_study = Column(String(200), index=True)
    year_of_study = Column(Integer, index=True)
    state_of_school = Column(String(300), index=True)
    password = Column(String(100))
    is_active = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True, default=None)
    registered_at = Column(DateTime, nullable=True, default=None)
    updated_at = Column(DateTime, nullable=True, default=None, onupdate=datetime.now)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    