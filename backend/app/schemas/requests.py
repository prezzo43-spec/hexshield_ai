from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import date

class LoginPayload(BaseModel):
    login_identifier: str = Field(..., min_length=3, description="Accepts valid badge_number or account Email")
    password: str = Field(..., min_length=8)

    @validator('login_identifier')
    def sanitize_identifier(cls, v):
        return v.strip()

class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

class CaseCreatePayload(BaseModel):
    case_reference: str = Field(..., min_length=3, max_length=100)
    case_title: str = Field(..., min_length=5, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = "OPEN"
    classification: Optional[str] = "CONFIDENTIAL"
    jurisdiction: Optional[str] = "Republic of Kenya"
    applicable_law: Optional[str] = None
    lead_investigator_id: Optional[str] = None
    incident_location: Optional[str] = None
    incident_date: Optional[date] = None

class CaseStatusUpdatePayload(BaseModel):
    status: str

    @validator('status')
    def validate_status_scope(cls, v):
        allowed = {"OPEN", "UNDER_ANALYSIS", "PENDING_REVIEW", "CLOSED", "ARCHIVED", "REFERRED"}
        if v.upper() not in allowed:
            raise ValueError(f"Status must be one of: {list(allowed)}")
        return v.upper()

class InvestigatorCreatePayload(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    badge_number: Optional[str] = None
    organization: str
    department: Optional[str] = None
    role: str
    temporary_password: str = Field(..., min_length=8)