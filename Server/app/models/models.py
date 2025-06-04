from typing import Optional
from datetime import datetime
from sqlmodel import Field, SQLModel

class Token(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(unique=True, index=True)
    signedToken: Optional[str] = Field(default=None, index=True)
    isBlacklisted: bool = Field(default=False)
    decryptionKey: Optional[str] = Field(default=None)  # Clé de déchiffrement du stage1
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class TokenCreate(SQLModel):
    token: str

class Stage0Create(SQLModel):
    token: str
    payload: bytes

class ServerConfig(SQLModel):
    serverUrl: str 