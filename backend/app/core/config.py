from functools import lru_cache

from pydantic import Field
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default="TechvSOC XDR Platform", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    debug: bool = Field(default=True, alias="DEBUG")
    api_v1_prefix: str = Field(default="/api/v1", alias="API_V1_PREFIX")
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    allowed_origins: list[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        alias="ALLOWED_ORIGINS",
    )
    database_url: str = Field(
        default="postgresql+psycopg2://postgres:postgres@localhost:5432/techvsoc_xdr",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    syslog_tcp_enabled: bool = Field(default=True,      alias="SYSLOG_TCP_ENABLED")
    syslog_tcp_host:    str  = Field(default="0.0.0.0", alias="SYSLOG_TCP_HOST")
    syslog_tcp_port:    int  = Field(default=5514,      alias="SYSLOG_TCP_PORT")
    secret_key: str = Field(default="change-this-in-production", alias="SECRET_KEY")
    access_token_expire_minutes: int = Field(
        default=60,
        alias="ACCESS_TOKEN_EXPIRE_MINUTES",
    )
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
