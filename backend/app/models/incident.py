from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy import Column
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.models.base import TimestampMixin
from app.models.enums import IncidentSeverity
from app.models.enums import IncidentStatus

incident_alert_link = Table(
    "incident_alert_links",
    Base.metadata,
    Column(
        "incident_id",
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "alert_id",
        Integer,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Incident(TimestampMixin, Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity, name="incident_severity"),
        default=IncidentSeverity.MEDIUM,
        nullable=False,
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status"),
        default=IncidentStatus.NEW,
        nullable=False,
    )
    attack_chain_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    timeline_json: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)
    assigned_to_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    investigating_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    contained_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    forensics_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    assigned_to = relationship("User", back_populates="incidents")
    alerts = relationship(
        "Alert",
        secondary=incident_alert_link,
        back_populates="incidents",
    )
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")
    activities = relationship("IncidentActivity", back_populates="incident", cascade="all, delete-orphan")

