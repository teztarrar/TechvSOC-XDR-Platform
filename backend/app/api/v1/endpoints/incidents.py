from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.session import get_db
from app.models.enums import IncidentSeverity
from app.models.enums import IncidentStatus
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.incident import ForensicsResponse
from app.schemas.incident import IncidentCreateRequest
from app.schemas.incident import IncidentListResponse
from app.schemas.incident import IncidentResponse
from app.schemas.incident import IncidentStoryResponse
from app.schemas.incident import IncidentUpdateRequest
from app.schemas.incident_workflow import IncidentNoteCreate
from app.schemas.incident_workflow import IncidentNoteResponse
from app.schemas.incident_workflow import IncidentActivityResponse
from app.services.correlation_service import correlate_alerts_into_incidents
from app.services.incident_service import add_incident_note
from app.services.incident_service import calculate_confidence_level
from app.services.incident_service import calculate_risk_score
from app.services.incident_service import create_incident
from app.services.incident_service import delete_incident
from app.services.incident_service import generate_forensics_data
from app.services.incident_service import generate_incident_story
from app.services.incident_service import generate_incident_summary
from app.services.incident_service import generate_recommended_actions
from app.services.incident_service import get_incident_activities
from app.services.incident_service import get_incident_notes
from app.services.incident_service import get_incident_or_404
from app.services.incident_service import list_incidents
from app.services.incident_service import log_incident_activity
from app.services.incident_service import update_incident


def _enrich_incident_response(incident) -> IncidentResponse:
    response = IncidentResponse.model_validate(incident)
    response.risk_score = calculate_risk_score(incident)
    response.confidence_level = calculate_confidence_level(incident)
    response.ai_summary = generate_incident_summary(incident)
    response.recommended_actions = generate_recommended_actions(incident)
    response.story = IncidentStoryResponse(**generate_incident_story(incident))
    if incident.forensics_json:
        response.forensics = ForensicsResponse(**incident.forensics_json)
    else:
        response.forensics = None
    return response

router = APIRouter(prefix="/incidents")


@router.post(
    "/",
    response_model=IncidentResponse,
    summary="Create incident",
)
async def create_incident_endpoint(
    payload: IncidentCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
) -> IncidentResponse:
    incident = create_incident(
        db,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        alert_ids=payload.alert_ids,
    )
    return _enrich_incident_response(incident)


@router.get(
    "/",
    response_model=IncidentListResponse,
    summary="List incidents",
)
async def get_incidents(
    severity: IncidentSeverity | None = Query(default=None),
    status: IncidentStatus | None = Query(default=None),
    assigned_to_id: int | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
    ),
) -> IncidentListResponse:
    items, total = list_incidents(
        db,
        severity=severity,
        status=status,
        assigned_to_id=assigned_to_id,
        skip=skip,
        limit=limit,
    )
    return IncidentListResponse(
        items=[_enrich_incident_response(item) for item in items],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Get incident details",
)
async def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
    ),
) -> IncidentResponse:
    incident = get_incident_or_404(db, incident_id)
    return _enrich_incident_response(incident)


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Update incident",
)
async def patch_incident(
    incident_id: int,
    payload: IncidentUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
) -> IncidentResponse:
    incident = get_incident_or_404(db, incident_id)

    # Log status change before updating
    if payload.status is not None and payload.status != incident.status:
        log_incident_activity(
            db,
            incident_id=incident.id,
            actor_id=current_user.id,
            action="status_changed",
            old_value=incident.status.value if incident.status else None,
            new_value=payload.status.value,
        )

    # Log assignment change
    if payload.assigned_to_id is not None and payload.assigned_to_id != incident.assigned_to_id:
        log_incident_activity(
            db,
            incident_id=incident.id,
            actor_id=current_user.id,
            action="assigned",
            old_value=str(incident.assigned_to_id) if incident.assigned_to_id else "unassigned",
            new_value=str(payload.assigned_to_id),
        )

    updated = update_incident(
        db,
        incident,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status=payload.status,
        assigned_to_id=payload.assigned_to_id,
    )
    return _enrich_incident_response(updated)


@router.delete(
    "/{incident_id}",
    summary="Delete incident",
)
async def delete_incident_endpoint(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
) -> dict[str, str]:
    incident = get_incident_or_404(db, incident_id)
    delete_incident(db, incident)
    return {"detail": f"Incident {incident_id} deleted."}


@router.get(
    "/{incident_id}/story",
    response_model=IncidentStoryResponse,
    summary="Get incident investigation story",
)
async def get_incident_story(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
    ),
) -> IncidentStoryResponse:
    incident = get_incident_or_404(db, incident_id)
    return IncidentStoryResponse(**generate_incident_story(incident))


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteResponse,
    summary="Add note to incident",
)
async def create_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
) -> IncidentNoteResponse:
    incident = get_incident_or_404(db, incident_id)
    note = add_incident_note(
        db,
        incident_id=incident.id,
        author_id=current_user.id,
        content=payload.content,
    )
    log_incident_activity(
        db,
        incident_id=incident.id,
        actor_id=current_user.id,
        action="note_added",
        new_value=f"Note #{note.id}",
    )
    return IncidentNoteResponse(
        id=note.id,
        incident_id=note.incident_id,
        author_id=note.author_id,
        author_name=current_user.full_name if current_user else None,
        content=note.content,
        created_at=note.created_at,
    )


@router.get(
    "/{incident_id}/notes",
    response_model=list[IncidentNoteResponse],
    summary="List incident notes",
)
async def list_notes(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
    ),
) -> list[IncidentNoteResponse]:
    incident = get_incident_or_404(db, incident_id)
    notes = get_incident_notes(db, incident.id)
    return [
        IncidentNoteResponse(
            id=n.id,
            incident_id=n.incident_id,
            author_id=n.author_id,
            author_name=n.author.full_name if n.author else None,
            content=n.content,
            created_at=n.created_at,
        )
        for n in notes
    ]


@router.get(
    "/{incident_id}/activity",
    response_model=list[IncidentActivityResponse],
    summary="List incident activity log",
)
async def list_activity(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
    ),
) -> list[IncidentActivityResponse]:
    incident = get_incident_or_404(db, incident_id)
    activities = get_incident_activities(db, incident.id)
    return [
        IncidentActivityResponse(
            id=a.id,
            incident_id=a.incident_id,
            actor_id=a.actor_id,
            actor_name=a.actor.full_name if a.actor else None,
            action=a.action,
            old_value=a.old_value,
            new_value=a.new_value,
            created_at=a.created_at,
        )
        for a in activities
    ]


@router.get(
    "/{incident_id}/forensics",
    response_model=ForensicsResponse,
    summary="Get incident forensics data",
)
async def get_incident_forensics(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
    ),
) -> ForensicsResponse:
    incident = get_incident_or_404(db, incident_id)
    if incident.forensics_json:
        return ForensicsResponse(**incident.forensics_json)
    # Generate on-the-fly if not present
    forensics = generate_forensics_data(incident)
    incident.forensics_json = forensics
    db.add(incident)
    db.commit()
    return ForensicsResponse(**forensics)


@router.post(
    "/correlate",
    response_model=list[IncidentResponse],
    summary="Run correlation engine",
)
async def run_correlation(
    hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
) -> list[IncidentResponse]:
    incidents = correlate_alerts_into_incidents(db, hours=hours)
    return [_enrich_incident_response(inc) for inc in incidents]

