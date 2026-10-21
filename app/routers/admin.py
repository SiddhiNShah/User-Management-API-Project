from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import AuditAction, RoleEnum, User
from app.schemas import UserListPage, UserOut, UserUpdateAdmin
from app.services import audit
from app.services.admin_guard import is_last_active_admin

router = APIRouter(prefix="/admin/users", tags=["admin"])


def _get_manageable_user(db: Session, user_id: int, admin: User) -> User:
    """Fetch a user the admin may act on; raise if not allowed.

    Target must exist, not be deleted, not be another admin,
    and must not be the acting admin themselves.
    """
    target = db.query(User).filter(User.user_id == user_id).first()
    if not target or target.is_deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target.role == RoleEnum.admin and target.user_id != admin.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot manage another admin")
    if target.user_id == admin.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot manage your own account here")
    return target


@router.get("", response_model=UserListPage)
def list_users(
    department: str | None = Query(default=None),
    is_deactivated: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    # Exclude soft-deleted users and other admins from the admin listing.
    query = db.query(User).filter(
        User.is_deleted.is_(False),
        User.role != RoleEnum.admin,
    )
    if department is not None:
        query = query.filter(User.department == department)
    if is_deactivated is not None:
        query = query.filter(User.is_deactivated.is_(is_deactivated))

    total = query.count()
    items = query.order_by(User.user_id).offset(offset).limit(limit).all()
    return UserListPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    # Read-only, no audit entry.
    return _get_manageable_user(db, user_id, admin)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateAdmin,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_manageable_user(db, user_id, admin)
    data = payload.model_dump(exclude_unset=True)

    # Role policy: admins cannot promote anyone to admin.
    if "role" in data and data["role"] == RoleEnum.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot assign admin role")

    role_changed = "role" in data and data["role"] != target.role

    # Capture before-state only for fields actually changing (for the audit entry).
    before = {k: getattr(target, k) for k in data.keys()}
    for field, value in data.items():
        setattr(target, field, value)
    if role_changed:
        # Invalidate existing tokens so the user picks up new permissions.
        target.token_version += 1

    audit.record(
        db,
        actor=admin,
        action=AuditAction.user_role_change if role_changed else AuditAction.user_update,
        target=target,
        details={"before": before, "after": data},
    )
    db.commit()
    db.refresh(target)
    return target


@router.post("/{user_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_manageable_user(db, user_id, admin)
    if target.is_deactivated:
        raise HTTPException(status.HTTP_409_CONFLICT, "User is already deactivated")

    target.is_deactivated = True
    target.token_version += 1  # Revoke outstanding tokens immediately.
    audit.record(db, actor=admin, action=AuditAction.user_deactivate, target=target)
    db.commit()


@router.post("/{user_id}/reactivate", status_code=status.HTTP_204_NO_CONTENT)
def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_manageable_user(db, user_id, admin)
    if not target.is_deactivated:
        raise HTTPException(status.HTTP_409_CONFLICT, "User is already active")

    target.is_deactivated = False
    # No token_version decrement — old tokens stay invalid; user must log in again.
    audit.record(db, actor=admin, action=AuditAction.user_reactivate, target=target)
    db.commit()


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = _get_manageable_user(db, user_id, admin)

    # Defensive: last-active-admin safeguard (target isn't an admin given the guard,
    # but keep this check in case guard rules change).
    if is_last_active_admin(db, target):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Cannot remove the last active admin",
        )

    target.is_deleted = True
    target.deleted_at = datetime.utcnow()
    target.token_version += 1
    audit.record(db, actor=admin, action=AuditAction.user_delete, target=target)
    db.commit()
