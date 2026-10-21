from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_current_user
from app.models import RoleEnum, User
from app.schemas import ChangePassword, UserOut, UserUpdateSelf
from app.security import hash_password, verify_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    # Status/role already checked in get_current_user.
    return current_user


@router.patch("/me", response_model=UserOut)
def update_me(
    payload: UserUpdateSelf,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Only apply fields the client actually sent (PATCH semantics).
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(current_user, field, value)

    db.commit()
    db.refresh(current_user)
    return current_user


@router.post("/me/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePassword,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Re-verify the current password before accepting a new one.
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")

    current_user.password_hash = hash_password(payload.new_password)
    # Bump token_version so all previously issued JWTs are rejected on next use.
    current_user.token_version += 1
    db.commit()


@router.post("/me/deactivate", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Admins must use the admin flow (and we never let them self-deactivate anyway).
    if current_user.role == RoleEnum.admin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Admins cannot deactivate their own account",
        )
    # Guard against double-deactivation (though get_current_user would already 403).
    if current_user.is_deactivated:
        raise HTTPException(status.HTTP_409_CONFLICT, "Account is already deactivated")

    current_user.is_deactivated = True
    current_user.token_version += 1  # Revoke every outstanding token.
    db.commit()
