from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..interfaces.user_management import UserBase, UserOut, UserRoleUpdate, UserWithRoleNames
from ..JWT.jwt_validator.auth.dependencies import get_current_user, admin_required
from ...Business_Layer.services.user_management_service import UserService
from ...Data_Access_Layer.utils.dependency import get_db

router = APIRouter()

# Injecting the service with DB session
def get_user_service(db: Session = Depends(get_db)) -> UserService:
    return UserService(db)

@router.get("/")
def admin_home(current_user: dict = Depends(admin_required)):
    return {"message": "User Management Route"}

@router.get("", response_model=list[UserOut])
def list_users(
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    return user_service.list_users()

@router.get("/roles", response_model=list[UserWithRoleNames])
def get_users_with_roles(
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    return user_service.get_users_with_roles()

@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    user = user_service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("", response_model=UserOut)
def create_user(
    user: UserBase,
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.create_user(user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    user: UserBase,
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.update_user(user_id, user)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{user_id}")
def deactivate_user(
    user_id: int,
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    try:
        user_service.deactivate_user(user_id)
        return {"message": "User deactivated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.put("/{user_id}/role")
def update_user_roles(
    user_id: int,
    payload: UserRoleUpdate,
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    try:
        message = user_service.update_user_roles(user_id, payload.role_ids)
        return {"message": message}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{user_id}/roles")
def get_user_roles(
    user_id: int,
    current_user: dict = Depends(admin_required),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return {"roles": user_service.get_user_roles(user_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
