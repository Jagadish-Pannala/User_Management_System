from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from ..interfaces.user_management import UserBase, UserOut, UserRoleUpdate, UserWithRoleNames, UserBaseIn, UserOut_uuid, UserWithRoleNames_id
from ..JWT.jwt_validator.auth.dependencies import get_current_user
from ...Business_Layer.services.user_management_service import UserService
from ...Data_Access_Layer.utils.dependency import get_db
import pandas as pd
from io import BytesIO

router = APIRouter()

# Injecting the service with DB session
def get_user_service(db: Session = Depends(get_db)) -> UserService:
    return UserService(db)

@router.get("/")
def admin_home(current_user: dict = Depends(get_current_user)):
    return {"message": "User Management Route"}

@router.get("", response_model=list[UserOut])
def list_users(
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    return user_service.list_users()

@router.get("/roles", response_model=list[UserWithRoleNames])
def get_users_with_roles(
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    return user_service.get_users_with_roles()

@router.get("/id/roles", response_model=list[UserWithRoleNames_id])
def get_users_with_roles_id(
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    return user_service.get_users_with_roles_id()

@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    user = user_service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/uuid/{user_uuid}", response_model=UserOut_uuid)
def get_user_uuid(
    user_uuid: str,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    user = user_service.get_user_uuid(current_user, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("", response_model=UserOut)
def create_user(
    user: UserBaseIn,
    request: Request,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.create_user(
            user, 
            created_by_user_id=current_user['user_id'],
            current_user=current_user,
            request=request
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
@router.post("/multiple-users", response_model=dict)
async def bulk_create_users(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        context = await file.read()
        df = pd.read_excel(BytesIO(context))

        required_cols = {"first_name", "last_name", "mail", "contact"}
        if not required_cols.issubset(df.columns):
            raise HTTPException(
                status_code=400,
                detail=f"Missing required columns. Expected: {', '.join(required_cols)}"
            )

        result = user_service.create_bulk_user(df, created_by_user_id=current_user["user_id"], request=request)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    user: UserBaseIn,
    request: Request,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.update_user(
            user_id, 
            user,
            current_user=current_user,
            request=request
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@router.put("/uuid/{user_uuid}", response_model=UserOut_uuid)
def update_user_uuid(
    user_uuid: str,
    user: UserBaseIn,
    request: Request,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.update_user_uuid(
            user_uuid, 
            user,
            current_user=current_user,
            request=request
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{user_id}")
def deactivate_user(
    user_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        user_service.deactivate_user(
            user_id,
            current_user=current_user,
            request=request
        )
        return {"message": "User deactivated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@router.delete("/uuid/{user_uuid}")
def deactivate_user_uuid(
    user_uuid: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        user_service.deactivate_user_uuid(
            user_uuid,
            current_user=current_user,
            request=request
        )
        return {"message": "User deactivated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.put("/{user_id}/role")
def update_user_roles(
    user_id: int,
    payload: UserRoleUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        message = user_service.update_user_roles(
            user_id, 
            payload.role_ids,
            current_user['user_id'],
            current_user=current_user,
            request=request
        )
        return {"message": message}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.put("/uuid/{user_uuid}/role")
def update_user_roles_uuid(
    user_uuid: str,
    payload: UserRoleUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        message = user_service.update_user_roles_uuid(
            user_uuid, 
            payload.role_ids,
            current_user['user_id'],
            current_user=current_user,
            request=request
        )
        return {"message": message}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{user_id}/roles")
def get_user_roles(
    user_id: int,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return {"roles": user_service.get_user_roles(user_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@router.get("/uuid/{user_uuid}/roles")
def get_user_roles_uuid(
    user_uuid: str,
    current_user: dict = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    try:
        return {"roles": user_service.get_user_roles_by_uuid(user_uuid)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))