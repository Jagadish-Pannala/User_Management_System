from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Request,Query
from sqlalchemy.orm import Session
from ..interfaces.user_management import UserOut, UserRoleUpdate, UserBaseIn, UserOut_uuid, UserWithRoleNames_id, PaginatedUserResponse,PaginatedUserWithRolesResponse
from ...Business_Layer.services.user_management_service import UserService
from ...Data_Access_Layer.utils.dependency import get_db
import pandas as pd
from io import BytesIO
from typing import Optional
import time
import logging

router = APIRouter()

logger = logging.getLogger(__name__)

# Injecting the service with DB session
def get_user_service(db: Session = Depends(get_db)) -> UserService:
    return UserService(db)

@router.get("/")
def admin_home():
    return {"message": "User Management Route"}

@router.get("/count")
def count_users(
    user_service: UserService = Depends(get_user_service)
):
    return {"user_count": user_service.count_users()}

@router.get("/active-count")
def count_active_users(
    user_service: UserService = Depends(get_user_service)
):
    return {"active_user_count": user_service.count_active_users()}

@router.get("", response_model=PaginatedUserResponse)
def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(50, le=500),
    search: str = Query(None),
    user_service: UserService = Depends(get_user_service)
):
    t_start = time.time()
    print(f"🔵 START list_users endpoint - page={page}, limit={limit}, search={search}")
    
    try:
        result = user_service.list_users(page, limit, search)
        
        t_end = time.time()
        elapsed = (t_end - t_start) * 1000
        print(f"✅ END list_users endpoint - {elapsed:.2f}ms")
        
        if elapsed > 500:
            print(f"⚠️ SLOW ENDPOINT: list_users took {elapsed:.2f}ms")
        
        return result
    except Exception as e:
        t_end = time.time()
        elapsed = (t_end - t_start) * 1000
        print(f"❌ ERROR in list_users endpoint after {elapsed:.2f}ms: {str(e)}")
        raise

@router.get("/roles", response_model=PaginatedUserWithRolesResponse)
def get_users_with_roles(
    page: int = Query(1, ge=1),
    limit: int = Query(10, le=100),
    search: Optional[str] = Query(None),
    user_service: UserService = Depends(get_user_service),
):
    return user_service.get_users_with_roles(page, limit, search)

@router.get("/id/roles", response_model=list[UserWithRoleNames_id])
def get_users_with_roles_id(
    user_service: UserService = Depends(get_user_service)
):
    return user_service.get_users_with_roles_id()

@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    user_service: UserService = Depends(get_user_service)
):
    user = user_service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/uuid/{user_uuid}", response_model=UserOut_uuid)
def get_user_uuid(
    user_uuid: str,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    user = user_service.get_user_uuid(request.state.user, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("", response_model=UserOut)
def create_user(
    user: UserBaseIn,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    try:
        current_user = request.state.user
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

        result = user_service.create_bulk_user(df, created_by_user_id=request.state.user["user_id"], request=request)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    user: UserBaseIn,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.update_user(
            user_id, 
            user,
            current_user=request.state.user,
            request=request
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@router.put("/uuid/{user_uuid}", response_model=UserOut_uuid)
def update_user_uuid(
    user_uuid: str,
    user: UserBaseIn,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    try:
        return user_service.update_user_uuid(
            user_uuid, 
            user,
            current_user=request.state.user,
            request=request
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{user_id}")
def deactivate_user(
    user_id: int,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    try:
        user_service.deactivate_user(
            user_id,
            current_user=  request.state.user,
            request=request
        )
        return {"message": "User deactivated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@router.delete("/uuid/{user_uuid}")
def deactivate_user_uuid(
    user_uuid: str,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    try:
        user_service.deactivate_user_uuid(
            user_uuid,
            current_user=   request.state.user,
            request=request
        )
        return {"message": "User deactivated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@router.patch("/uuid/{user_uuid}/activate")
def activate_user_uuid(
    user_uuid: str,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    """
    Activate user by UUID (set is_active = True)
    """
    try:
        user_service.activate_user_uuid(
            user_uuid,
            current_user=request.state.user,
            request=request
        )
        return {"message": "User activated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.put("/{user_id}/role")
def update_user_roles(
    user_id: int,
    payload: UserRoleUpdate,
    request: Request,
    user_service: UserService = Depends(get_user_service)
):
    try:
        current_user = request.state.user
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
    user_service: UserService = Depends(get_user_service)
):
    try:
        current_user = request.state.user
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
    user_service: UserService = Depends(get_user_service)
):
    try:
        return {"roles": user_service.get_user_roles(user_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@router.get("/uuid/{user_uuid}/roles")
def get_user_roles_uuid(
    user_uuid: str,
    user_service: UserService = Depends(get_user_service)
):
    try:
        return {"roles": user_service.get_user_roles_by_uuid(user_uuid)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))