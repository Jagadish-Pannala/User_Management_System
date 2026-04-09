from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from typing import List

from ..interfaces.access_point import (
    AccessPointCreate,
    AccessPointUpdate,
    AccessPointOut,
    CreateAPResponse,
    PermissionMappingIn,
    BulkCreateAPResponse,
)
from ...Business_Layer.services.access_point_service import AccessPointService

router = APIRouter()


# ✅ Inject service directly using middleware session
def get_access_point_service(request: Request) -> AccessPointService:
    return AccessPointService(request.state.db)


# -------------------------------------------------------
# List all modules
# -------------------------------------------------------
@router.get("/modules", response_model=List[str])
def get_all_modules(request: Request):
    service = AccessPointService(request.state.db)
    return service.list_modules()


# -------------------------------------------------------
# Get unmapped access points
# -------------------------------------------------------
@router.get("/unmapped-access-points", response_model=List[AccessPointOut])
def get_unmapped_access_points(request: Request):
    service = AccessPointService(request.state.db)
    return service.get_unmapped_access_points()


# -------------------------------------------------------
# Get unmapped permissions
# -------------------------------------------------------
@router.get("/unmapped-permissions")
def get_unmapped_permissions(request: Request):
    service = AccessPointService(request.state.db)
    return service.get_unmapped_permissions()


# -------------------------------------------------------
# Create single access point
# -------------------------------------------------------
@router.post("/", response_model=CreateAPResponse)
def create_ap(data: AccessPointCreate, request: Request):
    service = AccessPointService(request.state.db)
    current_user = request.state.user
    return service.create_access_point(
        data,
        created_by_user_id=current_user["user_id"],
        request=request,
        current_user=current_user,
    )


# -------------------------------------------------------
# Bulk create access points
# -------------------------------------------------------
@router.post("/bulk-access-points-create", response_model=BulkCreateAPResponse)
def bulk_create_ap(request: Request, file: UploadFile = File(...)):
    service = AccessPointService(request.state.db)
    current_user = request.state.user
    return service.bulk_create_access_points(
        file=file,
        created_by_user_id=current_user["user_id"],
        request=request,
        current_user=current_user,
    )


# -------------------------------------------------------
# List all access points
# -------------------------------------------------------
@router.get("/", response_model=List[AccessPointOut])
def list_aps(request: Request):
    service = AccessPointService(request.state.db)
    return service.list()


# -------------------------------------------------------
# Get access point by UUID
# -------------------------------------------------------
@router.get("/{access_uuid}", response_model=AccessPointOut)
def get_ap(access_uuid: str, request: Request):
    service = AccessPointService(request.state.db)
    return service.get(access_uuid)


# -------------------------------------------------------
# Update access point
# -------------------------------------------------------
@router.put("/{access_uuid}", response_model=AccessPointOut)
def update_ap(access_uuid: str, data: AccessPointUpdate, request: Request):
    service = AccessPointService(request.state.db)
    return service.update(
        access_uuid, data, request=request, current_user=request.state.user
    )


# -------------------------------------------------------
# Delete access point
# -------------------------------------------------------
@router.delete("/{access_uuid}")
def delete_ap(access_uuid: str, request: Request):
    service = AccessPointService(request.state.db)
    return service.delete(access_uuid, request=request, current_user=request.state.user)


# -------------------------------------------------------
# Map single permission
# -------------------------------------------------------
@router.post("/{access_uuid}/map-permission/{permission_uuid}")
def map_permission(access_uuid: str, permission_uuid: str, request: Request):
    service = AccessPointService(request.state.db)
    current_user = request.state.user
    return service.map_permission(
        access_uuid,
        permission_uuid,
        current_user["user_id"],
        request=request,
        current_user=current_user,
    )


# -------------------------------------------------------
# Bulk map permissions via file upload
# -------------------------------------------------------
@router.post("/access-point-map-permission-bulk")
def map_permission_bulk(request: Request, file: UploadFile = File(...)):
    service = AccessPointService(request.state.db)
    current_user = request.state.user
    return service.map_permission_bulk(
        file, current_user["user_id"], request=request, current_user=current_user
    )


# -------------------------------------------------------
# Unmap permission from access point
# -------------------------------------------------------
@router.delete("/{access_uuid}/unmap-permission/{permission_uuid}")
def unmap_permission(access_uuid: str, permission_uuid: str, request: Request):
    service = AccessPointService(request.state.db)
    return service.unmap_permission_both(
        access_uuid, permission_uuid, request=request, current_user=request.state.user
    )


# -------------------------------------------------------
# New way: map permission using body input
# -------------------------------------------------------
@router.post("/{access_uuid}/map-permission")
def map_permission_new(access_uuid: str, data: PermissionMappingIn, request: Request):
    service = AccessPointService(request.state.db)
    current_user = request.state.user
    return service.map_permission(
        access_uuid,
        data.permission_uuid,
        current_user["user_id"],
        request=request,
        current_user=current_user,
    )
