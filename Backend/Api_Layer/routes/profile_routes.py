from fastapi import APIRouter, Depends, Query
from ..interfaces.general_user import EditProfile, EditProfileHr
from ..JWT.jwt_validator.auth.dependencies import get_current_user
from ...Business_Layer.services.profile_service import ProfileService
from ...Business_Layer.utils.permission_check import permission_required

router = APIRouter()
service = ProfileService()

@router.get("/profile")
def get_profile(
    current_user: dict = Depends(get_current_user),
):
    return service.get_profile(current_user)

@router.put("/profile")
def update_profile(
    profile: EditProfile,
    current_user: dict = Depends(get_current_user),
):
    return service.update_profile(profile, current_user)

@router.get("/search")
def search_users(
    query: str = Query(..., description="Search by name, email, or contact"),
    current_user: dict = Depends(get_current_user),
):
    return service.search_users(query, current_user)

@router.get("/search/suggestions")
def user_search_suggestions(
    query: str = Query(..., min_length=1),
    current_user: dict = Depends(get_current_user),
):
    return service.user_search_suggestions(query, current_user)

@router.get("/edit-user/{user_id}")
def get_user_by_id(
    user_id: int,
    current_user: dict = Depends(get_current_user),
):
    return service.get_user_by_id(user_id, current_user)

@router.put("/edit-user/{user_id}")
def update_user_by_id(
    user_id: int,
    profile: EditProfileHr,
    current_user: dict = Depends(get_current_user),
):
    return service.update_user_by_id(user_id, profile, current_user)
