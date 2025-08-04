from fastapi import APIRouter,HTTPException
from fastapi.responses import RedirectResponse
from ..interfaces.auth import RegisterUser, LoginUser, ForgotPassword
from ...Business_Layer.services.auth_service import AuthService
from ...config.env_loader import get_env_var


router = APIRouter()

# Instantiate service per request (no shared singleton)
# If needed, can cache in future
auth_service = AuthService()

@router.post("/register")
def register(user_data: RegisterUser):
    return auth_service.register_user(user_data)


@router.post("/login")
def login(credentials: LoginUser):
    return auth_service.login_user(credentials)

@router.get("/ms-login")
def ms_login():
    client_id = get_env_var("CLIENT_ID")
    tenant_id = get_env_var("TENANT_ID")
    redirect_uri = get_env_var("REDIRECT_URI")
    state = get_env_var("SESSION_SECRET")
 
    microsoft_auth_url = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        f"?client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid profile email offline_access"
        f"&response_mode=query"
        f"&state={state}"
    )
   
 
    return RedirectResponse(url=microsoft_auth_url)
 
used_codes = set()
 
@router.get("/callback")
def handle_microsoft_callback(code: str):
    try:
        print("Received code:", code)
        return auth_service.handle_microsoft_callback(code)
    except HTTPException as http_exc:
        print("HTTPException:", http_exc.status_code, http_exc.detail)
        raise http_exc
    except Exception as e:
        import traceback
        print("Unhandled Exception:", str(e))
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="OAuth callback failed unexpectedly")

@router.get("/forgot-password/{email}")
def check_user_status(email: str):
    return auth_service.check_user_exists(email)


@router.post("/forgot-password")
def forgot_password(update: ForgotPassword):
    return auth_service.forgot_password(update)
