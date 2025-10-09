"""
Audit Trail Decorator for FastAPI/SQLAlchemy Applications
Place this in: Business_Layer/utils/audit_decorator.py
"""

from functools import wraps
from typing import Callable, Optional, Any, Dict
from sqlalchemy.orm import Session
from datetime import datetime
import json
import inspect
from ...Data_Access_Layer.models import models
from ...Business_Layer.utils.generate_uuid7 import generate_uuid7


def audit_action(
    action_type: str,
    entity_type: str,
    get_entity_id: Optional[Callable] = None,
    capture_old_data: bool = False,
    capture_new_data: bool = False,
    description: Optional[str] = None
):
    """
    Decorator to automatically log audit trail for CRUD operations.
    
    Args:
        action_type: One of 'CREATE', 'UPDATE', 'DELETE', 'ASSIGN_ROLE', 'OTHER'
        entity_type: Type of entity being modified (e.g., 'User', 'Role', 'Permission')
        get_entity_id: Optional function to extract entity_id from args/kwargs
        capture_old_data: Whether to capture state before modification
        capture_new_data: Whether to capture state after modification
        description: Optional custom description template (can use {field} placeholders)
    
    Usage:
        @audit_action('UPDATE', 'User', lambda *args, **kwargs: kwargs.get('user_id'))
        def update_user(self, user_id, user_schema):
            # Your logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get 'self' (service instance) and db session
            service_instance = args[0] if args else None
            db: Session = service_instance.db if service_instance and hasattr(service_instance, 'db') else None
            
            if not db:
                # If no DB session, just execute function without audit
                return func(*args, **kwargs)
            
            # Extract user_id from current_user (typically passed in kwargs or args)
            user_id = _extract_user_id(*args, **kwargs)
            
            # Extract entity_id if function provided
            entity_id = None
            if get_entity_id:
                try:
                    entity_id = get_entity_id(*args, **kwargs)
                except Exception:
                    pass
            
            # Capture old data if needed
            old_data = None
            if capture_old_data and entity_id:
                old_data = _capture_entity_state(db, entity_type, entity_id)
            
            # Execute the actual function
            result = func(*args, **kwargs)
            
            # Capture new data if needed
            new_data = None
            if capture_new_data:
                if entity_id:
                    new_data = _capture_entity_state(db, entity_type, entity_id)
                elif hasattr(result, '__dict__'):
                    # If result is a new entity, capture its state
                    new_data = _serialize_entity(result)
                    if hasattr(result, f"{entity_type.lower()}_id"):
                        entity_id = getattr(result, f"{entity_type.lower()}_id")
            
            # Generate description
            final_description = description
            if description and '{' in description:
                # Replace placeholders with actual values
                final_description = description.format(**kwargs)
            elif not description:
                final_description = f"{action_type} operation on {entity_type}"
            
            # Create audit log entry
            try:
                audit_entry = models.AuditTrail(
                    audit_uuid=generate_uuid7(),
                    user_id=user_id,
                    action_type=action_type,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    old_data=old_data,
                    new_data=new_data,
                    ip_address=_get_ip_address(*args, **kwargs),
                    description=final_description,
                    created_at=datetime.utcnow()
                )
                db.add(audit_entry)
                db.commit()
            except Exception as e:
                # Log error but don't break the flow
                print(f"Audit logging failed: {e}")
                db.rollback()
            
            return result
        
        return wrapper
    return decorator


def _extract_user_id(*args, **kwargs) -> Optional[int]:
    """Extract user_id from function arguments."""
    # Check kwargs for common patterns
    for key in ['current_user', 'user_info', 'auth_user']:
        if key in kwargs:
            user_data = kwargs[key]
            if isinstance(user_data, dict):
                return user_data.get('user_id')
            elif hasattr(user_data, 'user_id'):
                return user_data.user_id
    
    # Check for explicit user_id in kwargs
    if 'created_by_user_id' in kwargs:
        return kwargs['created_by_user_id']
    if 'updated_by_user_id' in kwargs:
        return kwargs['updated_by_user_id']
    
    return None


def _get_ip_address(*args, **kwargs) -> Optional[str]:
    """Extract IP address from request context if available."""
    # In FastAPI, you can inject request and pass it
    if 'request' in kwargs:
        request = kwargs['request']
        if hasattr(request, 'client') and request.client:
            return request.client.host
    return None


def _capture_entity_state(db: Session, entity_type: str, entity_id: int) -> Optional[Dict]:
    """Capture current state of an entity."""
    try:
        # Map entity_type to model class
        model_class = getattr(models, entity_type, None)
        if not model_class:
            return None
        
        entity = db.query(model_class).filter_by(**{f"{entity_type.lower()}_id": entity_id}).first()
        if entity:
            return _serialize_entity(entity)
    except Exception as e:
        print(f"Failed to capture entity state: {e}")
    return None


def _serialize_entity(entity) -> Dict[str, Any]:
    """Convert SQLAlchemy model to JSON-serializable dict."""
    if not entity:
        return None
    
    result = {}
    for column in entity.__table__.columns:
        value = getattr(entity, column.name)
        
        # Handle non-serializable types
        if isinstance(value, datetime):
            result[column.name] = value.isoformat()
        elif isinstance(value, (str, int, float, bool, type(None))):
            result[column.name] = value
        else:
            result[column.name] = str(value)
    
    return result


# ===== ENHANCED VERSION WITH REQUEST CONTEXT =====

def audit_action_with_request(
    action_type: str,
    entity_type: str,
    get_entity_id: Optional[Callable] = None,
    capture_old_data: bool = False,
    capture_new_data: bool = False,
    description: Optional[str] = None
):
    """
    Enhanced version that captures request context (IP, user agent, etc.)
    
    Usage in FastAPI routes:
        @router.put("/{user_id}")
        def update_user(
            user_id: int,
            user: UserBaseIn,
            request: Request,  # Add this
            current_user: dict = Depends(get_current_user),
            user_service: UserService = Depends(get_user_service)
        ):
            return user_service.update_user(
                user_id, user, 
                current_user=current_user, 
                request=request  # Pass it
            )
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            service_instance = args[0] if args else None
            db: Session = service_instance.db if service_instance and hasattr(service_instance, 'db') else None
            
            if not db:
                return func(*args, **kwargs)
            
            # Extract context
            user_id = _extract_user_id(*args, **kwargs)
            ip_address = _get_ip_address(*args, **kwargs)
            entity_id = get_entity_id(*args, **kwargs) if get_entity_id else None
            
            # Capture old state
            old_data = None
            if capture_old_data and entity_id:
                old_data = _capture_entity_state(db, entity_type, entity_id)
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Capture new state
            new_data = None
            if capture_new_data:
                if entity_id:
                    new_data = _capture_entity_state(db, entity_type, entity_id)
                elif hasattr(result, '__dict__'):
                    new_data = _serialize_entity(result)
                    id_field = f"{entity_type.lower()}_id"
                    if hasattr(result, id_field):
                        entity_id = getattr(result, id_field)
            
            # Build description
            final_description = _build_description(
                description, action_type, entity_type, old_data, new_data, kwargs
            )
            
            # Log audit
            _log_audit(
                db, user_id, action_type, entity_type, entity_id,
                old_data, new_data, ip_address, final_description
            )
            
            return result
        
        return wrapper
    return decorator


def _build_description(
    template: Optional[str],
    action_type: str,
    entity_type: str,
    old_data: Optional[Dict],
    new_data: Optional[Dict],
    kwargs: Dict
) -> str:
    """Build intelligent description based on changes."""
    if template:
        try:
            return template.format(**kwargs)
        except KeyError:
            pass
    
    # Auto-generate description based on changes
    if action_type == 'UPDATE' and old_data and new_data:
        changes = []
        for key, new_val in new_data.items():
            old_val = old_data.get(key)
            if old_val != new_val and key not in ['updated_at', 'password']:
                if key == 'password':
                    changes.append("password")
                else:
                    changes.append(f"{key}: '{old_val}' → '{new_val}'")
        
        if changes:
            return f"Updated {entity_type}: {', '.join(changes[:5])}"
    
    return f"{action_type} operation on {entity_type}"


def _log_audit(
    db: Session,
    user_id: Optional[int],
    action_type: str,
    entity_type: str,
    entity_id: Optional[int],
    old_data: Optional[Dict],
    new_data: Optional[Dict],
    ip_address: Optional[str],
    description: str
):
    """Create and persist audit log entry."""
    try:
        audit_entry = models.AuditTrail(
            audit_uuid=generate_uuid7(),
            user_id=user_id,
            action_type=action_type,
            entity_type=entity_type,
            entity_id=entity_id,
            old_data=old_data,
            new_data=new_data,
            ip_address=ip_address,
            description=description,
            created_at=datetime.utcnow()
        )
        db.add(audit_entry)
        db.commit()
    except Exception as e:
        print(f"Audit logging failed: {e}")
        db.rollback()