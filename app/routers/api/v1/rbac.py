from fastapi import APIRouter, Depends

from app.dependencies import get_rbac_service, verify_app
from app.schemas.permission import PermissionCreate, PermissionResponse
from app.schemas.role import RoleCreate, RoleResponse
from app.services.rbac import RBACService

router = APIRouter(prefix="/rbac", tags=["rbac"])

@router.post("/permissions", response_model=PermissionResponse)
async def create_permission(
    perm_in: PermissionCreate,
    app_id: str = Depends(verify_app),
    service: RBACService = Depends(get_rbac_service)
):
    return await service.create_permission(app_id, perm_in)

@router.get("/permissions", response_model=list[PermissionResponse])
async def list_permissions(
    app_id: str = Depends(verify_app),
    service: RBACService = Depends(get_rbac_service)
):
    return await service.get_permissions(app_id)

@router.post("/roles", response_model=RoleResponse)
async def create_role(
    role_in: RoleCreate,
    app_id: str = Depends(verify_app),
    service: RBACService = Depends(get_rbac_service)
):
    return await service.create_role(app_id, role_in)

@router.get("/roles", response_model=list[RoleResponse])
async def list_roles(
    app_id: str = Depends(verify_app),
    service: RBACService = Depends(get_rbac_service)
):
    return await service.get_roles(app_id)
