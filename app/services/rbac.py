from fastapi import HTTPException

from app.repositories.permission import PermissionRepository
from app.repositories.role import RoleRepository
from app.schemas.permission import PermissionCreate, PermissionModel, PermissionResponse
from app.schemas.role import RoleCreate, RoleModel, RoleResponse


class RBACService:
    def __init__(self, role_repo: RoleRepository, perm_repo: PermissionRepository):
        self.role_repo = role_repo
        self.perm_repo = perm_repo

    async def create_permission(self, app_id: str, perm_in: PermissionCreate) -> PermissionResponse:
        existing = await self.perm_repo.get_by_name(app_id, perm_in.name)
        if existing:
            raise HTTPException(status_code=400, detail="Permission already exists")
            
        perm_data = PermissionModel(
            app_id=app_id,
            name=perm_in.name,
            description=perm_in.description
        ).model_dump()
        
        created = await self.perm_repo.create(perm_data)
        return PermissionResponse(**created)

    async def get_permissions(self, app_id: str) -> list[PermissionResponse]:
        perms = await self.perm_repo.get_by_app(app_id)
        return [PermissionResponse(**p) for p in perms]

    async def create_role(self, app_id: str, role_in: RoleCreate) -> RoleResponse:
        existing = await self.role_repo.get_by_name(app_id, role_in.name)
        if existing:
            raise HTTPException(status_code=400, detail="Role already exists")
            
        # Verify permissions exist
        if role_in.permissions:
            all_perms = await self.perm_repo.get_by_app(app_id)
            all_perm_names = {p["name"] for p in all_perms}
            for p in role_in.permissions:
                if p not in all_perm_names:
                    raise HTTPException(status_code=400, detail=f"Permission {p} does not exist")
            
        role_data = RoleModel(
            app_id=app_id,
            name=role_in.name,
            description=role_in.description,
            permissions=role_in.permissions
        ).model_dump()
        
        created = await self.role_repo.create(role_data)
        return RoleResponse(**created)

    async def get_roles(self, app_id: str) -> list[RoleResponse]:
        roles = await self.role_repo.get_by_app(app_id)
        return [RoleResponse(**r) for r in roles]
