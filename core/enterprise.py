"""Enterprise identity, tenancy, authorization, audit and SLO primitives."""
from __future__ import annotations
import json, os, time, uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set
import requests
from fastapi import HTTPException, Request
try:
    import jwt
except ImportError:
    jwt = None
ROLES={"viewer","analyst","admin","tenant_admin","api_only"}
ROLE_PERMISSIONS={"viewer":{"detection:read","case:read"},"analyst":{"detection:read","detection:run","case:read","case:write","export:write"},"api_only":{"detection:run","export:write"},"admin":{"*"},"tenant_admin":{"*"}}
@dataclass(frozen=True)
class Principal:
    subject:str; tenant_id:str; roles:Set[str]=field(default_factory=set); scopes:Set[str]=field(default_factory=set); claims:Dict[str,Any]=field(default_factory=dict)
    def can(self,p:str)->bool: return "*" in self.scopes or any(p in ROLE_PERMISSIONS.get(r,set()) or "*" in ROLE_PERMISSIONS.get(r,set()) for r in self.roles)
class OIDCValidator:
    def __init__(self): self.issuer=os.getenv("THREATFADE_OIDC_ISSUER","").rstrip("/"); self.audience=os.getenv("THREATFADE_OIDC_AUDIENCE",""); self.jwks_url=os.getenv("THREATFADE_OIDC_JWKS_URL",""); self._jwks=None; self._jwks_at=0.0
    @property
    def configured(self): return bool(self.issuer and self.audience and (self.jwks_url or self.issuer))
    def _load_jwks(self):
        if self._jwks and time.monotonic()-self._jwks_at<300:return self._jwks
        r=requests.get(self.jwks_url or f"{self.issuer}/.well-known/jwks.json",timeout=5); r.raise_for_status(); self._jwks=r.json(); self._jwks_at=time.monotonic(); return self._jwks
    def validate(self,token):
        if not self.configured: raise HTTPException(503,"OIDC is not configured")
        if jwt is None: raise HTTPException(503,"PyJWT is required for OIDC authentication")
        try:
            kid=jwt.get_unverified_header(token).get("kid"); key=next((k for k in self._load_jwks().get("keys",[]) if k.get("kid")==kid),None)
            if not key: self._jwks=None; key=next((k for k in self._load_jwks().get("keys",[]) if k.get("kid")==kid),None)
            if not key: raise ValueError("unknown signing key")
            pub=jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key)); claims=jwt.decode(token,pub,algorithms=["RS256","RS384","RS512"],audience=self.audience,issuer=self.issuer,options={"require":["exp","iat","sub"]})
        except Exception as exc: raise HTTPException(401,"Invalid OIDC access token") from exc
        roles=(set(claims.get("roles",[]))|set(claims.get("https://tinlance.com/roles",[])))&ROLES; scopes=set(str(claims.get("scope","")).split()); tenant=claims.get("tenant_id") or claims.get("https://tinlance.com/tenant_id")
        if not tenant: raise HTTPException(403,"Token has no tenant_id claim")
        return Principal(str(claims["sub"]),str(tenant),roles,scopes,claims)
OIDC=OIDCValidator()
def authenticate(request:Request,api_key:Optional[str]=None)->Principal:
    auth=request.headers.get("Authorization","")
    if auth.startswith("Bearer "): return OIDC.validate(auth[7:].strip())
    if os.getenv("THREATFADE_ENV","development").lower()!="production":
        configured=os.getenv("THREATFADE_API_KEY")
        if configured and api_key==configured:return Principal("api-key",request.headers.get("X-Tenant-ID","local"),{"api_only"})
        return Principal("local-development",request.headers.get("X-Tenant-ID","local"),{"admin"})
    raise HTTPException(401,"Bearer OIDC token required in production")
def authorize(p:Principal,permission:str):
    if not p.can(permission):raise HTTPException(403,"Insufficient permissions")
def require_tenant(p:Principal,tenant_id:Optional[str])->str:
    requested=tenant_id or p.tenant_id
    if requested!=p.tenant_id and "admin" not in p.roles and "tenant_admin" not in p.roles:raise HTTPException(403,"Cross-tenant access denied")
    return requested
class AuditLogger:
    def __init__(self,path:Optional[str]=None): self.path=path or os.getenv("THREATFADE_AUDIT_PATH","reports/audit/audit.jsonl"); os.makedirs(os.path.dirname(self.path),exist_ok=True)
    def record(self,action,p:Principal,request:Optional[Request]=None,metadata:Optional[Dict[str,Any]]=None):
        event={"event_id":str(uuid.uuid4()),"timestamp":datetime.now(timezone.utc).isoformat(),"action":action,"subject":p.subject,"tenant_id":p.tenant_id,"roles":sorted(p.roles),"request_id":request.headers.get("X-Request-ID") if request else None,"source_ip":request.client.host if request and request.client else None,"metadata":metadata or {}}
        with open(self.path,"a",encoding="utf-8") as h:h.write(json.dumps(event,sort_keys=True)+"\n")
AUDIT=AuditLogger()
def slo_targets(): return {"api_availability":os.getenv("THREATFADE_SLO_API_AVAILABILITY","99.9%"),"p95_detection_latency":os.getenv("THREATFADE_SLO_P95_DETECTION_LATENCY","<2s"),"p99_detection_latency":os.getenv("THREATFADE_SLO_P99_DETECTION_LATENCY","<5s"),"recovery_time_objective":os.getenv("THREATFADE_SLO_RTO","<60m"),"recovery_point_objective":os.getenv("THREATFADE_SLO_RPO","<15m")}
