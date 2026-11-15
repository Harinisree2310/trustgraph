
from __future__ import annotations
import csv, io, json, os, re, uuid, zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
import requests

app = FastAPI(title="TrustGraph API", version="1.0.0",
              description="Third-party software trust and supply-chain risk intelligence prototype")
_extra_origins = [x.strip() for x in os.getenv("TRUSTGRAPH_ALLOWED_ORIGINS", "").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", *_extra_origins],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

# Demo advisories are intentionally synthetic and clearly labelled. They demonstrate
# the workflow without pretending to be a live vulnerability feed.
DEMO_ADVISORIES = [
    {"id":"TG-DEMO-001","package":"log4j-core","ecosystem":"Maven","affected":"2.0–2.14.1",
     "severity":"Critical","cvss":10.0,"summary":"Simulated remote-code-execution exposure in a logging component.",
     "fixed":"2.17.1","source":"TrustGraph demo intelligence","demo":True},
    {"id":"TG-DEMO-002","package":"lodash","ecosystem":"npm","affected":"<4.17.21",
     "severity":"High","cvss":7.4,"summary":"Simulated prototype-pollution exposure in a utility dependency.",
     "fixed":"4.17.21","source":"TrustGraph demo intelligence","demo":True},
    {"id":"TG-DEMO-003","package":"requests","ecosystem":"PyPI","affected":"<2.31.0",
     "severity":"Medium","cvss":5.3,"summary":"Simulated redirect and credential-handling weakness.",
     "fixed":"2.31.0","source":"TrustGraph demo intelligence","demo":True},
    {"id":"TG-DEMO-004","package":"axios","ecosystem":"npm","affected":"<1.6.0",
     "severity":"High","cvss":7.2,"summary":"Simulated server-side request handling weakness.",
     "fixed":"1.6.0","source":"TrustGraph demo intelligence","demo":True},
    {"id":"TG-DEMO-005","package":"minimist","ecosystem":"npm","affected":"<1.2.6",
     "severity":"High","cvss":7.5,"summary":"Simulated prototype-pollution exposure in argument parsing.",
     "fixed":"1.2.6","source":"TrustGraph demo intelligence","demo":True},
    {"id":"TG-DEMO-006","package":"urllib3","ecosystem":"PyPI","affected":"<2.0.7",
     "severity":"Medium","cvss":6.1,"summary":"Simulated request handling weakness in an HTTP client.",
     "fixed":"2.0.7","source":"TrustGraph demo intelligence","demo":True},
]

def now():
    return datetime.now(timezone.utc).isoformat()

def item(id, name, version, ecosystem, direct, app_name, business, criticality, exposure, license_name="MIT", latest=None, deps=None):
    return {"id":id,"name":name,"version":version,"ecosystem":ecosystem,"direct":direct,
            "application":app_name,"business_service":business,"criticality":criticality,
            "exposure":exposure,"license":license_name,"latest":latest or version,
            "dependencies":deps or [],"source":"Seeded demonstration inventory"}

def seed_inventory():
    return [
      item("pkg-001","log4j-core","2.14.1","Maven",False,"Order API","Order processing","Critical","Internet-facing","Apache-2.0","2.23.1",["pkg-002"]),
      item("pkg-002","spring-boot","2.7.8","Maven",True,"Order API","Order processing","Critical","Internet-facing","Apache-2.0","3.3.0",["pkg-003"]),
      item("pkg-003","jackson-databind","2.13.4","Maven",False,"Order API","Order processing","Critical","Internet-facing","Apache-2.0","2.17.1"),
      item("pkg-004","lodash","4.17.19","npm",True,"Customer Portal","Customer identity","High","Internet-facing","MIT","4.17.21",["pkg-005"]),
      item("pkg-005","axios","0.21.1","npm",False,"Customer Portal","Customer identity","High","Internet-facing","MIT","1.7.9"),
      item("pkg-006","react","18.2.0","npm",True,"Customer Portal","Customer identity","High","Internet-facing","MIT","18.3.1"),
      item("pkg-007","requests","2.28.0","PyPI",True,"Risk Engine","Fraud analytics","Critical","Internal","Apache-2.0","2.32.3"),
      item("pkg-008","urllib3","1.26.5","PyPI",False,"Risk Engine","Fraud analytics","Critical","Internal","MIT","2.2.3"),
      item("pkg-009","pandas","2.1.0","PyPI",True,"Risk Engine","Fraud analytics","Critical","Internal","BSD-3-Clause","2.2.3"),
      item("pkg-010","fastapi","0.110.0","PyPI",True,"Partner Gateway","Partner integrations","High","Internet-facing","MIT","0.115.6"),
      item("pkg-011","pydantic","2.7.0","PyPI",False,"Partner Gateway","Partner integrations","High","Internet-facing","MIT","2.10.4"),
      item("pkg-012","minimist","1.2.5","npm",False,"Build Pipeline","Software delivery","Medium","Build-time","MIT","1.2.8"),
      item("pkg-013","vite","5.2.0","npm",True,"Build Pipeline","Software delivery","Medium","Build-time","MIT","6.0.1"),
      item("pkg-014","openssl","3.0.8","System",True,"Core Platform","Platform security","Critical","Internal","Apache-2.0","3.4.0"),
      item("pkg-015","zlib","1.2.13","System",False,"Core Platform","Platform security","Critical","Internal","Zlib","1.3.1"),
      item("pkg-016","dayjs","1.11.10","npm",True,"Customer Portal","Customer identity","High","Internet-facing","MIT","1.11.13"),
      item("pkg-017","legacy-logging-adapter","1.4.0","Maven",False,"Billing Worker","Payment settlement","Critical","Internet-facing","Apache-2.0","1.6.2",["pkg-001"]),
    ]

inventory = []
findings = []
actions = {}
workspace_mode = "live"
scan_meta = {"last_scan": None, "source":"No inventory imported yet", "scanned_files":0}

def version_tuple(v: str):
    nums = re.findall(r"\d+", str(v))
    return tuple(int(x) for x in nums[:4]) if nums else (0,)

def is_affected(package, version, advisory):
    if package.lower() != advisory["package"].lower():
        return False
    # Demo catalogue ranges are simple less-than thresholds.
    match = re.search(r"<\s*([0-9.]+)", advisory["affected"])
    if match:
        return version_tuple(version) < version_tuple(match.group(1))
    # Explicit inclusive ranges in the synthetic demo catalogue, e.g. 2.0–2.14.1.
    range_match = re.search(r"([0-9.]+)\s*[–-]\s*([0-9.]+)", advisory["affected"])
    if range_match:
        return version_tuple(range_match.group(1)) <= version_tuple(version) <= version_tuple(range_match.group(2))
    return version == advisory["affected"]

def findings_for(items):
    out = []
    for p in items:
        for adv in DEMO_ADVISORIES:
            if is_affected(p["name"], p["version"], adv):
                severity = adv["severity"]
                sev_weight = {"Critical":40,"High":30,"Medium":18,"Low":8}.get(severity,10)
                criticality_weight = {"Critical":25,"High":18,"Medium":10,"Low":4}.get(p["criticality"],8)
                exposure_weight = {"Internet-facing":20,"Internal":10,"Build-time":6}.get(p["exposure"],5)
                direct_weight = 5 if p["direct"] else 0
                score = min(100, round(sev_weight + criticality_weight + exposure_weight + direct_weight + adv["cvss"]*0.5))
                priority = "P0" if score >= 85 else "P1" if score >= 70 else "P2" if score >= 50 else "P3"
                out.append({
                    "id":f"finding-{p['id']}-{adv['id']}", "package_id":p["id"],
                    "package":p["name"],"version":p["version"],"application":p["application"],
                    "business_service":p["business_service"],"severity":severity,
                    "cvss":adv["cvss"],"risk_score":score,"priority":priority,
                    "advisory_id":adv["id"],"summary":adv["summary"],"fixed":adv["fixed"],
                    "ecosystem":p["ecosystem"],"exposure":p["exposure"],
                    "criticality":p["criticality"],"direct":p["direct"],
                    "source":adv["source"],"demo_intelligence":True,
                    "recommendation":f"Upgrade {p['name']} to {adv['fixed']} or later, run regression tests, then redeploy the affected application."
                })
    return sorted(out, key=lambda x:(-x["risk_score"], x["package"]))

findings = findings_for(inventory)

def overview():
    critical = sum(1 for f in findings if f["severity"]=="Critical")
    high = sum(1 for f in findings if f["severity"]=="High")
    affected_apps = len(set(f["application"] for f in findings))
    return {
      "packages":len(inventory),"direct":sum(1 for p in inventory if p["direct"]),
      "transitive":sum(1 for p in inventory if not p["direct"]),
      "findings":len(findings),"critical":critical,"high":high,
      "affected_apps":affected_apps,
      "risk_score":round(sum(f["risk_score"] for f in findings)/max(1,len(findings))),
      "last_scan":scan_meta["last_scan"],"scan_source":scan_meta["source"],"mode":workspace_mode,"data_source":scan_meta["source"]
    }

@app.get("/api/health")
def health():
    return {"status":"ok","service":"TrustGraph API","version":"1.0.0","time":now()}

@app.get("/api/overview")
def get_overview():
    return overview()

@app.get("/api/inventory")
def get_inventory():
    return {"items":inventory,"count":len(inventory)}

@app.get("/api/findings")
def get_findings():
    return {"items":findings,"count":len(findings)}

@app.get("/api/graph")
def get_graph():
    nodes = []
    edges = []
    apps = {}
    for p in inventory:
        app_id = "app-" + re.sub(r"[^a-z0-9]+","-",p["application"].lower()).strip("-")
        if app_id not in apps:
            apps[app_id] = {"id":app_id,"label":p["application"],"type":"application","service":p["business_service"]}
        nodes.append({"id":p["id"],"label":p["name"],"type":"package","version":p["version"],
                      "risk":next((f["priority"] for f in findings if f["package_id"]==p["id"]), "Clear")})
        edges.append({"source":app_id,"target":p["id"]})
        for dep in p["dependencies"]:
            edges.append({"source":p["id"],"target":dep})
    nodes = list(apps.values()) + nodes
    return {"nodes":nodes,"edges":edges}

@app.get("/api/actions")
def get_actions():
    return {"items":list(actions.values())}

class ActionUpdate(BaseModel):
    status: str

@app.patch("/api/actions/{finding_id}")
def update_action(finding_id: str, body: ActionUpdate):
    if body.status not in ["Open","In progress","Resolved","Accepted risk"]:
        raise HTTPException(400, "Unsupported status")
    f = next((x for x in findings if x["id"]==finding_id), None)
    if not f:
        raise HTTPException(404, "Finding not found")
    current = actions.get(finding_id, {"finding_id":finding_id,"status":"Open","owner":"Unassigned","updated_at":now()})
    current.update({"status":body.status,"updated_at":now()})
    actions[finding_id] = current
    return current

def parse_package_json(data: dict):
    result = []
    # package-lock v2/v3: packages map, package-lock v1: dependencies tree
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict): continue
            name = meta.get("name") or path.split("node_modules/")[-1]
            if not name or name == path: continue
            result.append({"name":name,"version":str(meta.get("version","unknown")),"ecosystem":"npm",
                           "direct":path.count("node_modules/") <= 1})
    def walk(deps, direct=True):
        if not isinstance(deps, dict): return
        for name, meta in deps.items():
            if not isinstance(meta, dict): continue
            result.append({"name":name,"version":str(meta.get("version","unknown")),"ecosystem":"npm","direct":direct})
            walk(meta.get("dependencies",{}), False)
    if not result:
        walk(data.get("dependencies",{}), True)
    return result

def parse_upload(filename: str, raw: bytes):
    ext = filename.lower()
    result = []
    if ext.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                for name in z.namelist():
                    if name.endswith("package-lock.json") or name.endswith("npm-shrinkwrap.json"):
                        result += parse_package_json(json.loads(z.read(name)))
                    elif name.endswith("requirements.txt"):
                        result += parse_requirements(z.read(name).decode("utf-8","ignore"))
                    elif name.endswith("package.json"):
                        result += parse_package_manifest(json.loads(z.read(name)))
                    elif name.endswith("bom.json") or name.endswith("cyclonedx.json"):
                        result += parse_cyclonedx(json.loads(z.read(name)))
        except zipfile.BadZipFile:
            raise HTTPException(400,"The uploaded ZIP file could not be opened.")
    elif ext.endswith(".json"):
        try: data=json.loads(raw.decode("utf-8"))
        except Exception: raise HTTPException(400,"Invalid JSON file.")
        if "components" in data: result=parse_cyclonedx(data)
        elif "lockfileVersion" in data or "packages" in data: result=parse_package_json(data)
        else: result=parse_package_manifest(data)
    elif ext.endswith(".txt"):
        result=parse_requirements(raw.decode("utf-8","ignore"))
    else:
        raise HTTPException(400,"Supported inputs: .zip, package-lock.json, package.json, requirements.txt, CycloneDX bom.json")
    # Deduplicate by ecosystem/name/version.
    seen=set(); clean=[]
    for x in result:
        key=(x["ecosystem"],x["name"].lower(),x["version"])
        if key not in seen:
            seen.add(key); clean.append(x)
    if not clean:
        raise HTTPException(400,"No supported dependencies were found in the uploaded file.")
    return clean

def parse_requirements(text):
    out=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith("#") or line.startswith("-"): continue
        m=re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)\s*([A-Za-z0-9_.+-]+)",line)
        if m: out.append({"name":m.group(1),"version":m.group(2),"ecosystem":"PyPI","direct":True})
    return out

def parse_package_manifest(data):
    out=[]
    for group in ["dependencies","devDependencies","optionalDependencies"]:
        for name, ver in (data.get(group,{}) or {}).items():
            out.append({"name":name,"version":str(ver).lstrip("^~"),"ecosystem":"npm","direct":True})
    return out

def parse_cyclonedx(data):
    out=[]
    for c in data.get("components",[]):
        purl=c.get("purl","")
        name=c.get("name")
        version=c.get("version","unknown")
        ecosystem="Unknown"
        if purl.startswith("pkg:npm/"): ecosystem="npm"
        elif purl.startswith("pkg:pypi/"): ecosystem="PyPI"
        elif purl.startswith("pkg:maven/"): ecosystem="Maven"
        if name: out.append({"name":name,"version":version,"ecosystem":ecosystem,"direct":True})
    return out

@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    global inventory, findings, scan_meta
    raw=await file.read()
    parsed=parse_upload(file.filename or "upload",raw)
    new=[]
    for idx,p in enumerate(parsed,1):
        old=next((x for x in inventory if x["name"].lower()==p["name"].lower() and x["ecosystem"]==p["ecosystem"]),None)
        new.append({
          "id":f"upload-{idx:03d}-{uuid.uuid4().hex[:5]}","name":p["name"],"version":p["version"],
          "ecosystem":p["ecosystem"],"direct":p["direct"],"application":"Uploaded application",
          "business_service":"Unclassified service","criticality":"Medium","exposure":"Unknown",
          "license":"Unknown","latest":p["version"],"dependencies":[],
          "source":"Uploaded dependency manifest"
        })
    inventory=new
    findings=[]
    workspace_mode="live"
    actions.clear()
    scan_meta={"last_scan":now(),"source":file.filename or "Uploaded file","scanned_files":1}
    return {"overview":overview(),"inventory_count":len(inventory),"findings":[],
            "message":f"Imported {len(inventory)} dependency records from {file.filename}. Run a live OSV scan to check published advisories."}

@app.post("/api/demo/reset")
def reset_demo():
    global inventory, findings, scan_meta, workspace_mode
    inventory=seed_inventory()
    findings=findings_for(inventory)
    workspace_mode="simulation"
    actions.clear()
    scan_meta={"last_scan":now(),"source":"Seeded TrustGraph simulation inventory","scanned_files":12}
    return {"overview":overview(),"message":"Simulation workspace loaded. Built-in advisory matches are synthetic."}

@app.post("/api/live/reset")
def reset_live():
    global inventory, findings, scan_meta, workspace_mode
    inventory=[]
    findings=[]
    workspace_mode="live"
    actions.clear()
    scan_meta={"last_scan":None,"source":"No inventory imported yet","scanned_files":0}
    return {"overview":overview(),"message":"Live workspace ready. Import a dependency inventory to begin."}

def _osv_severity(vuln):
    candidates=[(vuln.get("database_specific") or {}).get("severity"),
                (vuln.get("ecosystem_specific") or {}).get("severity")]
    for value in candidates:
        if isinstance(value,str) and value.strip().title() in {"Critical","High","Medium","Low"}:
            return value.strip().title()
    return "Unknown"

def _osv_fixed_version(vuln, package_name, ecosystem):
    for affected in vuln.get("affected",[]):
        pkg=affected.get("package") or {}
        if pkg.get("name","").lower()!=package_name.lower() or pkg.get("ecosystem","").lower()!=ecosystem.lower():
            continue
        for version_range in affected.get("ranges",[]):
            for event in version_range.get("events",[]):
                if event.get("fixed"):
                    return str(event["fixed"])
    return None

def _osv_risk_finding(component, vuln):
    severity=_osv_severity(vuln)
    sev_weight={"Critical":40,"High":30,"Medium":18,"Low":8,"Unknown":12}[severity]
    criticality_weight={"Critical":25,"High":18,"Medium":10,"Low":4}.get(component.get("criticality"),8)
    exposure_weight={"Internet-facing":20,"Internal":10,"Build-time":6}.get(component.get("exposure"),5)
    direct_weight=5 if component.get("direct") else 0
    score=min(100,round(sev_weight+criticality_weight+exposure_weight+direct_weight))
    priority="P0" if score>=85 else "P1" if score>=70 else "P2" if score>=50 else "P3"
    advisory_id=vuln.get("id") or "OSV-UNKNOWN"
    fixed=_osv_fixed_version(vuln,component["name"],component["ecosystem"])
    refs=[x.get("url") for x in vuln.get("references",[]) if x.get("url")]
    vector=next((x.get("score") for x in vuln.get("severity",[]) if x.get("type","").startswith("CVSS")),None)
    summary=vuln.get("summary") or vuln.get("details") or "OSV advisory matched this package version."
    recommendation=(f"Upgrade {component['name']} to {fixed} or later, run regression tests, then redeploy the affected application."
                    if fixed else f"Review {advisory_id} and upstream affected-version guidance before selecting an upgrade.")
    return {
      "id":f"osv-{component['id']}-{advisory_id}","package_id":component["id"],
      "package":component["name"],"version":component["version"],"application":component["application"],
      "business_service":component["business_service"],"severity":severity,"cvss":None,
      "cvss_vector":vector,"risk_score":score,"priority":priority,"advisory_id":advisory_id,
      "summary":summary,"fixed":fixed or "Check upstream advisory","ecosystem":component["ecosystem"],
      "exposure":component["exposure"],"criticality":component["criticality"],"direct":component["direct"],
      "source":"OSV.dev","source_url":f"https://osv.dev/vulnerability/{advisory_id}",
      "references":refs,"demo_intelligence":False,
      "recommendation":recommendation
    }

@app.post("/api/osv/check")
def osv_check():
    """Match imported package versions against published OSV.dev vulnerability records."""
    global findings, scan_meta, workspace_mode
    if not inventory:
        raise HTTPException(400,"Import a dependency inventory before running a live vulnerability scan.")
    ecosystem_map={"npm":"npm","PyPI":"PyPI","Maven":"Maven"}
    eligible=[p for p in inventory if ecosystem_map.get(p.get("ecosystem")) and p.get("version") not in {"","unknown","*"}]
    if not eligible:
        raise HTTPException(400,"No supported, versioned npm, PyPI or Maven components were found.")
    results=[]
    try:
        for offset in range(0,len(eligible),100):
            batch=eligible[offset:offset+100]
            queries=[{"package":{"name":p["name"],"ecosystem":ecosystem_map[p["ecosystem"]]},"version":p["version"]} for p in batch]
            response=requests.post("https://api.osv.dev/v1/querybatch",json={"queries":queries},timeout=25)
            response.raise_for_status()
            payload=response.json()
            for component, match in zip(batch,payload.get("results",[])):
                for vuln in match.get("vulns",[]):
                    results.append(_osv_risk_finding(component,vuln))
    except Exception as e:
        raise HTTPException(502,f"OSV.dev lookup failed. Inventory was retained; retry the live scan. Details: {str(e)[:160]}")
    findings=sorted(results,key=lambda x:(-x["risk_score"],x["package"],x["advisory_id"]))
    workspace_mode="live"
    actions.clear()
    scan_meta={"last_scan":now(),"source":"OSV.dev live vulnerability query","scanned_files":len(eligible)}
    return {"source":"OSV.dev","items":findings,"count":len(findings),"scanned_components":len(eligible),
            "unsupported_components":len(inventory)-len(eligible),"overview":overview(),
            "message":f"Checked {len(eligible)} package versions against OSV.dev; found {len(findings)} matching advisories."}

@app.get("/api/export/{fmt}")
def export_report(fmt: str):
    report={"generated_at":now(),"product":"TrustGraph","data_source":scan_meta["source"],
            "notice":"Demo advisory matches are synthetic unless a separate OSV live check is performed.",
            "overview":overview(),"inventory":inventory,"findings":findings,
            "remediation_actions":list(actions.values())}
    if fmt=="json":
        content=json.dumps(report,indent=2)
        return StreamingResponse(io.BytesIO(content.encode()),media_type="application/json",
          headers={"Content-Disposition":"attachment; filename=trustgraph-report.json"})
    if fmt=="csv":
        buf=io.StringIO()
        fields=["package","version","ecosystem","application","business_service","severity","risk_score","priority","advisory_id","fixed","recommendation"]
        writer=csv.DictWriter(buf,fieldnames=fields); writer.writeheader()
        for f in findings: writer.writerow({k:f.get(k,"") for k in fields})
        return StreamingResponse(io.BytesIO(buf.getvalue().encode()),media_type="text/csv",
          headers={"Content-Disposition":"attachment; filename=trustgraph-findings.csv"})
    raise HTTPException(400,"Format must be json or csv")

@app.get("/")
def root():
    return {"service":"TrustGraph API","docs":"/docs","health":"/api/health"}


# TrustGraph 2.0 incident-to-business-impact analysis.
# Inventory presence is evidence for triage, not proof of compromise or reachability.
class IncidentRequest(BaseModel):
    package: str
    ecosystem: str | None = None
    severity: str = "Critical"
    cvss: float = 9.8
    advisory_id: str | None = None
    fixed_version: str | None = None
    source_type: str = "reported_incident"

def _incident_assessment(payload: IncidentRequest):
    package_name = payload.package.strip()
    if not package_name:
        raise HTTPException(400, "Package name is required.")
    severity = payload.severity.title()
    if severity not in {"Critical", "High", "Medium", "Low"}:
        raise HTTPException(400, "Severity must be Critical, High, Medium or Low.")
    if not 0 <= payload.cvss <= 10:
        raise HTTPException(400, "CVSS must be between 0 and 10.")
    if payload.source_type not in {"reported_incident", "simulated_demo"}:
        raise HTTPException(400, "Unsupported source_type.")

    matched = [p for p in inventory if p["name"].lower() == package_name.lower()
               and (not payload.ecosystem or p["ecosystem"].lower() == payload.ecosystem.lower())]
    if not matched:
        raise HTTPException(404, f"{package_name} was not found in the current inventory.")

    impacted_ids = {p["id"] for p in matched}
    changed = True
    while changed:
        changed = False
        for component in inventory:
            if component["id"] not in impacted_ids and any(
                dep_id in impacted_ids for dep_id in component.get("dependencies", [])
            ):
                impacted_ids.add(component["id"])
                changed = True

    impacted = [p for p in inventory if p["id"] in impacted_ids]
    apps = {}
    for p in impacted:
        entry = apps.setdefault(p["application"], {
            "application": p["application"], "business_service": p["business_service"],
            "criticality": p["criticality"], "exposure": p["exposure"], "components": []
        })
        entry["components"].append({
            "name": p["name"], "version": p["version"], "ecosystem": p["ecosystem"],
            "dependency_type": "direct" if p["direct"] else "transitive",
            "evidence": p.get("source", "inventory")
        })

    severity_weight = {"Critical": 40, "High": 30, "Medium": 18, "Low": 8}[severity]
    criticality_weight = {"Critical": 20, "High": 14, "Medium": 8, "Low": 3}
    exposure_weight = {"Internet-facing": 15, "Internal": 8, "Build-time": 4}
    business_weight = max((criticality_weight.get(x["criticality"], 5) +
                           exposure_weight.get(x["exposure"], 3) for x in apps.values()), default=0)
    direct_bonus = 5 if any(p["direct"] for p in matched) else 0
    blast_bonus = min(10, max(0, (len(apps) - 1) * 3))
    score = min(100, round(severity_weight + payload.cvss * 2.5 + business_weight + direct_bonus + blast_bonus))
    priority = "P0" if score >= 85 else "P1" if score >= 70 else "P2" if score >= 50 else "P3"

    remediation = [
        {"order": 1, "title": "Validate the incident and inventory evidence",
         "detail": f"Confirm {package_name} and the reported advisory against the upstream maintainer or trusted advisory source; verify the component in the deployed artifact and its version."},
        {"order": 2, "title": "Contain potentially affected releases",
         "detail": "Pause promotion of affected builds and isolate or roll back artifacts only under the organization's incident-response policy."},
        {"order": 3, "title": "Select a verified safe version",
         "detail": f"Use {payload.fixed_version} only if the upstream advisory confirms it is fixed; otherwise identify a vendor-supported patched release." if payload.fixed_version else "Identify a vendor-supported patched release from the authoritative advisory; TrustGraph will not guess a safe version."},
        {"order": 4, "title": "Rebuild and test",
         "detail": "Regenerate lockfiles and SBOMs, rebuild from trusted sources, run regression/security tests, and scan the resulting artifact."},
        {"order": 5, "title": "Review downstream impact",
         "detail": "Review logs, credentials and sensitive operations accessible to affected workloads; rotate secrets if investigation indicates exposure."},
        {"order": 6, "title": "Verify closure",
         "detail": "Confirm the vulnerable version is absent from deployed artifacts, preserve evidence, and close the work item only after verification."}
    ]
    return {
        "assessment_type": "simulated_scenario" if payload.source_type == "simulated_demo" else "reported_incident_assessment",
        "incident": {"package": package_name, "ecosystem": payload.ecosystem, "severity": severity,
                     "cvss": payload.cvss, "advisory_id": payload.advisory_id,
                     "reported_fixed_version": payload.fixed_version},
        "status": "inventory_match_found", "analysis_basis": "Current inventory records and declared dependency edges",
        "risk_score": score, "priority": priority,
        "risk_interpretation": "A transparent triage heuristic based on supplied severity/CVSS, affected-service criticality and exposure, direct presence, and inventory blast radius. Not a probability of exploitation.",
        "risk_factors": [
            {"factor": "Reported severity", "value": severity, "contribution": severity_weight},
            {"factor": "CVSS input", "value": payload.cvss, "contribution": round(payload.cvss * 2.5, 1)},
            {"factor": "Highest affected-service context", "value": f"{max((x['criticality'] for x in apps.values()), default='Unknown')} criticality / {max((x['exposure'] for x in apps.values()), default='Unknown')} exposure", "contribution": business_weight},
            {"factor": "Direct package presence", "value": "Yes" if direct_bonus else "No", "contribution": direct_bonus},
            {"factor": "Additional application blast radius", "value": len(apps), "contribution": blast_bonus}
        ],
        "matched_components": [{"id": p["id"], "name": p["name"], "version": p["version"],
            "ecosystem": p["ecosystem"], "direct": p["direct"], "application": p["application"],
            "business_service": p["business_service"], "criticality": p["criticality"], "exposure": p["exposure"]}
            for p in matched],
        "dependent_components": [{"id": p["id"], "name": p["name"], "version": p["version"],
            "application": p["application"]} for p in impacted if p["id"] not in {m["id"] for m in matched}],
        "affected_applications": list(apps.values()),
        "affected_business_services": sorted({x["business_service"] for x in apps.values()}),
        "blast_radius": {"matched_package_records": len(matched), "potentially_impacted_components": len(impacted),
            "affected_applications": len(apps), "affected_business_services": len({x["business_service"] for x in apps.values()})},
        "reachability": {"status": "not_assessed", "note": "Manifest presence and dependency edges do not prove vulnerable code is reachable or executed at runtime."},
        "compromise_verification": {"status": "not_verified", "note": "This analyzes a reported or simulated incident; it does not detect compromise or verify malicious activity."},
        "remediation_plan": remediation,
        "limitations": [
            "Application ownership and business-service mappings depend on supplied inventory metadata.",
            "Dependency relationships are manifest-level; runtime call paths and vulnerable-function reachability are not analyzed.",
            "Risk score is a triage heuristic, not a calibrated likelihood or financial-loss estimate.",
            "Confirm advisory details and fixed versions with authoritative upstream sources before remediation."
        ]
    }

@app.post("/api/incidents/analyze")
def analyze_incident(payload: IncidentRequest):
    return _incident_assessment(payload)

@app.get("/api/incidents/demo")
def demo_incident():
    return _incident_assessment(IncidentRequest(
        package="log4j-core", ecosystem="Maven", severity="Critical", cvss=9.8,
        advisory_id="TG-SCENARIO-001", fixed_version="2.17.1", source_type="simulated_demo"
    ))
