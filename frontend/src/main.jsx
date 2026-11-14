
import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, AlertOctagon, AlertTriangle, ArrowDownRight, ArrowRight, ArrowUpRight,
  Boxes, Check, CheckCircle2, ChevronDown, ChevronRight, CircleHelp, Clock3,
  CloudUpload, Code2, Download, ExternalLink, FileSearch, Filter, GitBranch,
  Globe2, LayoutDashboard, LockKeyhole, Menu, MoreHorizontal, Package,
  RefreshCw, Search, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal,
  Sparkles, Target, TrendingUp, Upload, X, Zap
} from 'lucide-react'
import './style.css'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const fmt = n => new Intl.NumberFormat('en-IN').format(n || 0)
const shortDate = s => s ? new Date(s).toLocaleString([], {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'}) : '—'

function App(){
  const [page,setPage]=useState('Overview')
  const [overview,setOverview]=useState(null)
  const [inventory,setInventory]=useState([])
  const [findings,setFindings]=useState([])
  const [graph,setGraph]=useState({nodes:[],edges:[]})
  const [actions,setActions]=useState([])
  const [selected,setSelected]=useState(null)
  const [query,setQuery]=useState('')
  const [severity,setSeverity]=useState('All')
  const [loading,setLoading]=useState(true)
  const [busy,setBusy]=useState(false)
  const [toast,setToast]=useState('')
  const [apiOnline,setApiOnline]=useState(false)
  const [uploadName,setUploadName]=useState('')
  const [showUpload,setShowUpload]=useState(false)
  const [osvBusy,setOsvBusy]=useState(false)
  const [osvResult,setOsvResult]=useState(null)

  const notify = msg => { setToast(msg); window.clearTimeout(window.__tgToast); window.__tgToast=window.setTimeout(()=>setToast(''),3600) }
  async function request(path,opts={}){
    const r=await fetch(API+path,opts)
    if(!r.ok){const t=await r.text();throw new Error(t.slice(0,220))}
    const ct=r.headers.get('content-type')||''
    return ct.includes('application/json')?r.json():r.blob()
  }
  async function refresh(){
    setLoading(true)
    try{
      const [o,i,f,g,a]=await Promise.all(['/api/overview','/api/inventory','/api/findings','/api/graph','/api/actions'].map(x=>request(x)))
      setOverview(o);setInventory(i.items);setFindings(f.items);setGraph(g);setActions(a.items);setApiOnline(true)
    }catch(e){setApiOnline(false);notify('Could not connect to TrustGraph API. Start the backend and retry.')}
    finally{setLoading(false)}
  }
  useEffect(()=>{refresh()},[])
  const highRisk=findings.filter(f=>['P0','P1'].includes(f.priority))
  const filtered=useMemo(()=>findings.filter(f=>(severity==='All'||f.severity===severity)&&
    [f.package,f.application,f.business_service,f.advisory_id].join(' ').toLowerCase().includes(query.toLowerCase())),[findings,severity,query])
  const active=selected || findings[0]
  const nav=[['Overview',LayoutDashboard],['Risk findings',ShieldAlert],['Dependency map',GitBranch],['Inventory',Boxes],['Response centre',Target]]
  async function resetDemo(){
    setBusy(true);try{await request('/api/demo/reset',{method:'POST'});setSelected(null);setOsvResult(null);await refresh();notify('Demo workspace restored.')}catch(e){notify(e.message)}finally{setBusy(false)}
  }
  async function uploadFile(file){
    if(!file)return
    setBusy(true);setUploadName(file.name)
    try{const fd=new FormData();fd.append('file',file);const res=await request('/api/scan',{method:'POST',body:fd});await refresh();setPage('Risk findings');notify(res.message)}
    catch(e){notify('Scan failed: '+e.message)}finally{setBusy(false);setShowUpload(false)}
  }
  async function updateStatus(f,status){
    try{await request('/api/actions/'+encodeURIComponent(f.id),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});await refresh();notify(`Finding marked ${status.toLowerCase()}.`)}
    catch(e){notify('Could not update action: '+e.message)}
  }
  async function runOSV(){
    setOsvBusy(true)
    try{const res=await request('/api/osv/check',{method:'POST'});setOsvResult(res);notify(`OSV returned ${res.count} live advisories.`)}
    catch(e){notify('Live OSV lookup unavailable. Check backend internet access.')}
    finally{setOsvBusy(false)}
  }
  async function download(fmt){
    try{const blob=await request('/api/export/'+fmt);const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`trustgraph-report.${fmt}`;a.click();URL.revokeObjectURL(url);notify(`${fmt.toUpperCase()} report exported.`)}
    catch(e){notify('Export failed: '+e.message)}
  }

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><GitBranch size={20}/></div><div><div className="brand-name">trustgraph<span>®</span></div><div className="brand-sub">SOFTWARE TRUST INTELLIGENCE</div></div></div>
      <div className="workspace"><div className="workspace-icon"><ShieldCheck size={17}/></div><div><b>Northstar Commerce</b><small>Production workspace</small></div><ChevronDown size={14}/></div>
      <div className="nav-label">WORKSPACE</div>
      <nav>{nav.map(([name,Icon])=><button key={name} className={'nav-item '+(page===name?'active':'')} onClick={()=>setPage(name)}><Icon size={17}/><span>{name}</span>{name==='Risk findings'&&findings.length>0&&<em>{findings.length}</em>}</button>)}</nav>
      <div className="nav-label nav-label-lower">MANAGE</div>
      <button className="nav-item" onClick={()=>setShowUpload(true)}><CloudUpload size={17}/><span>Import inventory</span></button>
      <button className="nav-item" onClick={runOSV}><Globe2 size={17}/><span>Live OSV check</span><span className="nav-dot"/></button>
      <div className="sidebar-bottom"><div className="support-card"><div className="support-icon"><CircleHelp size={17}/></div><b>Need a hand?</b><p>Explore the demo workspace or import your own dependency inventory.</p><button onClick={()=>notify('Use Import inventory to scan package manifests or a CycloneDX BOM.')}>View quick guide <ArrowRight size={13}/></button></div><div className="user-row"><div className="avatar">NS</div><div><b>Northstar Security</b><small>Security analyst</small></div><MoreHorizontal size={17}/></div></div>
    </aside>

    <main className="main">
      <header className="topbar"><div className="crumb"><span>Workspace</span><ChevronRight size={13}/><b>{page}</b></div><div className="top-actions"><div className="connection"><span className={apiOnline?'live-dot':'dead-dot'}/>{apiOnline?'API connected':'API offline'}</div><button className="icon-btn" title="Refresh" onClick={refresh}><RefreshCw size={16}/></button><button className="top-avatar">NS</button></div></header>
      <div className="content">
        <div className="page-heading"><div><div className="eyebrow">SECURITY POSTURE <span>/</span> THIRD-PARTY RISK</div><h1>{page==='Overview'?'Software trust, in focus.':page}</h1><p>{page==='Overview'?'Understand what your software depends on, what could go wrong, and what to do next.':page==='Risk findings'?'Prioritized exposure across your software supply chain.':page==='Dependency map'?'Trace external components to the applications and services that rely on them.':page==='Inventory'?'A consolidated view of packages, versions, licenses and ownership.':'Turn findings into accountable remediation work.'}</p></div><div className="heading-actions"><button className="btn btn-secondary" onClick={()=>download('json')}><Download size={15}/> Export</button><button className="btn btn-primary" onClick={()=>setShowUpload(true)}><Upload size={15}/> Import inventory</button></div></div>
        {loading?<div className="loading"><div className="spinner"/>Loading workspace intelligence…</div>:!apiOnline?<div className="offline"><AlertTriangle/><b>TrustGraph API is not connected</b><p>Start the FastAPI backend on port 8000, then refresh this page.</p><button className="btn btn-primary" onClick={refresh}>Retry connection</button></div>:<>
          {page==='Overview'&&<Overview overview={overview} findings={findings} inventory={inventory} setPage={setPage} setSelected={setSelected} actions={actions} onReset={resetDemo} busy={busy} onOSV={runOSV} osvBusy={osvBusy} osvResult={osvResult}/>}
          {page==='Risk findings'&&<Findings findings={filtered} query={query} setQuery={setQuery} severity={severity} setSeverity={setSeverity} setSelected={setSelected} selected={selected} actions={actions}/>}
          {page==='Dependency map'&&<DependencyMap graph={graph} findings={findings} inventory={inventory}/>}
          {page==='Inventory'&&<Inventory inventory={inventory} query={query} setQuery={setQuery}/>}
          {page==='Response centre'&&<ResponseCentre findings={findings} actions={actions} updateStatus={updateStatus}/>}
        </>}
        <footer className="footer"><span>TRUSTGRAPH <b>·</b> PROTOTYPE 1.0</span><span>Demo advisory catalogue is synthetic. Use live OSV check for external vulnerability intelligence.</span></footer>
      </div>
    </main>

    {active&&selected&&<FindingDrawer finding={active} onClose={()=>setSelected(null)} updateStatus={updateStatus} actions={actions}/>}
    {showUpload&&<UploadModal onClose={()=>setShowUpload(false)} onFile={uploadFile} busy={busy} uploadName={uploadName}/>}
    {toast&&<div className="toast"><CheckCircle2 size={17}/>{toast}<button onClick={()=>setToast('')}><X size={14}/></button></div>}
  </div>
}

function Metric({label,value,sub,icon:Icon,tone='green',trend}){
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><div className={'metric-icon '+tone}><Icon size={17}/></div></div><div className="metric-value">{value??'—'}</div><div className="metric-foot"><span>{sub}</span>{trend&&<span className="metric-trend"><ArrowUpRight size={13}/>{trend}</span>}</div></div>
}
function Overview({overview:o,findings,inventory,setPage,setSelected,actions,onReset,busy,onOSV,osvBusy,osvResult}){
  const critical=findings.filter(f=>f.severity==='Critical').length, high=findings.filter(f=>f.severity==='High').length
  const top=findings.slice(0,4)
  const apps=[...new Set(findings.map(f=>f.application))]
  const bars=[['Critical',critical,'#c45c4b'],['High',high,'#d48b4c'],['Medium',findings.filter(f=>f.severity==='Medium').length,'#c5a45c'],['Low',findings.filter(f=>f.severity==='Low').length,'#8ca58d']]
  const max=Math.max(1,...bars.map(x=>x[1]))
  return <>
    <div className="metrics-grid">
      <Metric label="DEPENDENCIES TRACKED" value={fmt(o?.packages)} sub={`${o?.direct||0} direct · ${o?.transitive||0} transitive`} icon={Package}/>
      <Metric label="OPEN RISK FINDINGS" value={fmt(o?.findings)} sub={`${o?.critical||0} critical · ${o?.high||0} high`} icon={ShieldAlert} tone="amber"/>
      <Metric label="AFFECTED APPLICATIONS" value={fmt(o?.affected_apps)} sub="Across business services" icon={Boxes} tone="blue"/>
      <Metric label="AVERAGE RISK SCORE" value={`${o?.risk_score||0}`} sub="Weighted exposure index / 100" icon={Activity} tone="red"/>
    </div>
    <div className="section-row"><div><h2>Risk at a glance</h2><p>Prioritization based on severity, business criticality, exposure and dependency role.</p></div><button className="text-link" onClick={()=>setPage('Risk findings')}>View all findings <ArrowRight size={14}/></button></div>
    <div className="overview-grid">
      <div className="panel risk-panel"><div className="panel-head"><div><h3>Exposure by severity</h3><p>Current inventory assessment</p></div><span className="pill pill-neutral">LIVE WORKSPACE</span></div>
        <div className="severity-layout"><div className="donut-wrap"><div className="donut" style={{background:`conic-gradient(#c45c4b 0 ${critical*100/Math.max(1,findings.length)}%, #d48b4c ${critical*100/Math.max(1,findings.length)}% ${(critical+high)*100/Math.max(1,findings.length)}%, #c5a45c ${(critical+high)*100/Math.max(1,findings.length)}% 100%)`}}><div><b>{findings.length}</b><small>FINDINGS</small></div></div></div>
        <div className="severity-bars">{bars.map(([label,val,color])=><div className="severity-row" key={label}><span><i style={{background:color}}/>{label}</span><div className="bar-track"><div style={{width:`${val/max*100}%`,background:color}}/></div><b>{val}</b></div>)}</div></div>
        <div className="panel-note"><ShieldCheck size={15}/> Findings are prioritized; a high score is a review signal, not proof of exploitability.</div>
      </div>
      <div className="panel exposure-panel"><div className="panel-head"><div><h3>Business exposure</h3><p>Where vulnerable components are used</p></div><button className="mini-link" onClick={()=>setPage('Dependency map')}>Explore map <ArrowRight size={13}/></button></div>
        <div className="business-list">{apps.slice(0,5).map((app,i)=>{const count=findings.filter(f=>f.application===app).length;const topSev=findings.filter(f=>f.application===app).some(f=>f.severity==='Critical')?'Critical':'High';return <div className="business-row" key={app}><div className="business-icon">{['OR','CP','RE','PG','BP'][i%5]}</div><div className="business-info"><b>{app}</b><small>{findings.find(f=>f.application===app)?.business_service}</small></div><span className={`severity-tag ${topSev.toLowerCase()}`}>{topSev}</span><b className="business-count">{count}</b></div>})}{apps.length===0&&<div className="empty-state">No affected services detected.</div>}</div>
      </div>
    </div>
    <div className="section-row section-row-tight"><div><h2>Needs attention</h2><p>Highest-priority items from your current inventory.</p></div><button className="text-link" onClick={()=>setPage('Risk findings')}>Open risk register <ArrowRight size={14}/></button></div>
    <div className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>DEPENDENCY</th><th>APPLICATION</th><th>SEVERITY</th><th>RISK SCORE</th><th>RECOMMENDED FIX</th><th></th></tr></thead><tbody>{top.map(f=><tr key={f.id} onClick={()=>setSelected(f)} className="click-row"><td><div className="package-cell"><span className="package-icon"><Code2 size={15}/></span><div><b>{f.package}</b><small>{f.version} · {f.ecosystem}</small></div></div></td><td>{f.application}</td><td><span className={`severity-tag ${f.severity.toLowerCase()}`}>{f.severity}</span></td><td><div className="score-cell"><b>{f.risk_score}</b><div className="score-track"><i style={{width:`${f.risk_score}%`}}/></div></div></td><td className="fix-cell">Upgrade to {f.fixed}</td><td><ChevronRight size={16} className="muted"/></td></tr>)}</tbody></table>{top.length===0&&<div className="empty-state">No findings in this inventory. Import a manifest or restore the demo workspace.</div>}</div><div className="table-foot"><span>Showing {top.length} of {findings.length} findings</span><button className="text-link" onClick={()=>setPage('Risk findings')}>View full register <ArrowRight size={13}/></button></div></div>
    <div className="bottom-grid"><div className="panel data-panel"><div className="panel-head"><div><h3>Inventory coverage</h3><p>What TrustGraph currently knows about</p></div><Package size={18} className="muted"/></div><div className="coverage-grid"><div><b>{inventory.filter(x=>x.license!=='Unknown').length}</b><span>Known licenses</span></div><div><b>{inventory.filter(x=>x.latest!==x.version).length}</b><span>Version updates available</span></div><div><b>{inventory.filter(x=>x.source==='Uploaded dependency manifest').length}</b><span>Imported records</span></div></div></div>
      <div className="panel quick-panel"><div className="panel-head"><div><h3>Quick actions</h3><p>Continue your security workflow</p></div><Zap size={18} className="muted"/></div><div className="quick-actions"><button onClick={()=>onOSV()} disabled={osvBusy}><Globe2 size={16}/><span>{osvBusy?'Querying OSV…':'Check live OSV intelligence'}</span><ArrowRight size={14}/></button><button onClick={onReset} disabled={busy}><RefreshCw size={16}/><span>Restore demo scenario</span><ArrowRight size={14}/></button></div>{osvResult&&<div className="osv-summary">OSV live check: <b>{osvResult.count}</b> advisories returned.</div>}</div></div>
  </>
}
function Findings({findings,query,setQuery,severity,setSeverity,setSelected,selected,actions}){
  return <div className="panel full-panel"><div className="filter-toolbar"><div className="search-box"><Search size={16}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search package, application or advisory…"/></div><div className="filter-select"><Filter size={15}/><select value={severity} onChange={e=>setSeverity(e.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div><span className="result-count">{findings.length} results</span></div>
    <div className="table-wrap"><table><thead><tr><th>DEPENDENCY / ADVISORY</th><th>APPLICATION</th><th>SEVERITY</th><th>PRIORITY</th><th>RISK SCORE</th><th>STATUS</th><th></th></tr></thead><tbody>{findings.map(f=><tr key={f.id} onClick={()=>setSelected(f)} className="click-row"><td><div className="package-cell"><span className="package-icon"><Code2 size={15}/></span><div><b>{f.package}</b><small>{f.version} · {f.advisory_id}</small></div></div></td><td>{f.application}</td><td><span className={`severity-tag ${f.severity.toLowerCase()}`}>{f.severity}</span></td><td><span className={`priority ${f.priority.toLowerCase()}`}>{f.priority}</span></td><td><div className="score-cell"><b>{f.risk_score}</b><div className="score-track"><i style={{width:`${f.risk_score}%`}}/></div></div></td><td><span className="status-text">{actions.find(a=>a.finding_id===f.id)?.status||'Open'}</span></td><td><ChevronRight size={16} className="muted"/></td></tr>)}</tbody></table>{findings.length===0&&<div className="empty-state">No findings match those filters.</div>}</div>
    <div className="table-foot"><span>Advisories in this demo catalogue are synthetic examples.</span><span>Risk scores are explainable prioritization signals.</span></div></div>
}
function Inventory({inventory,query,setQuery}){
  const filtered=inventory.filter(p=>[p.name,p.application,p.ecosystem,p.license].join(' ').toLowerCase().includes(query.toLowerCase()))
  return <div className="panel full-panel"><div className="inventory-summary"><div><b>{inventory.length}</b><span>Total components</span></div><div><b>{inventory.filter(p=>p.direct).length}</b><span>Direct dependencies</span></div><div><b>{inventory.filter(p=>!p.direct).length}</b><span>Transitive dependencies</span></div><div><b>{new Set(inventory.map(p=>p.ecosystem)).size}</b><span>Ecosystems</span></div></div><div className="filter-toolbar"><div className="search-box"><Search size={16}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search package, application or license…"/></div><span className="result-count">{filtered.length} components</span></div><div className="table-wrap"><table><thead><tr><th>COMPONENT</th><th>VERSION</th><th>ECOSYSTEM</th><th>APPLICATION</th><th>LICENSE</th><th>TYPE</th><th>UPDATE</th></tr></thead><tbody>{filtered.map(p=><tr key={p.id}><td><div className="package-cell"><span className="package-icon"><Package size={15}/></span><div><b>{p.name}</b><small>{p.id}</small></div></div></td><td className="mono">{p.version}</td><td>{p.ecosystem}</td><td>{p.application}</td><td>{p.license}</td><td><span className="type-tag">{p.direct?'Direct':'Transitive'}</span></td><td>{p.latest!==p.version?<span className="update-tag">Update available</span>:<span className="muted">Current</span>}</td></tr>)}</tbody></table>{filtered.length===0&&<div className="empty-state">No components match your search.</div>}</div></div>
}
function DependencyMap({graph,findings,inventory}){
  const apps=graph.nodes.filter(n=>n.type==='application')
  const pkgs=graph.nodes.filter(n=>n.type==='package')
  const [active,setActive]=useState('All')
  const filtered=active==='All'?pkgs:pkgs.filter(p=>p.risk!=='Clear')
  return <div className="map-layout"><div className="panel map-panel"><div className="panel-head"><div><h3>Application dependency topology</h3><p>Application-to-package relationships in the current inventory.</p></div><div className="legend"><span><i className="legend-app"/>Application</span><span><i className="legend-risk"/>At risk</span><span><i className="legend-safe"/>No demo match</span></div></div><div className="map-canvas"><div className="map-col"><div className="map-col-title">APPLICATIONS <span>{apps.length}</span></div>{apps.map((a,i)=><div className="map-node app-node" key={a.id}><div className="node-icon"><Boxes size={15}/></div><div><b>{a.label}</b><small>{a.service}</small></div><span className="node-count">{inventory.filter(p=>p.application===a.label).length}</span></div>)}</div><div className="map-connect"><div className="connect-line"/></div><div className="map-col package-col"><div className="map-col-title">DEPENDENCIES <span>{filtered.length} / {pkgs.length}</span></div>{filtered.map(p=><div className="map-node package-node" key={p.id}><div className={'node-status '+(p.risk==='Clear'?'safe':'risk')}/><div><b>{p.label}</b><small>{p.version} · {p.risk==='Clear'?'No demo match':p.risk+' priority'}</small></div><span className="node-count">{p.version}</span></div>)}</div></div><div className="map-foot"><span>Relationship view is derived from imported manifest and seeded demo mappings.</span><button className="text-link" onClick={()=>setActive(active==='All'?'At risk only':'All')}>{active==='All'?'Show at-risk only':'Show all components'}</button></div></div><div className="panel map-side"><h3>Exposure summary</h3><p>Services with one or more matched demo advisories.</p>{apps.map(a=>{const fs=findings.filter(f=>f.application===a.label);return <div className="map-service" key={a.id}><div><b>{a.label}</b><small>{a.service}</small></div><span className={fs.length?'risk-number':'safe-number'}>{fs.length||'—'}</span></div>})}<div className="map-callout"><Shield size={17}/><div><b>Why this matters</b><p>A vulnerable transitive dependency can affect a critical application even when the application team never selected it directly.</p></div></div></div></div>
}
function ResponseCentre({findings,actions,updateStatus}){
  const open=findings.filter(f=>!['Resolved','Accepted risk'].includes(actions.find(a=>a.finding_id===f.id)?.status||'Open'))
  return <div className="response-layout"><div className="panel response-panel"><div className="panel-head"><div><h3>Remediation queue</h3><p>Track findings from discovery through resolution.</p></div><span className="pill pill-neutral">{open.length} OPEN ITEMS</span></div>{findings.map(f=>{const a=actions.find(x=>x.finding_id===f.id);const status=a?.status||'Open';return <div className="response-row" key={f.id}><div className={`priority-mark ${f.priority.toLowerCase()}`}>{f.priority}</div><div className="response-main"><b>{f.package} <span>{f.version}</span></b><small>{f.application} · Fix: {f.fixed}</small><p>{f.recommendation}</p></div><div className="response-controls"><select value={status} onChange={e=>updateStatus(f,e.target.value)}><option>Open</option><option>In progress</option><option>Resolved</option><option>Accepted risk</option></select><span className="score-mini">{f.risk_score}/100</span></div></div>})}{findings.length===0&&<div className="empty-state">No remediation items. Import an inventory to begin.</div>}</div><div className="panel response-guide"><h3>Suggested response sequence</h3><div className="guide-step"><span>01</span><div><b>Validate exposure</b><p>Confirm the affected package is present in the deployed artifact and reachable in the relevant execution path.</p></div></div><div className="guide-step"><span>02</span><div><b>Plan the upgrade</b><p>Check fixed versions, breaking changes, transitive constraints and test coverage.</p></div></div><div className="guide-step"><span>03</span><div><b>Verify closure</b><p>Re-scan the artifact, attach evidence and mark the finding resolved only after validation.</p></div></div></div></div>
}
function FindingDrawer({finding:f,onClose,updateStatus,actions}){
  const [tab,setTab]=useState('Overview')
  const action=actions.find(a=>a.finding_id===f.id)
  return <div className="drawer-backdrop" onClick={onClose}><aside className="drawer" onClick={e=>e.stopPropagation()}><div className="drawer-head"><div><span className="eyebrow">FINDING DETAIL / {f.id.slice(-8).toUpperCase()}</span><h2>{f.package}</h2></div><button className="icon-btn" onClick={onClose}><X size={17}/></button></div><div className="drawer-tabs"><button className={tab==='Overview'?'selected':''} onClick={()=>setTab('Overview')}>Overview</button><button className={tab==='Remediation'?'selected':''} onClick={()=>setTab('Remediation')}>Remediation</button></div>{tab==='Overview'?<><div className="drawer-badges"><span className={`severity-tag ${f.severity.toLowerCase()}`}>{f.severity}</span><span className={`priority ${f.priority.toLowerCase()}`}>{f.priority}</span><span className="score-badge">{f.risk_score} / 100 risk</span></div><p className="drawer-summary">{f.summary}</p><div className="detail-section"><h4>COMPONENT CONTEXT</h4><div className="detail-grid"><div><small>Installed version</small><b>{f.version}</b></div><div><small>Fixed version</small><b className="green-text">{f.fixed}</b></div><div><small>Ecosystem</small><b>{f.ecosystem}</b></div><div><small>CVSS (demo)</small><b>{f.cvss}</b></div><div><small>Application</small><b>{f.application}</b></div><div><small>Business service</small><b>{f.business_service}</b></div></div></div><div className="detail-section"><h4>WHY THIS IS PRIORITIZED</h4><div className="reason-list"><div><Check size={14}/> {f.severity} advisory severity</div><div><Check size={14}/> {f.criticality} business criticality</div><div><Check size={14}/> {f.exposure} exposure</div><div><Check size={14}/> {f.direct?'Direct':'Transitive'} dependency</div></div></div><div className="source-note"><AlertTriangle size={15}/><span>This match comes from the synthetic TrustGraph demo catalogue. Validate against a trusted advisory source before acting.</span></div></>:<><div className="recommendation-card"><div className="recommendation-icon"><ShieldCheck size={18}/></div><div><b>Recommended action</b><p>{f.recommendation}</p></div></div><div className="detail-section"><h4>VALIDATION CHECKLIST</h4><div className="checklist"><label><input type="checkbox"/> Confirm component is present in deployed artifact</label><label><input type="checkbox"/> Check reachability and exploit preconditions</label><label><input type="checkbox"/> Review upgrade compatibility and release notes</label><label><input type="checkbox"/> Run tests and re-scan after deployment</label></div></div></>}<div className="drawer-footer"><label>WORK ITEM STATUS</label><select value={action?.status||'Open'} onChange={e=>updateStatus(f,e.target.value)}><option>Open</option><option>In progress</option><option>Resolved</option><option>Accepted risk</option></select><button className="btn btn-primary" onClick={onClose}>Done</button></div></aside></div>
}
function UploadModal({onClose,onFile,busy,uploadName}){
  const [drag,setDrag]=useState(false)
  return <div className="modal-backdrop" onClick={onClose}><div className="upload-modal" onClick={e=>e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow">INVENTORY INGESTION</span><h2>Bring your dependencies in.</h2><p>Import a manifest to build a component inventory and run the TrustGraph assessment.</p></div><button className="icon-btn" onClick={onClose}><X size={17}/></button></div><label className={'dropzone '+(drag?'dragging':'')} onDragOver={e=>{e.preventDefault();setDrag(true)}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);onFile(e.dataTransfer.files[0])}}><input type="file" accept=".zip,.json,.txt" onChange={e=>onFile(e.target.files[0])}/><div className="upload-symbol"><CloudUpload size={24}/></div><b>{busy?'Scanning '+uploadName:'Drop a file here or browse'}</b><span>ZIP · package-lock.json · package.json · requirements.txt · CycloneDX JSON</span><small>Files are processed locally by the backend. No file is sent to a third-party service.</small></label><div className="supported"><b>Supported formats</b><span><Code2 size={14}/> npm manifests and lockfiles</span><span><Code2 size={14}/> Python requirements.txt</span><span><Boxes size={14}/> CycloneDX JSON BOM</span></div><div className="modal-actions"><button className="btn btn-secondary" onClick={onClose}>Cancel</button></div></div></div>
}

createRoot(document.getElementById('root')).render(<App/>)
