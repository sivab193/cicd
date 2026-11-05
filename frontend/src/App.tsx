import {useEffect,useState} from 'react';
import {Link,NavLink,Route,Routes,useLocation} from 'react-router-dom';
import {useQuery} from '@tanstack/react-query';
import {Check,Download,Github,Instagram,Linkedin,LogOut,X} from 'lucide-react';
import {AnimatePresence,motion} from 'motion/react';
import {LineIcon,type LineIconName} from './components/LineIcon';
import {api,useAction,useDashboard,type Item} from './api';
import {Empty,ErrorNotice,Modal,Status,Submit} from './components/ui';
import NewProject from './components/NewProject';
import DeploymentStages from './components/DeploymentStages';
import Overview from './pages/Overview';
import Projects from './pages/Projects';
import Pipelines from './pages/Pipelines';
import Runners from './pages/Runners';
import Integrations from './pages/Integrations';
import OrganizationPatterns from './pages/OrganizationPatterns';
import {Deployments,Security,Health,Infrastructure,ActivityFeed} from './pages/Operations';
import ProjectDetail from './pages/ProjectDetail';
import Settings from './pages/Settings';

const nav=[
 ['/','Overview','dashboard','Workspace'],
 ['/projects','Repositories','box','Workspace'],
 ['/pipelines','Pipelines','workflow','Automation'],
 ['/runners','Runners','cpu','Automation'],
 ['/patterns','Org patterns','sliders','Automation'],
 ['/integrations','Integrations','plug','Automation'],
 ['/deployments','Deployments','rocket','Operations'],
 ['/security','Security','shield','Operations'],
 ['/health','Health','heartPulse','Operations'],
 ['/infrastructure','Infrastructure','server','Operations'],
 ['/activity','Activity','activity','Operations'],
 ['/settings','Settings','settings','System'],
] as const;

export default function App(){
 const session=useQuery({queryKey:['session'],queryFn:()=>api('/session')});
 if(session.isLoading)return <div className="boot"><LineIcon name="box"/><p>Opening CICD…</p></div>;
 if(session.error)return <div className="boot"><h1>Let’s get connected.</h1><p>The API isn’t responding. Start the backend with ./run.sh.</p><ErrorNotice error={session.error}/><button className="button" onClick={()=>session.refetch()}>Retry connection</button></div>;
 if(!session.data?.user)return <div className="login"><LineIcon name="box" size={50}/><h1>CICD</h1><p>A private control plane for every repository you ship.</p><a className="button primary" href="/api/auth/github"><Github size={18}/>Continue with GitHub</a><small>Access is restricted to authorized workspace members.</small></div>;
 return <Workspace/>;
}

function Workspace(){
 const {data,error,isLoading}=useDashboard();
 const action=useAction<Item>();
 const loc=useLocation();
 const [mobile,setMobile]=useState(false);
 const [newProject,setNewProject]=useState(false);
 const [searchOpen,setSearchOpen]=useState(false);
 const [query,setQuery]=useState('');
 const [selected,setSelected]=useState<Item|null>(null);
 const [deploy,setDeploy]=useState<{project:Item;action:string;target?:string}|null>(null);
 const [target,setTarget]=useState('');
 const [environment,setEnvironment]=useState('production');
 const [toast,setToast]=useState('');
 const [downloadError,setDownloadError]=useState<Error|null>(null);

 useEffect(()=>setMobile(false),[loc.pathname]);
 useEffect(()=>{
  if(!mobile)return;
  const navElement=document.querySelector('.sidebar nav');
  const close=()=>setMobile(false);
  navElement?.addEventListener('click',close);
  return()=>navElement?.removeEventListener('click',close);
 },[mobile]);
 useEffect(()=>{
  const key=(e:KeyboardEvent)=>{if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();setSearchOpen(v=>!v)}};
  window.addEventListener('keydown',key);
  return()=>window.removeEventListener('keydown',key);
 },[]);
 useEffect(()=>{
  if(!toast)return;
  const t=setTimeout(()=>setToast(''),4500);
  return()=>clearTimeout(t);
 },[toast]);
 const startDeploy=(project:Item,a='deploy',t?:string)=>{
  action.reset();
  setDeploy({project,action:a,target:t});
  setTarget(t||'');
  setEnvironment('production');
 };
 if(isLoading||!data)return <div className="boot"><LineIcon name="box" className="spin"/><p>Loading workspace…</p><ErrorNotice error={error}/></div>;
 const title=nav.find(([path])=>path==='/'?loc.pathname==='/':loc.pathname.startsWith(path))?.[1]||'Overview';
 return <div className="app-shell">
  {mobile&&<button className="mobile-backdrop" aria-label="Close navigation" onClick={()=>setMobile(false)}/>}
  <aside className={`sidebar ${mobile?'open':''}`}>
   <Link to="/" className="brand"><span className="brand-cube"><LineIcon name="box" size={30}/></span><span><strong>CICD</strong><small>siv19.dev</small></span></Link>
   <div className="workspace-switch"><span className="nav-label">ACCOUNT</span><div><span className="avatar mint">S</span><b>{data.user.login}</b></div></div>
   <nav>{nav.map(([path,label,icon,group],index)=><div className="nav-item" key={path}>{(index===0||nav[index-1][3]!==group)&&<span className="nav-section-label">{group}</span>}<NavLink to={path} end={path==='/'} className={({isActive})=>(isActive?'active ':'')+(group==='Operations'&&index===6?'nav-separated':'')}><LineIcon name={icon as LineIconName} size={17}/><span>{label}</span>{label==='Security'&&data.finding.some(f=>f.status==='open'&&f.severity==='critical')&&<span className="nav-alert">1</span>}</NavLink></div>)}</nav>
   <div className="sidebar-bottom"><div className="connection"><i className="live-dot"/><div>{data.demo?'Sample mode':'Connected workspace'}<small>{data.demo?'No external actions run':'GitHub authenticated'}</small></div><span>v1.0</span></div><div className="profile"><span className="avatar">S</span><div><b>{data.user.login}</b><small>{data.user.role}</small></div>{!data.demo&&<button className="icon-button" aria-label="Sign out" onClick={async()=>{await api('/auth/logout','POST');location.reload()}}><LogOut size={16}/></button>}</div></div>
  </aside>
  <div className="main-shell">
   <header className="topbar"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={()=>setMobile(true)}><LineIcon name="menu" size={22}/></button><button className="global-search" aria-label="Search repositories, runs, and deployments" onClick={()=>setSearchOpen(true)}><LineIcon name="search" size={17}/><span>Search repositories, runs, and deployments…</span><kbd>⌘ K</kbd></button><div className="topbar-right"><span className="workspace-badge">{data.demo?'SAMPLE':'PRIVATE'}</span><button className="button primary" onClick={()=>setNewProject(true)}><LineIcon name="plus" size={16}/><span>Add project</span></button></div></header>
   <main><div className="breadcrumb"><span>{title}</span><div><span>{new Date().toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})}</span><span className="breadcrumb-status"><i className="live-dot"/>{data.demo?'Sample workspace':'Control plane online'}</span></div></div><AnimatePresence mode="wait"><motion.div key={loc.pathname} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} exit={{opacity:0}} transition={{duration:.18}}><Routes>
    <Route path="/" element={<Overview data={data}/>}/>
    <Route path="/projects" element={<Projects data={data} onNew={()=>setNewProject(true)}/>}/>
    <Route path="/projects/:id" element={<ProjectDetail data={data} onSelect={setSelected} onDeploy={startDeploy}/>}/>
    <Route path="/pipelines" element={<Pipelines data={data}/>}/>
    <Route path="/runners" element={<Runners data={data}/>}/>
    <Route path="/integrations" element={<Integrations/>}/>
    <Route path="/patterns" element={<OrganizationPatterns data={data}/>}/>
    <Route path="/deployments" element={<Deployments data={data} onSelect={setSelected}/>}/>
    <Route path="/security" element={<Security data={data}/>}/>
    <Route path="/health" element={<Health data={data}/>}/>
    <Route path="/infrastructure" element={<Infrastructure data={data}/>}/>
    <Route path="/activity" element={<ActivityFeed data={data}/>}/>
    <Route path="/settings" element={<Settings/>}/>
    <Route path="*" element={<Empty title="Page not found" text="Choose a page from the navigation."/>}/>
   </Routes></motion.div></AnimatePresence></main>
   <footer className="app-footer"><span>Build <i>•</i> Automate <i>•</i> Open Source</span><div className="footer-links"><a href="https://siv19.dev/" target="_blank" rel="noopener noreferrer">siv19.dev</a><a href="https://github.com/sivab193" target="_blank" rel="noopener noreferrer" aria-label="GitHub"><Github size={16}/></a><a href="https://www.linkedin.com/in/sivab193/" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn"><Linkedin size={16}/></a><a href="https://www.instagram.com/siv19.dev/" target="_blank" rel="noopener noreferrer" aria-label="Instagram"><Instagram size={16}/></a></div></footer>
  </div>
  <NewProject open={newProject} onClose={()=>{setNewProject(false);setToast('Project created')}} repos={data.repository}/>
  <Modal open={searchOpen} onClose={()=>setSearchOpen(false)} title="Jump to anything" description="Search projects, pages, and infrastructure services."><div className="search-field command-search"><LineIcon name="search" size={18}/><input autoFocus placeholder="Type to search…" value={query} onChange={e=>setQuery(e.target.value)}/></div><div className="search-results">{nav.filter(([,label])=>label.toLowerCase().includes(query.toLowerCase())).map(([path,label,icon])=><Link key={path} to={path} onClick={()=>setSearchOpen(false)}><LineIcon name={icon as LineIconName} size={17}/>{label}<LineIcon name="arrowUpRight" size={15}/></Link>)}{data.project.filter(p=>p.name.toLowerCase().includes(query.toLowerCase())).map(p=><Link key={p.id} to={'/projects/'+p.id} onClick={()=>setSearchOpen(false)}><LineIcon name="box" size={17}/>{p.name}<Status value={p.status}/></Link>)}{data.repository.filter(r=>r.name.toLowerCase().includes(query.toLowerCase())).map(r=><Link key={r.id} to="/projects" onClick={()=>setSearchOpen(false)}><LineIcon name="github" size={17}/>{r.name}<Status value={r.state}/></Link>)}</div></Modal>
  <Modal open={!!selected} onClose={()=>{setSelected(null);setDownloadError(null)}} title={selected?.project_name+' · Deployment'} description="Immutable release history, from build to verification.">{selected&&<><div className="row between"><Status value={selected.status}/><code>{selected.commit}</code></div><dl className="details-grid">{['provider','environment','branch','source','actor','started_at'].map(k=><div key={k}><dt>{k.replaceAll('_',' ')}</dt><dd>{selected[k]}</dd></div>)}</dl><DeploymentStages deployment={selected} demo={data.demo}/><div className="terminal compact">{selected.logs?.map((line:string,index:number)=><div key={index}><span>{index+1}</span><code>{line}</code></div>)}</div><ErrorNotice error={downloadError||action.error}/><div className="modal-actions"><button className="button" onClick={async()=>{try{const result=await api('/deployments/'+selected.id+'/sbom');const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='sbom.cdx.json';a.click();URL.revokeObjectURL(url)}catch(e){setDownloadError(e as Error)}}}><Download size={15}/>SBOM</button>{selected.status==='healthy'&&<button className="button primary" onClick={()=>{const project=data.project.find(p=>p.id===selected.project);setSelected(null);if(project)startDeploy(project,'rollback',selected.id)}}>Rollback to this version</button>}{['verifying','failed'].includes(selected.status)&&<button className="button" onClick={async()=>{try{const result=await action.mutateAsync({path:`/deployments/${selected.id}/verify`});setSelected(result)}catch{}}}>Retry verification</button>}</div></>}</Modal>
  <Modal open={!!deploy} onClose={()=>setDeploy(null)} title={`${deploy?.action==='rollback'?'Rollback':'Deploy'} ${deploy?.project.name}`} description={data.demo?'Sample mode records the request without triggering a real deployment.':'This action changes the selected environment through its configured provider.'}><form onSubmit={async e=>{e.preventDefault();if(!deploy)return;try{await action.mutateAsync({path:`/projects/${deploy.project.id}/deployments`,body:{action:deploy.action,environment,target:target||undefined}});setDeploy(null);setToast('Deployment request recorded')}catch{}}}><label>Action<select value={deploy?.action||'deploy'} onChange={e=>deploy&&setDeploy({...deploy,action:e.target.value})}>{(deploy?.project.provider==='Vercel'?['deploy','redeploy','rollback']:deploy?.project.provider==='GitHub Actions'?['deploy','redeploy','cancel']:['deploy','redeploy','rollback','restart','stop']).map(name=><option key={name}>{name}</option>)}</select></label><label>Environment<select value={environment} onChange={e=>setEnvironment(e.target.value)}>{deploy?.project.environments.map((value:string)=><option key={value}>{value}</option>)}</select></label>{deploy?.action==='rollback'&&<label>Healthy target deployment<select required value={target} onChange={e=>setTarget(e.target.value)}><option value="">Select a version</option>{data.deployment.filter(d=>d.project===deploy.project.id&&d.status==='healthy'&&d.environment===environment).map(d=><option key={d.id} value={d.id}>{d.commit} · {d.id}</option>)}</select></label>}<ErrorNotice error={action.error}/><div className="modal-actions"><Submit pending={action.isPending}>Confirm {deploy?.action}</Submit></div></form></Modal>
  <AnimatePresence>{toast&&<motion.div role="status" className="toast" initial={{y:30,opacity:0}} animate={{y:0,opacity:1}} exit={{opacity:0}}><Check size={17}/>{toast}<button className="icon-button" aria-label="Dismiss notification" onClick={()=>setToast('')}><X size={15}/></button></motion.div>}</AnimatePresence>
 </div>;
}
