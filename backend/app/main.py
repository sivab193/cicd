import os, json, secrets, hashlib, hmac, fnmatch, base64, asyncio, re, shlex
from datetime import datetime, timezone
from uuid import uuid4
from contextlib import asynccontextmanager
from urllib.parse import quote
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet
import httpx
from .db import Session, Record, Secret
from .seed import seed
from .providers import PROVIDERS, ProviderError, discover, installation_token, request as provider_request
from .security import normalize, gate
from .health import probe

DEMO=os.getenv('DEMO_MODE','true').lower()=='true'
SESSION_KEY=os.getenv('SESSION_SECRET') or (secrets.token_urlsafe(48) if DEMO else '')
if not SESSION_KEY: raise RuntimeError('SESSION_SECRET is required outside demo mode')
@asynccontextmanager
async def lifespan(app):
    if DEMO: seed()
    yield
app=FastAPI(title='CICD Control Plane',lifespan=lifespan)
app.add_middleware(SessionMiddleware,secret_key=SESSION_KEY,https_only=not DEMO,same_site='lax')
def now(): return datetime.now(timezone.utc).isoformat()
def records(kind):
    with Session() as db: return [r.data for r in db.query(Record).filter_by(kind=kind).order_by(Record.created_at.desc()).all()]
def get(id,kind=None):
    with Session() as db:
        r=db.get(Record,id)
        if not r or (kind and r.kind!=kind): raise HTTPException(404,'Not found')
        return r.data

def put(kind,data):
    with Session() as db:
        r=db.get(Record,data['id'])
        if r: r.data=data
        else: db.add(Record(id=data['id'],kind=kind,data=data))
        db.commit()
    return data

def audit(title,type='configuration',actor='system'):
    put('activity',{'id':uuid4().hex,'title':title,'type':type,'actor':actor,'time':now()})
async def user(req:Request):
    if DEMO: return {'login':'Sivaganesh','role':'owner','demo':True}
    value=req.session.get('user')
    if not value: raise HTTPException(401,'Sign in with GitHub')
    return value
async def writer(req:Request,u=Depends(user)):
    if u['role'] not in ('owner','admin','developer'): raise HTTPException(403,'Read-only role')
    if req.method not in ('GET','HEAD'):
        origin=req.headers.get('origin')
        expected=os.getenv('APP_URL','http://127.0.0.1:5173').rstrip('/')
        if origin and origin!=expected: raise HTTPException(403,'Origin rejected')
    return u
async def admin(u=Depends(writer)):
    if u['role'] not in ('owner','admin'): raise HTTPException(403,'Administrator required')
    return u
class ProjectInput(BaseModel):
    name:str=Field(min_length=1,max_length=80)
    description:str=''
    repositories:list[str]=[]
    provider:str='Vercel'
    branch:str='main'
    url:str=''
    environment:str='production'
class DeployInput(BaseModel):
    action:str='deploy'
    environment:str='production'
    target:str|None=None
class SecretInput(BaseModel):
    name:str=Field(pattern=r'^[A-Z][A-Z0-9_]{0,99}$')
    value:str=Field(min_length=1,max_length=65536)
    environment:str='production'
class WorkflowUpdate(BaseModel):
    repo:str=Field(min_length=3,max_length=200)
    path:str=Field(pattern=r'^\.github/workflows/[^/]+\.ya?ml$')
    content:str=Field(min_length=1,max_length=262144)
    mode:str='pull_request'
    branch:str|None=Field(default=None,max_length=255)
class RunnerInput(BaseModel):
    repo:str=Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
    name:str=Field(min_length=1,max_length=80,pattern=r'^[A-Za-z0-9_.-]+$')
    labels:str=Field(default='cicd,linux',max_length=100,pattern=r'^[A-Za-z0-9_.-]+(,[A-Za-z0-9_.-]+)*$')
class ProviderAccountInput(BaseModel):
    provider:str
    name:str=Field(min_length=1,max_length=80)
    account_id:str=Field(default='',max_length=180)
    project_name:str=Field(default='',max_length=100)
    team_id:str=Field(default='',max_length=100)
    access_token:str=Field(default='',max_length=65536)
class OrganizationPatternInput(BaseModel):
    organization:str=Field(min_length=1,max_length=100,pattern=r'^[A-Za-z0-9_.-]+$')
    name:str=Field(min_length=1,max_length=100)
    path:str=Field(default='.github/workflows/cicd.yml',pattern=r'^\.github/workflows/[^/]+\.ya?ml$')
    content:str=Field(min_length=1,max_length=262144)

@app.get('/api/session')
async def session(req:Request):
    return {'user':await user(req) if DEMO or req.session.get('user') else None,'demo':DEMO,'github_configured':bool(os.getenv('GITHUB_CLIENT_ID'))}
@app.get('/api/auth/github')
async def login(req:Request):
    if not os.getenv('GITHUB_CLIENT_ID'): raise HTTPException(503,'Configure GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET on the backend.')
    state=secrets.token_urlsafe(32); req.session['oauth_state']=state
    return RedirectResponse('https://github.com/login/oauth/authorize?client_id='+os.environ['GITHUB_CLIENT_ID']+'&state='+state+'&scope=read:user')
@app.get('/api/auth/callback')
async def callback(req:Request,code:str,state:str):
    saved=req.session.pop('oauth_state',None)
    if not saved or not secrets.compare_digest(saved,state): raise HTTPException(400,'Invalid OAuth state')
    async with httpx.AsyncClient(timeout=20) as client:
        result=await client.post('https://github.com/login/oauth/access_token',json={'client_id':os.environ['GITHUB_CLIENT_ID'],'client_secret':os.environ['GITHUB_CLIENT_SECRET'],'code':code},headers={'Accept':'application/json'})
        token=result.json().get('access_token')
        if not token: raise HTTPException(401,'OAuth exchange failed')
        result=await client.get('https://api.github.com/user',headers={'Authorization':f'Bearer {token}'})
        profile=result.json()
    roles=json.loads(os.getenv('GITHUB_ALLOWED_USERS','{}'))
    role=roles.get(profile.get('login'))
    if role not in ('owner','admin','developer','viewer'): raise HTTPException(403,'This account is not authorized for this private workspace.')
    req.session.clear(); req.session['user']={'login':profile['login'],'role':role,'avatar':profile.get('avatar_url')}
    audit('Signed in with GitHub','authentication',profile['login'])
    return RedirectResponse(os.getenv('APP_URL','http://127.0.0.1:5173'))
@app.post('/api/auth/logout')
async def logout(req:Request,u=Depends(writer)):
    req.session.clear(); return {'ok':True}
def _redacted_projects():
    out=[]
    for proj in records('project'):
        proj=dict(proj); cfg=dict(proj.get('provider_config') or {})
        proj['provider_config']={k:v for k,v in cfg.items() if not any(t in k.lower() for t in ('token','secret','password','private_key','api_key','access_key'))}
        out.append(proj)
    return out
@app.get('/api/dashboard')
async def dashboard(u=Depends(user)):
    data={kind:records(kind) for kind in ['repository','deployment','finding','health_check','host','service','activity','incident']}
    data['project']=_redacted_projects()
    return data | {'demo':DEMO,'user':u}
@app.get('/api/actions/runs')
async def recent_action_runs(limit:int=30,u=Depends(user)):
    limit=max(1,min(limit,100))
    managed=sorted((r for r in records('repository') if r.get('state')=='managed'),key=lambda r:r.get('updated_at') or '',reverse=True)
    if DEMO:
        projects={p['id']:p for p in records('project')}
        runs=[]
        for d in records('deployment'):
            p=projects.get(d['project'])
            if not p: continue
            for repo in p.get('repositories',[]):
                runs.append({'id':d['id'],'name':f'{p["name"]} · CI','repository':{'full_name':repo},'head_branch':d.get('branch','main'),'head_sha':d.get('commit') or '','actor':{'login':d.get('actor','Sivaganesh')},'status':'completed','conclusion':'success' if d['status']=='healthy' else 'failure' if d['status']=='failed' else d['status'],'created_at':d.get('started_at'),'html_url':None,'sample':True})
        return {'workflow_runs':sorted(runs,key=lambda r:r.get('created_at') or '',reverse=True)[:limit],'repositories_scanned':len(managed),'repositories_total':len(managed),'truncated':False,'errors':[]}
    semaphore=asyncio.Semaphore(8);token_cache={};cache_lock=asyncio.Lock()
    async def runs_for(repository):
        async with semaphore:
            installation=repository.get('installation_id')
            if not installation: return [],f'{repository["name"]}: no GitHub App installation'
            try:
                async with cache_lock:
                    token=token_cache.get(str(installation))
                    if token is None:
                        token=await installation_token(installation)
                        token_cache[str(installation)]=token
                result=await provider_request('GET',f'https://api.github.com/repos/{repository["name"]}/actions/runs?per_page=20',token)
                return [{**run,'repository':{'full_name':repository['name']}} for run in result.get('workflow_runs',[])],None
            except ProviderError as e: return [],f'{repository["name"]}: {e}'
    results=await asyncio.gather(*(runs_for(r) for r in managed[:200]))
    errors=[error for _,error in results if error]
    workflow_runs=sorted((run for runs,_ in results for run in runs),key=lambda run:run.get('created_at') or '',reverse=True)[:limit]
    if not workflow_runs and errors and not any(runs for runs,_ in results): raise HTTPException(503,'Unable to read workflow runs: '+'; '.join(errors[:5]))
    return {'workflow_runs':workflow_runs,'repositories_scanned':min(len(managed),200),'repositories_total':len(managed),'truncated':len(managed)>200,'errors':errors}
@app.post('/api/projects')
async def create_project(body:ProjectInput,u=Depends(writer)):
    if body.provider not in PROVIDERS: raise HTTPException(400,'Unknown provider')
    if body.environment not in ('development','preview','staging','production'): raise HTTPException(400,'Invalid environment')
    for repo in body.repositories:
        if get(repo,'repository')['state']!='managed': raise HTTPException(400,'Manage repositories before creating a project')
    data=put('project',{'id':uuid4().hex,**body.model_dump(),'status':'unknown','color':'#8fffc2','stack':'Unknown','environments':['development','preview','staging','production'],'public':False,'auto_rollback':False,'provider_config':{},'security_policy':{'block_critical':True,'block_secrets':True}})
    audit(f'{body.name} project created','project',u['login']); return data
@app.patch('/api/projects/{id}')
async def update_project(id:str,body:dict,u=Depends(admin)):
    p=get(id,'project'); allowed={'name','description','branch','url','public','public_name','public_description','auto_rollback','provider_config','security_policy','provider'}
    changes={k:v for k,v in body.items() if k in allowed}
    if 'provider' in changes and changes['provider'] not in PROVIDERS: raise HTTPException(400,'Unknown provider')
    if 'provider_config' in changes and not isinstance(changes['provider_config'],dict): raise HTTPException(400,'Provider configuration must be an object')
    if 'provider_config' in changes and any(t in k.lower() for k in changes['provider_config'] for t in ('token','secret','password','private_key','api_key','access_key')): raise HTTPException(400,'Provider configuration must not contain credentials; use an integration account instead')
    selected_provider=changes.get('provider',p['provider'])
    selected_config=changes.get('provider_config',p.get('provider_config',{}))
    if selected_config.get('integration_account_id'):
        account=get(selected_config['integration_account_id'],'integration_account')
        if account['provider']!=selected_provider: raise HTTPException(400,'Selected deployment account does not match the project provider')
    p.update(changes); put('project',p); audit(f'{p["name"]} settings updated',actor=u['login']); return p
@app.post('/api/repositories/discover')
async def discover_repos(u=Depends(admin)):
    if DEMO:
        data=[{'id':'sample/new-project','name':'sample/new-project','state':'unreviewed','stack':'TypeScript','branch':'main','archived':False,'fork':False},{'id':'sample/lab-experiment','name':'sample/lab-experiment','state':'unreviewed','stack':'Python','branch':'main','archived':False,'fork':False}]
    else:
        try: data=await discover()
        except ProviderError as e: raise HTTPException(503,str(e))
    current={r['id']:r for r in records('repository')}; settings=records('settings'); cfg=settings[0] if settings else {}
    for repo in data:
        if repo['id'] in current: repo['state']=current[repo['id']]['state']
        elif (cfg.get('ignore_archived',True) and repo['archived']) or (cfg.get('ignore_forks',True) and repo['fork']) or any(fnmatch.fnmatch(repo['name'].split('/')[-1],p.strip()) for p in cfg.get('ignore_patterns','').splitlines() if p.strip()): repo['state']='ignored'
        put('repository',repo)
    audit(f'Discovered {len(data)} repositories','repository',u['login']); return records('repository')
@app.patch('/api/repositories/state')
async def repo_state(body:dict,u=Depends(writer)):
    if body.get('state') not in ('managed','ignored','unreviewed'): raise HTTPException(400,'Invalid state')
    r=get(body['id'],'repository'); r['state']=body['state']; put('repository',r); audit(f'{r["name"]} marked {r["state"]}','repository',u['login']); return r
@app.post('/api/repositories/inspect')
async def inspect_repo(body:dict,u=Depends(user)):
    r=get(body['id'],'repository')
    if DEMO: return {'stack':[r['stack']],'recommendations':['HTTP availability check','Lint → tests → security → build → deploy'],'provider':'Vercel' if r['stack'] in ('React','Next.js','TypeScript') else 'GitHub Actions'}
    try:
        token=await installation_token(r.get('installation_id'))
        files=await provider_request('GET',f'https://api.github.com/repos/{r["name"]}/contents',token)
        names=[f['name'] for f in files]; stack=[]
        for pattern,label in [('package.json','Node.js'),('next.config.*','Next.js'),('vite.config.*','Vite'),('requirements.txt','Python'),('pyproject.toml','Python'),('Dockerfile','Docker'),('*compose*yml','Docker Compose'),('vercel.json','Vercel')]:
            if any(fnmatch.fnmatch(n,pattern) for n in names): stack.append(label)
        return {'stack':stack,'recommendations':['Add an HTTP health check','Use the supplied security workflow template'],'provider':'Vercel' if 'Vercel' in stack or 'Next.js' in stack else 'GitHub Actions'}
    except ProviderError as e: raise HTTPException(503,str(e))
@app.post('/api/projects/{id}/deployments')
async def deployment(id:str,body:DeployInput,u=Depends(writer)):
    p=get(id,'project'); provider=PROVIDERS[p['provider']]
    try: p=provider_project(p)
    except ProviderError as e: raise HTTPException(503,str(e))
    if body.action not in provider.capabilities: raise HTTPException(400,'This provider does not support this action')
    if body.environment not in p['environments']: raise HTTPException(400,'Unknown environment')
    findings=[f for f in records('finding') if f['project']==id]
    if body.action not in ('stop','cancel') and gate(findings,p['security_policy']): raise HTTPException(409,'Security gate blocked this action: resolve or acknowledge blocking findings first.')
    history=[d for d in records('deployment') if d['project']==id and d['environment']==body.environment]
    target=get(body.target,'deployment') if body.target else None
    if body.action=='rollback' and not target: raise HTTPException(400,'Choose a rollback target')
    if target and (target['project']!=id or target['environment']!=body.environment or target['status']!='healthy'): raise HTTPException(400,'Rollback target must be a healthy deployment in the same project/environment')
    d={'id':uuid4().hex,'project':id,'project_name':p['name'],'environment':body.environment,'provider':p['provider'],'branch':p['branch'],'commit':target['commit'] if target else '','source':body.action,'actor':u['login'],'status':'queued','started_at':now(),'duration':0,'previous_deployment':history[0]['id'] if history else None,'rollback_target':body.target,'target_external_id':target.get('external_id') if target else (history[0].get('external_id') if history else None),'steps':{'build':'pending','security':'passed','deploy':'pending','verification':'pending'},'logs':[]}
    if DEMO: d['logs']=['Sample mode: action recorded. No external deployment was triggered.']; d['status']='queued'
    else:
        try: d.update(await provider.execute(body.action,p,d))
        except ProviderError as e: raise HTTPException(503,str(e))
    put('deployment',d)
    if d.get('agent_task'):
        put('agent_task',{'id':uuid4().hex,**d['agent_task'],'deployment':d['id'],'status':'queued'})
    audit(f'{p["name"]}: {body.action} queued','deployment',u['login']); return d
@app.get('/api/projects/{id}/builds')
async def builds(id:str,repo:str|None=None,u=Depends(user)):
    p=get(id,'project')
    if repo is not None:
        repository=workflow_repository(p,repo)
    else:
        repo=p.get('repositories',[None])[0]
        repository=workflow_repository(p,repo) if repo else None
    if DEMO: return {'workflow_runs':[d for d in records('deployment') if d['project']==id]}
    try: return await PROVIDERS['GitHub Actions'].builds(p,repo,workflow_token(repository,p) if repository else None)
    except ProviderError as e: raise HTTPException(503,str(e))
@app.get('/api/runners')
async def list_runners(repo:str,u=Depends(user)):
    repository=workflow_repository({'repositories':[repo]},repo)
    if DEMO: return {'runners':[],'repo':repo}
    try:
        token=await installation_token(repository.get('installation_id'))
        data=await provider_request('GET',f'https://api.github.com/repos/{repo}/actions/runners?per_page=100',token)
        return {'repo':repo,'runners':[{'id':r['id'],'name':r['name'],'status':r['status'],'busy':r['busy'],'labels':[l['name'] for l in r.get('labels',[])]} for r in data.get('runners',[])]}
    except ProviderError as e: raise HTTPException(503,str(e))
@app.post('/api/runners/install-command')
async def runner_install_command(body:RunnerInput,u=Depends(admin)):
    repository=next((r for r in records('repository') if r['id']==body.repo and r.get('state')=='managed'),None)
    if not repository: raise HTTPException(400,'Choose a managed repository')
    if DEMO: raise HTTPException(409,'Sample mode cannot issue real GitHub runner registration tokens.')
    try:
        token=await installation_token(repository.get('installation_id'))
        data=await provider_request('POST',f'https://api.github.com/repos/{body.repo}/actions/runners/registration-token',token)
    except ProviderError as e: raise HTTPException(503,str(e))
    name='cicd-runner-'+re.sub(r'[^a-zA-Z0-9_.-]','-',body.name.lower())
    volume='cicd-runner-'+hashlib.sha256(f'{body.repo}:{name}'.encode()).hexdigest()[:10]
    command='docker run --detach --restart unless-stopped --name '+name
    command+=' --volume '+volume+'-data:/runner/data --volume '+volume+'-work:/tmp/runner/work'
    for key,value in [('RUNNER_NAME',body.name),('RUNNER_SCOPE','repo'),('REPO_URL',f'https://github.com/{body.repo}'),('RUNNER_TOKEN',data['token']),('RUNNER_WORKDIR','/tmp/runner/work'),('CONFIGURED_ACTIONS_RUNNER_FILES_DIR','/runner/data'),('LABELS',body.labels),('UNSET_CONFIG_VARS','true')]:
        command+=' --env '+key+'='+shlex.quote(str(value))
    command+=' ghcr.io/myoung34/github-runner:latest'
    return {'repo':body.repo,'name':body.name,'expires_at':data.get('expires_at'),'command':command,'persistent':True,'image':'ghcr.io/myoung34/github-runner:latest','sample':False}
@app.get('/api/organization-patterns')
async def list_organization_patterns(u=Depends(admin)):
    return {'patterns':records('organization_pattern'),'demo':DEMO}
@app.post('/api/organization-patterns')
async def create_organization_pattern(body:OrganizationPatternInput,u=Depends(admin)):
    data={'id':uuid4().hex,'organization':body.organization,'name':body.name.strip(),'path':body.path,'content':body.content,'created_at':now(),'updated_at':now()}
    if not data['name']: raise HTTPException(400,'Pattern name is required')
    put('organization_pattern',data)
    audit(f'{data["name"]} pattern created for {data["organization"]}','workflow',u['login'])
    return data
@app.post('/api/organization-patterns/{pattern_id}/apply')
async def apply_organization_pattern(pattern_id:str,u=Depends(admin)):
    pattern=get(pattern_id,'organization_pattern')
    repos=[r for r in records('repository') if r.get('state')=='managed' and r.get('name','').split('/')[0].casefold()==pattern['organization'].casefold()]
    if not repos: raise HTTPException(400,'No managed repositories found for this organization')
    results=[]
    for repository in repos[:100]:
        if DEMO:
            results.append({'repo':repository['name'],'status':'simulated'})
            continue
        try:
            token=await installation_token(repository.get('installation_id'))
            base_branch=workflow_branch(repository,{})
            url=f'https://api.github.com/repos/{repository["name"]}'
            base=await provider_request('GET',f'{url}/git/ref/heads/{quote(base_branch,safe="")}',token)
            branch=f'cicd/{quote(pattern["name"].lower().replace(" ","-"),safe="-")}-{uuid4().hex[:8]}'
            await provider_request('POST',f'{url}/git/refs',token,json={'ref':f'refs/heads/{branch}','sha':base['object']['sha']})
            workflow_path=quote(pattern['path'],safe='/')
            content_args={'repo':repository['name'],'path':workflow_path,'branch':quote(branch,safe='')}
            try: current=await provider_request('GET',f'{url}/contents/{workflow_path}?ref={content_args["branch"]}',token)
            except ProviderError as e:
                if '404' not in str(e): raise
                current={}
            payload={'message':f'Apply organization pipeline pattern: {pattern["name"]}','content':base64.b64encode(pattern['content'].encode()).decode(),'branch':branch}
            if current.get('sha'): payload['sha']=current['sha']
            await provider_request('PUT',f'{url}/contents/{workflow_path}',token,json=payload)
            pr=await provider_request('POST',f'{url}/pulls',token,json={'title':f'Apply pipeline pattern: {pattern["name"]}','body':f'Applies the shared **{pattern["name"]}** workflow pattern for **{pattern["organization"]}**. Review repository-specific build, secret, and deploy settings before merging.','head':branch,'base':base_branch})
            results.append({'repo':repository['name'],'status':'pull_request_created','html_url':pr['html_url'],'number':pr['number']})
        except ProviderError as e: results.append({'repo':repository['name'],'status':'failed','error':str(e)})
    pattern['updated_at']=now();put('organization_pattern',pattern)
    audit(f'{pattern["name"]} pattern applied to {len(results)} {pattern["organization"]} repositories','workflow',u['login'])
    return {'results':results,'sample':DEMO,'truncated':len(repos)>100}
def workflow_repository(project,repo_name):
    if repo_name not in project.get('repositories',[]): raise HTTPException(400,'Repository is not attached to this project')
    repository=next((r for r in records('repository') if r['id']==repo_name),None)
    if not repository or repository.get('state')!='managed': raise HTTPException(403,'Manage this repository before editing its workflows')
    return repository
def workflow_branch(repository,project):
    return repository.get('branch') or project.get('branch') or 'main'
def workflow_token(repository,project):
    return repository.get('installation_id') or project.get('provider_config',{}).get('installation_id')
@app.get('/api/projects/{id}/workflows')
async def list_workflows(id:str,repo:str,u=Depends(user)):
    project=get(id,'project'); repository=workflow_repository(project,repo)
    if DEMO:
        files=[w for w in records('workflow') if w.get('project')==id and w.get('repo')==repo]
        if not files:
            files=[{'path':'.github/workflows/ci.yml','name':'CI','state':'active'}]
        return {'workflows':[{'path':w['path'],'name':w.get('name',w['path'].rsplit('/',1)[-1]),'state':w.get('state','active')} for w in files]}
    try:
        token=await installation_token(workflow_token(repository,project))
        data=await provider_request('GET',f'https://api.github.com/repos/{repo}/actions/workflows?per_page=100',token)
        return {'workflows':[{'path':w['path'],'name':w['name'],'state':w['state']} for w in data.get('workflows',[]) if w.get('path','').startswith('.github/workflows/') and w.get('path','').endswith(('.yml','.yaml'))]}
    except ProviderError as e: raise HTTPException(503,str(e))
@app.get('/api/projects/{id}/workflows/content')
async def workflow_content(id:str,repo:str,path:str,u=Depends(user)):
    project=get(id,'project'); repository=workflow_repository(project,repo)
    if not path.startswith('.github/workflows/') or '/' in path[len('.github/workflows/'): ] or not path.endswith(('.yml','.yaml')):
        raise HTTPException(400,'Workflow path must be a YAML file directly under .github/workflows/')
    if DEMO:
        saved=next((w for w in records('workflow') if w.get('project')==id and w.get('repo')==repo and w.get('path')==path),None)
        return saved or {'path':path,'name':path.rsplit('/',1)[-1],'content':'name: CI\\non:\\n  workflow_dispatch:\\njobs:\\n  build:\\n    runs-on: ubuntu-latest\\n    steps:\\n      - uses: actions/checkout@v4\\n','branch':workflow_branch(repository,project)}
    try:
        token=await installation_token(workflow_token(repository,project))
        ref=quote(workflow_branch(repository,project),safe='')
        item=await provider_request('GET',f'https://api.github.com/repos/{repo}/contents/{quote(path,safe="/")}?ref={ref}',token)
        return {'path':path,'name':path.rsplit('/',1)[-1],'content':base64.b64decode(item['content']).decode('utf-8'),'sha':item['sha'],'branch':workflow_branch(repository,project)}
    except (ProviderError,KeyError,ValueError,UnicodeDecodeError) as e:
        raise HTTPException(503,f'Unable to read workflow file: {e}')
@app.patch('/api/projects/{id}/workflows')
async def update_workflow(id:str,body:WorkflowUpdate,u=Depends(admin)):
    project=get(id,'project'); repository=workflow_repository(project,body.repo)
    if body.mode not in ('pull_request','direct'): raise HTTPException(400,'Publish mode must be pull_request or direct')
    if body.mode=='direct' and not body.branch: raise HTTPException(400,'Choose a target branch for a direct update')
    default_branch=workflow_branch(repository,project)
    if DEMO:
        existing=next((w for w in records('workflow') if w.get('project')==id and w.get('repo')==body.repo and w.get('path')==body.path),None)
        data={'id':existing['id'] if existing else uuid4().hex,'project':id,'repo':body.repo,'path':body.path,'name':body.path.rsplit('/',1)[-1],'content':body.content,'branch':body.branch or default_branch,'state':'active','mode':body.mode,'updated_at':now()}
        put('workflow',data)
        data['sample']=True
        return data
    try:
        token=await installation_token(workflow_token(repository,project))
        base_branch=body.branch if body.mode=='direct' and body.branch else default_branch
        path=quote(body.path,safe='/'); ref=quote(base_branch,safe='')
        try:
            current=await provider_request('GET',f'https://api.github.com/repos/{body.repo}/contents/{path}?ref={ref}',token)
            sha=current.get('sha')
        except ProviderError as e:
            if '404' not in str(e): raise
            sha=None
        target_branch=base_branch
        if body.mode=='pull_request':
            target_branch=f'cicd/workflow-{uuid4().hex[:12]}'
            base=await provider_request('GET',f'https://api.github.com/repos/{body.repo}/git/ref/heads/{ref}',token)
            await provider_request('POST',f'https://api.github.com/repos/{body.repo}/git/refs',token,json={'ref':f'refs/heads/{target_branch}','sha':base['object']['sha']})
            if sha is not None:
                current=await provider_request('GET',f'https://api.github.com/repos/{body.repo}/contents/{path}?ref={quote(target_branch,safe="")}',token)
                sha=current.get('sha')
        payload={'message':f'Update {body.path}','content':base64.b64encode(body.content.encode()).decode(),'branch':target_branch}
        if sha: payload['sha']=sha
        await provider_request('PUT',f'https://api.github.com/repos/{body.repo}/contents/{path}',token,json=payload)
        result={'repo':body.repo,'path':body.path,'branch':target_branch,'mode':body.mode}
        if body.mode=='pull_request':
            pr=await provider_request('POST',f'https://api.github.com/repos/{body.repo}/pulls',token,json={'title':f'Update workflow: {body.path.rsplit("/",1)[-1]}','body':'Workflow YAML updated from the CI/CD control plane. Please review pipeline stages and permissions before merging.','head':target_branch,'base':base_branch})
            result.update(number=pr['number'],html_url=pr['html_url'])
        audit(f'{project["name"]}: workflow {body.mode} for {body.path}','workflow',u['login'])
        return result
    except HTTPException: raise
    except ProviderError as e: raise HTTPException(503,str(e))
@app.post('/api/deployments/{id}/verify')
async def verify(id:str,u=Depends(writer)):
    d=get(id,'deployment'); checks=[c for c in records('health_check') if c['project']==d['project'] and c.get('required')]
    if d['status'] not in ('verifying','failed'): raise HTTPException(409,'Provider must complete deployment before verification')
    if not checks: raise HTTPException(409,'At least one required health check is needed')
    results=[await run_check(c['id'],u) for c in checks]
    d.setdefault('steps',{})['verification']='passed' if all(r['status']=='healthy' for r in results) else 'failed'; d['status']='healthy' if all(r['status']=='healthy' for r in results) else 'failed'; d['ended_at']=now(); put('deployment',d); audit(f'{d["project_name"]}: verification {d["status"]}','health',u['login']); return d
@app.patch('/api/findings/{id}')
async def finding_state(id:str,body:dict,u=Depends(writer)):
    if body.get('status') not in ('open','acknowledged','ignored','fixed','false_positive'): raise HTTPException(400,'Invalid finding status')
    f=get(id,'finding'); f['status']=body['status']; put('finding',f); audit(f'{f["rule"]}: {f["status"]}','security',u['login']); return f
@app.post('/api/security/import')
async def import_scan(body:dict,u=Depends(writer)):
    p=get(body['project'],'project'); d=get(body['deployment'],'deployment')
    if d['project']!=p['id']: raise HTTPException(400,'Deployment does not belong to project')
    if body['scanner']=='syft':
        payload=body['payload']
        if payload.get('bomFormat')!='CycloneDX': raise HTTPException(400,'CycloneDX format required')
        return put('sbom',{'id':d['id']+'-sbom','project':p['id'],'deployment':d['id'],'commit':d['commit'],'time':now(),'payload':payload})
    try: data=normalize(body['scanner'],body['payload'],p['id'],d['id'])
    except ValueError as e: raise HTTPException(400,str(e))
    for f in data: f.update(first_seen=now(),last_seen=now()); put('finding',f)
    audit(f'{p["name"]}: imported {len(data)} findings','security',u['login']); return {'count':len(data)}
@app.get('/api/deployments/{id}/sbom')
async def sbom(id:str,u=Depends(user)): return get(id+'-sbom','sbom')['payload']
@app.post('/api/health/checks')
async def create_check(body:dict,u=Depends(writer)):
    get(body['project'],'project')
    if not str(body.get('url','')).startswith(('https://','http://')): raise HTTPException(400,'HTTP(S) URL required')
    return put('health_check',{'id':uuid4().hex,'project':body['project'],'name':str(body.get('name','HTTP'))[:100],'url':body['url'],'status':'unknown','latency':0,'history':[],'required':True,'interval':60,'public':False})
@app.post('/api/health/checks/{id}/run')
async def run_check(id:str,u=Depends(writer)):
    c=get(id,'health_check')
    if DEMO: result={'status':c['status'],'latency':c['latency'],'sample':True}
    else:
        try: result=await probe(c['url'])
        except (ValueError,OSError) as e: raise HTTPException(400,str(e))
    old=c['status']; c.update(result); c['history']=(c['history']+[dict(result,time=now())])[-43200:]; c['last_checked']=now(); put('health_check',c)
    p=get(c['project'],'project'); checks=[v for v in records('health_check') if v['project']==p['id']]; p['status']='healthy' if all(v['status']=='healthy' for v in checks) else 'down' if all(v['status']=='down' for v in checks) else 'degraded'; put('project',p)
    if old!=c['status']:
        audit(f'{p["name"]}: {c["name"]} is {c["status"]}','health')
        if c['status']=='down': put('incident',{'id':uuid4().hex,'project':p['id'],'check':id,'started_at':now(),'ended_at':None,'title':f'{c["name"]} unavailable'})
        elif c['status']=='healthy':
            for i in records('incident'):
                if i['check']==id and not i['ended_at']: i['ended_at']=now(); put('incident',i)
    return c
@app.get('/api/public/status')
async def public_status():
    return {'updated_at':now(),'projects':[{'name':p.get('public_name') or p['name'],'description':p.get('public_description',''),'status':p['status'],'incidents':[{'started_at':i['started_at'],'ended_at':i['ended_at']} for i in records('incident') if i['project']==p['id']]} for p in records('project') if p.get('public')]}
@app.get('/api/settings')
async def settings(u=Depends(admin)):
    data=records('settings'); return (data[0] if data else {'id':'settings','workspace':'My workspace'}) | {'integrations':{'GitHub App':bool(os.getenv('GITHUB_APP_ID')),'GitHub OAuth':bool(os.getenv('GITHUB_CLIENT_ID')),'Vercel':bool(os.getenv('VERCEL_TOKEN')),'Email':bool(os.getenv('SMTP_HOST')),'Telegram':bool(os.getenv('TELEGRAM_BOT_TOKEN'))},'demo':DEMO}
@app.patch('/api/settings')
async def save_settings(body:dict,u=Depends(admin)):
    allowed={'workspace','ignore_archived','ignore_forks','ignore_patterns','notification_email','telegram_chat_id','notify_success','log_retention_days'}
    data=records('settings'); cfg=data[0] if data else {'id':'settings'}; cfg.update({k:v for k,v in body.items() if k in allowed}); put('settings',cfg); audit('Workspace settings updated',actor=u['login']); return cfg
@app.get('/api/integrations/accounts')
async def list_integration_accounts(u=Depends(admin)):
    return {'accounts':records('integration_account'),'demo':DEMO}
@app.post('/api/integrations/accounts')
async def add_integration_account(body:ProviderAccountInput,u=Depends(admin)):
    supported={'GitHub Pages','Cloudflare Pages','Vercel','Zoho Catalyst'}
    if body.provider not in supported: raise HTTPException(400,'Unsupported deployment provider')
    if body.provider in ('Cloudflare Pages','Vercel') and not body.access_token and not DEMO: raise HTTPException(400,'An API token is required for this provider')
    if body.provider in ('GitHub Pages','Zoho Catalyst') and body.access_token: raise HTTPException(400,'Store these deployment credentials as GitHub Actions environment secrets; workflow inputs must never carry tokens.')
    if body.provider=='Cloudflare Pages':
        if not re.fullmatch(r'[a-fA-F0-9]{32}',body.account_id): raise HTTPException(400,'Cloudflare account ID must be 32 hexadecimal characters')
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]*',body.project_name): raise HTTPException(400,'Cloudflare Pages project name must use lowercase letters, numbers, and hyphens')
    if body.provider=='GitHub Pages' and not body.account_id: raise HTTPException(400,'Enter the GitHub owner or organization for this account')
    if body.provider=='Zoho Catalyst' and not body.project_name: raise HTTPException(400,'Enter the Catalyst project name')
    key=os.getenv('MASTER_ENCRYPTION_KEY')
    if body.access_token and not DEMO and not key: raise HTTPException(503,'Set MASTER_ENCRYPTION_KEY to store integration credentials securely.')
    account_id=uuid4().hex
    data={'id':account_id,'name':body.name.strip(),'provider':body.provider,'account_id':body.account_id.strip(),'project_name':body.project_name.strip(),'team_id':body.team_id.strip(),'credential_configured':bool(body.access_token) and not DEMO if body.provider in ('Cloudflare Pages','Vercel') else False,'created_at':now()}
    if not data['name']: raise HTTPException(400,'Account name is required')
    if body.access_token and not DEMO:
        try:
            if body.provider=='Cloudflare Pages':
                verified=await provider_request('GET','https://api.cloudflare.com/client/v4/user/tokens/verify',body.access_token)
                if verified.get('result',{}).get('status')!='active': raise ProviderError('Cloudflare API token is not active')
            elif body.provider=='Vercel':
                await provider_request('GET','https://api.vercel.com/v2/user',body.access_token)
        except ProviderError as e: raise HTTPException(400,f'Could not verify {body.provider} credentials: {e}')
        cipher=Fernet(key.encode()).encrypt(body.access_token.encode()).decode()
        with Session() as db:
            db.add(Secret(id=f'integration:{account_id}',project='integration',environment='workspace',name='ACCESS_TOKEN',ciphertext=cipher))
            db.commit()
    put('integration_account',data)
    audit(f'{body.provider} account "{data["name"]}" added','integration',u['login'])
    if body.provider in ('GitHub Pages','Zoho Catalyst'):
        data['note']='Deployments use a repository GitHub Actions workflow. Keep provider credentials in GitHub Actions environment secrets; do not paste them into workflow_dispatch inputs.'
    if DEMO: data['sample']=True
    return data
@app.delete('/api/integrations/accounts/{account_id}')
async def delete_integration_account(account_id:str,u=Depends(admin)):
    account=get(account_id,'integration_account')
    linked=[p['name'] for p in records('project') if p.get('provider_config',{}).get('integration_account_id')==account_id]
    if linked: raise HTTPException(409,'This account is selected by: '+', '.join(linked))
    with Session() as db:
        secret=db.get(Secret,f'integration:{account_id}')
        if secret: db.delete(secret)
        record=db.get(Record,account_id)
        if record: db.delete(record)
        db.commit()
    audit(f'{account["provider"]} account "{account["name"]}" removed','integration',u['login'])
    return {'ok':True}
def integration_access_token(account_id):
    key=os.getenv('MASTER_ENCRYPTION_KEY')
    if not key: raise ProviderError('Set MASTER_ENCRYPTION_KEY to use connected deployment accounts.')
    with Session() as db: secret=db.get(Secret,f'integration:{account_id}')
    if not secret: raise ProviderError('Connected account credential is missing. Reconnect the provider account.')
    try: return Fernet(key.encode()).decrypt(secret.ciphertext.encode()).decode()
    except Exception as e: raise ProviderError('Could not decrypt connected account credentials; check MASTER_ENCRYPTION_KEY.') from e
def provider_project(project):
    p=dict(project)
    p['provider_config']=dict(project.get('provider_config',{}))
    if p.get('repositories'):
        repository=next((r for r in records('repository') if r['id']==p['repositories'][0]),None)
        if repository:
            p['provider_config'].setdefault('installation_id',repository.get('installation_id'))
    account_id=p['provider_config'].get('integration_account_id')
    if account_id:
        account=get(account_id,'integration_account')
        if account.get('provider')!=p['provider']:
            raise ProviderError('Selected deployment account does not match the project provider.')
        if account.get('provider')=='Cloudflare Pages':
            p['provider_config']['account_id']=account.get('account_id','')
            p['provider_config']['project_name']=account.get('project_name','')
        if account.get('provider')=='Vercel' and account.get('team_id'):
            p['provider_config']['team_id']=account['team_id']
        if account.get('provider') in ('Vercel','Cloudflare Pages') and not DEMO:
            p['provider_config']['integration_token']=integration_access_token(account_id)
    return p
@app.get('/api/projects/{id}/secrets')
async def list_secrets(id:str,u=Depends(admin)):
    with Session() as db: return [{'id':s.id,'name':s.name,'environment':s.environment} for s in db.query(Secret).filter_by(project=id).all()]
@app.post('/api/projects/{id}/secrets')
async def save_secret(id:str,body:SecretInput,u=Depends(admin)):
    get(id,'project'); key=os.getenv('MASTER_ENCRYPTION_KEY')
    if not key: raise HTTPException(503,'Set MASTER_ENCRYPTION_KEY on the server to enable encrypted secret storage.')
    sid=f'{id}:{body.environment}:{body.name}'
    with Session() as db:
        s=db.get(Secret,sid); ciphertext=Fernet(key.encode()).encrypt(body.value.encode()).decode()
        if s: s.ciphertext=ciphertext
        else: db.add(Secret(id=sid,project=id,environment=body.environment,name=body.name,ciphertext=ciphertext))
        db.commit()
    audit(f'{body.name} secret stored for {id}',actor=u['login']); return {'name':body.name,'environment':body.environment}
@app.delete('/api/projects/{id}/secrets/{name}')
async def delete_secret(id:str,name:str,environment:str='production',u=Depends(admin)):
    with Session() as db:
        s=db.get(Secret,f'{id}:{environment}:{name}')
        if not s: raise HTTPException(404,'Secret not found')
        db.delete(s); db.commit()
    audit(f'{name} secret deleted for {id}',actor=u['login']); return {'ok':True}
@app.post('/api/services/{id}/{action}')
async def service_action(id:str,action:str,u=Depends(admin)):
    if action not in ('restart','stop'): raise HTTPException(400,'Unsupported action')
    s=get(id,'service')
    if DEMO: s['status']='stopped' if action=='stop' else 'healthy'; put('service',s)
    else: put('agent_task',{'id':uuid4().hex,'agent_id':s['host'],'service':s['name'],'action':action,'status':'queued'})
    audit(f'{s["name"]}: {action} requested','infrastructure',u['login']); return s
@app.post('/api/webhooks/github')
async def webhook(req:Request):
    key=os.getenv('GITHUB_WEBHOOK_SECRET')
    if not key: raise HTTPException(503,'Webhook not configured')
    body=await req.body()
    expected='sha256='+hmac.new(key.encode(),body,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(req.headers.get('x-hub-signature-256',''),expected): raise HTTPException(401,'Invalid signature')
    delivery=req.headers.get('x-github-delivery','')
    if not delivery: raise HTTPException(400,'Delivery ID required')
    with Session() as db:
        if db.get(Record,'hook-'+delivery): return {'duplicate':True}
    payload=json.loads(body); event=req.headers.get('x-github-event'); put('webhook',{'id':'hook-'+delivery,'event':event,'time':now()})
    if event=='workflow_run':
        run=payload['workflow_run']; repo=payload['repository']['full_name']
        for p in records('project'):
            if repo not in p['repositories']: continue
            existing=next((d for d in records('deployment') if d['project']==p['id'] and d.get('external_id')==str(run['id'])),None)
            d=existing or {'id':uuid4().hex,'project':p['id'],'project_name':p['name'],'environment':'production','provider':'GitHub Actions','source':'push','actor':run['actor']['login'],'started_at':run['created_at'],'duration':0,'logs':[],'steps':{'build':'pending','security':'passed','deploy':'pending','verification':'pending'}}
            d.setdefault('steps',{})
            for _k in ('build','security','deploy','verification'): d['steps'].setdefault(_k,'pending')
            d.update(external_id=str(run['id']),commit=run['head_sha'],branch=run['head_branch'],status='verifying' if run.get('conclusion')=='success' else 'failed' if run.get('conclusion') in ('failure','timed_out') else 'cancelled' if run.get('conclusion')=='cancelled' else 'building')
            put('deployment',d)
    audit(f'GitHub {event} received','repository'); return {'ok':True}

@app.post('/api/agents/register')
async def register_agent(body:dict,u=Depends(admin)):
    name=str(body.get('name','')).strip()
    if not name or len(name)>80: raise HTTPException(400,'Host name required, maximum 80 characters')
    token=secrets.token_urlsafe(40);id=uuid4().hex
    put('agent',{'id':id,'name':name,'token_hash':hashlib.sha256(token.encode()).hexdigest(),'capabilities':['docker','metrics','deploy'],'version':'1.0.0'})
    put('host',{'id':id,'name':name,'status':'offline','cpu':0,'ram':0,'disk':0,'version':'1.0.0','last_seen':now(),'capabilities':['docker','metrics','deploy']})
    audit(f'{name}: agent registered','infrastructure',u['login']);return {'id':id,'token':token,'message':'Store this token on the host. It is shown only once.'}
async def agent_identity(req:Request):
    id=req.headers.get('x-agent-id','');authorization=req.headers.get('authorization','')
    if not authorization.startswith('Bearer '): raise HTTPException(401,'Agent token required')
    try: a=get(id,'agent')
    except HTTPException: raise HTTPException(401,'Unknown agent')
    if not secrets.compare_digest(a['token_hash'],hashlib.sha256(authorization[7:].encode()).hexdigest()): raise HTTPException(401,'Invalid agent token')
    return a
@app.post('/api/agent/heartbeat')
async def heartbeat(body:dict,a=Depends(agent_identity)):
    h=get(a['id'],'host');h.update(status='online',last_seen=now(),version=str(body.get('version','unknown'))[:50])
    for metric in ['cpu','ram','disk']:
        try: h[metric]=max(0,min(100,float(body.get(metric,0))))
        except (TypeError,ValueError): raise HTTPException(400,'Invalid metric')
    put('host',h)
    for service in body.get('services',[])[:100]:
        name=str(service.get('name',''))[:100]
        put('service',{'id':a['id']+':'+name,'host':a['id'],'name':name,'status':service.get('status','unknown'),'image':str(service.get('image',''))[:200],'port':service.get('port','')})
    return {'ok':True}
@app.get('/api/agent/tasks')
async def agent_tasks(a=Depends(agent_identity)):
    tasks=[]
    with Session() as db:
        rows=db.query(Record).filter_by(kind='agent_task').with_for_update().all()
        for r in rows:
            d=r.data
            claimed=d.get('claimed_at')
            lease_expired=d.get('status')=='running' and claimed and (datetime.now(timezone.utc)-datetime.fromisoformat(claimed)).total_seconds()>600
            if d.get('agent_id')==a['id'] and (d.get('status')=='queued' or lease_expired):
                d=dict(d,status='running',claimed_at=now());r.data=d;tasks.append(d)
                if len(tasks)>=5: break
        db.commit()
    return tasks
@app.post('/api/agent/tasks/{id}/result')
async def task_result(id:str,body:dict,a=Depends(agent_identity)):
    t=get(id,'agent_task')
    if t['agent_id']!=a['id'] or t['status']!='running': raise HTTPException(409,'Task is not assigned to this agent or already completed')
    t['status']='completed' if body.get('success') is True else 'failed';t['ended_at']=now()
    # Arbitrary process output may contain secrets: only store bounded status messages.
    t['message']='Agent operation completed' if body.get('success') else 'Agent operation failed; inspect logs on host'
    put('agent_task',t)
    if t.get('deployment'):
        d=get(t['deployment'],'deployment');d['status']='verifying' if body.get('success') else 'failed';d.setdefault('steps',{})['deploy']='passed' if body.get('success') else 'failed';d['logs']+= [t['message']];put('deployment',d)
    audit(f'{a["name"]}: {t["action"]} {t["status"]}','infrastructure',a['name']);return {'ok':True}
@app.get('/api/deployments/{id}/logs')
async def deployment_logs(id:str,u=Depends(user)):
    d=get(id,'deployment');return {'lines':d.get('logs',[])}
@app.get('/api/events')
async def events(req:Request,u=Depends(user)):
    import asyncio
    from fastapi.responses import StreamingResponse
    async def stream():
        previous=None
        while not await req.is_disconnected():
            latest=records('activity')[:1]; marker=latest[0]['id'] if latest else ''
            if marker!=previous: yield 'data: '+json.dumps({'type':'refresh','id':marker})+'\n\n';previous=marker
            else: yield ': keepalive\n\n'
            await asyncio.sleep(5)
    return StreamingResponse(stream(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})
