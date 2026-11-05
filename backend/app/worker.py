"""Durable Redis/Dramatiq work; run scheduler as exactly one replica."""
import os,asyncio,time
from datetime import datetime,timezone,timedelta
import dramatiq
from dramatiq.brokers.redis import RedisBroker
from .main import records,get,put,audit,run_check,verify,provider_project,DEMO,now
from .providers import PROVIDERS,ProviderError
from .notifications import deliver
broker=RedisBroker(url=os.getenv('REDIS_URL','redis://localhost:6379/0'));dramatiq.set_broker(broker)
SYSTEM={'login':'worker','role':'admin'}
@dramatiq.actor(max_retries=2,time_limit=60000)
def health_job(id):
    asyncio.run(run_check(id,SYSTEM))
@dramatiq.actor(max_retries=3,time_limit=60000)
def provider_job(id):
    async def run():
        d=get(id,'deployment');p=provider_project(get(d['project'],'project'))
        if d['status'] in ('healthy','failed','cancelled','rolled_back'):return
        if d['status']=='verifying':
            await verify(id,SYSTEM);return
        if not d.get('external_id'):return
        result=await PROVIDERS[p['provider']].status(p,d['external_id'])
        state=result.get('readyState') or result.get('status')
        if state=='READY' or result.get('conclusion')=='success': d['status']='verifying';d.setdefault('steps',{})['deploy']='passed'
        elif state in ('ERROR','CANCELED') or result.get('conclusion') in ('failure','timed_out','cancelled'): d['status']='failed'
        else: d['status']='building'
        put('deployment',d)
    asyncio.run(run())
@dramatiq.actor(max_retries=3,time_limit=60000)
def notification_job(id):
    e=get(id,'activity');cfg=records('settings');cfg=cfg[0] if cfg else {}
    # Retries only resend channels whose delivery has not completed.
    nid='notification-'+id
    try:
        sent=get(nid,'notification')
        if sent.get('status')=='sent':return
    except Exception:pass
    channels=deliver(e,cfg)
    put('notification',{'id':nid,'event':id,'channels':channels,'status':'sent','time':now()})
def schedule():
    if DEMO: raise RuntimeError('Background worker is disabled in sample mode')
    last_notifications=datetime.now(timezone.utc)
    while True:
        current=datetime.now(timezone.utc)
        for c in records('health_check'):
            last=datetime.fromisoformat(c.get('last_checked') or '2000-01-01T00:00:00+00:00')
            if (current-last).total_seconds()>=max(30,c.get('interval',60)):health_job.send(c['id'])
        for d in records('deployment'):
            if d['status'] in ('queued','building','deploying','verifying'):provider_job.send(d['id'])
        for h in records('host'):
            if h['status']=='online' and (current-datetime.fromisoformat(h['last_seen'])).total_seconds()>120:
                h['status']='offline';put('host',h);audit(f'{h["name"]}: host offline','infrastructure')
        cfg=records('settings');cfg=cfg[0] if cfg else {}
        for e in records('activity'):
            if datetime.fromisoformat(e['time'])<=last_notifications:continue
            title=e['title'].lower()
            if any(word in title for word in ['down','failed','rollback','critical','secret detected','offline']) or (cfg.get('notify_success') and 'healthy' in title):notification_job.send(e['id'])
        last_notifications=current
        time.sleep(30)
if __name__=='__main__':schedule()
