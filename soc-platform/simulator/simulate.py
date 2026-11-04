"""Generate harmless synthetic SOC telemetry for the local demo."""
import argparse, random, time
from datetime import datetime, timezone
import requests

p=argparse.ArgumentParser();p.add_argument('--url',default='http://localhost:8080/api/logs/single');p.add_argument('--mode',choices=['normal','bruteforce','offhours','bulk'],default='normal');p.add_argument('--count',type=int,default=20);p.add_argument('--delay',type=float,default=.4);p.add_argument('--email',default='admin@soc.local');p.add_argument('--password',default='ChangeMe123!');a=p.parse_args()
base=a.url.split('/api/')[0]
login=requests.post(base+'/api/auth/login',json={'email':a.email,'password':a.password},timeout=5);login.raise_for_status()
headers={'Authorization':'Bearer '+login.json()['token']}
for i in range(a.count):
    event={"timestamp":datetime.now(timezone.utc).isoformat(),"sourceType":"LOGIN","username":f'user{random.randint(1,8)}',"ip":f'198.51.100.{random.randint(1,20)}',"host":"workstation-demo","action":"login","outcome":"SUCCESS","extra":{}}
    if a.mode=='bruteforce': event.update(ip='203.0.113.77',username='demo-admin',outcome='FAILURE')
    elif a.mode=='offhours': event.update(timestamp=datetime.now(timezone.utc).replace(hour=2).isoformat(),action='login')
    elif a.mode=='bulk': event.update(sourceType='FILE',action='file_access',extra={'filesAccessed':35,'bytesTransferred':500000000})
    r=requests.post(a.url,json=event,headers=headers,timeout=5); print(r.status_code,event['sourceType'],event['action'],event['outcome']);time.sleep(a.delay)