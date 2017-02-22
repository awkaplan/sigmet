import json
import logging
import re
from argparse import ArgumentParser
from datetime import datetime, timedelta

import jwt
import requests
from f5.bigip import ManagementRoot

logging.basicConfig(level=logging.INFO)

ap = ArgumentParser()
ap.add_argument('-m', '--marathon', type=str, required=True, help='Path to Marathon')
ap.add_argument('-b', '--bhost', type=str, required=True, help='F5 Host')
ap.add_argument('-u', '--user', type=str, required=True, help='F5 Management User')
ap.add_argument('-p', '--password', type=str, required=True, help='F5 Management Password')
ap.add_argument('--partition', type=str, default='Common', help='Administrative Partition')
ap.add_argument('--prefix', type=str, default='marathon', help='Pool Name Prefix')
ap.add_argument('--insecure', action='store_false', help='Verify SSL Certificates')
ap.add_argument('--role_user', type=str, help='DC/OS Role Account')
ap.add_argument('--role_cert', type=str, help='DC/OS Role Certificate')
ap.add_argument('--dcos_master', type=str, help='DC/OS Master')

args = ap.parse_args()

req_role_params = [args.role_user, args.role_cert, args.dcos_master]
if any(req_role_params) and not all(req_role_params):
    ap.error('Must supply --role_user, --role_cert and --dcos_master')

if not args.insecure:
    logging.info('Disabled SSL verification')
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

pool_re = re.compile('^{}_.+'.format(args.prefix))

s = requests.Session()
s.headers.update({'Cache-Control': 'no-cache'})
s.verify = args.insecure

mgmt = ManagementRoot(args.bhost, args.user, args.password)


def get_token():
    token = jwt.encode({'uid': args.role_user}, args.role_cert, algorithm='RS256')
    token_data = {
        'uid': args.role_user,
        'token': token
    }
    auth_req = s.post(
        'https://{}/acs/api/v1/auth/login'.format(args.dcos_master),
        headers={'Content-type': 'application/json'},
        data=json.dumps(token_data)
    )
    auth_req.raise_for_status()
    s.headers.update({'Authorization': 'token={}'.format(auth_req.json()['token'])})
    return datetime.now()


def get_pools():
    return [pool.name for pool in mgmt.tm.ltm.pools.get_collection()]


def get_members(pool):
    pool_obj = mgmt.tm.ltm.pools.pool
    p = pool_obj.load(name=pool)
    return [member.name for member in p.members_s.get_collection()]


def create_pool(pool):
    logging.info('Creating pool {}'.format(pool))
    return mgmt.tm.ltm.pools.pool.create(name=pool)


def delete_pool(pool):
    logging.info('Deleting pool {}'.format(pool))
    p = mgmt.tm.ltm.pools.pool.load(name=pool)
    return p.delete()


def create_member(pool, member):
    logging.info('Creating member {} for pool {}'.format(member, pool))
    p = mgmt.tm.ltm.pools.pool.load(name=pool)
    return p.members_s.members.create(partition=args.partition, name=member)


def gen_full_pool_id(pid):
    return args.prefix + pid.replace('/', '_')


def gen_task_id(host, port):
    return '{}:{}'.format(host, port)


def gen_pool_dict():
    tmp = {}
    for pool in get_pools():
        if pool_re.match(pool):
            tmp[pool] = get_members(pool)
    return tmp


def start_stream():
    logging.info('Connecting to event stream')
    stream_req = s.get(
        '{}/v2/events'.format(args.marathon),
        stream=True,
        headers={'Accept': 'text/event-stream'}
    )
    stream_req.raise_for_status()
    return stream_req


def delete_member(pool, task):
    logging.info('Deleting member {} from pool {}'.format(task, pool))
    p = mgmt.tm.ltm.pools.pool.load(name=pool)
    m = p.members_s.members.load(partition=args.partition, name=task)
    return m.delete()


def gen_marathon_task_dict():
    task_dict = {}
    tasks_req = s.get(
        '{}/v2/tasks'.format(args.marathon)
    )
    tasks_req.raise_for_status()
    for task in tasks_req.json()['tasks']:
        app_id = gen_full_pool_id(task['appId'])
        if not app_id in task_dict:
            task_dict[app_id] = []
        task_dict[app_id].append(gen_task_id(task['host'], task['ports'][0]))
    return task_dict


def reconcile_tasks():
    marathon_dict = gen_marathon_task_dict()
    pool_dict = gen_pool_dict()

    for pool in marathon_dict:
        if pool not in pool_dict:
            create_pool(pool)
        for task in marathon_dict[pool]:
            if pool in pool_dict and task not in pool_dict[pool]:
                create_member(pool, task)

    for pool in pool_dict:
        for task in pool_dict[pool]:
            if pool in marathon_dict and task not in marathon_dict[pool]:
                delete_member(pool, task)
        if pool not in marathon_dict:
            delete_pool(pool)


def check_token():
    if token_issue_time and datetime.now() > (token_issue_time + timedelta(days=1)):
        logging.info('Refreshing token')
        get_token()


if args.role_user:
    token_issue_time = get_token()

reconcile_tasks()
for line in start_stream().iter_lines():
    if line.strip()[:6] == 'data: ':
        data = json.loads(line[6:])
        if data['eventType'] == 'status_update_event':
            check_token()
            logging.debug(json.dumps(data))
            reconcile_tasks()
