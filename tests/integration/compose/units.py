#!/usr/bin/env python3
"""deploy/compose 的两个 systemd 单元之间的关系：池的单元（idp-gateway-pool.service）和看守的单元
（idp-gateway-pool-keep.service）。在这台机器上用户级的 systemd 里跑，用的是两个单元文件本身，
只是里面的命令换成了替身：不起容器，不要 docker 和 go。

    python3 tests/integration/compose/units.py        # 一分钟左右；只用标准库

看的是单元文件自己说的那些事：
    看守跟着池的单元启动，在它的启动命令跑完之后；ExecStart 里的 ${…} 从 .env 取到值，拼出来的就是
    gateway-control keep 要的那组参数；.env 里的变量也都在它的环境里（它跑 docker compose 时带着的就是这些）；
    看守被杀掉之后由 systemd 重新起来，池的单元不受影响；它以退出码 2 结束（命令行写得不对）就不再起；
    停池的单元时看守先停，它手上的那条命令让它跑完，然后才是池的停止命令；
    池的单元启动失败时看守照样起来；这时停池的单元，看守停了，池的停止命令却不会跑。

与真的不一样的地方（每次运行都把改动逐行记在结果里）：
    /usr/bin/docker 换成了一个替身，它只记下自己被怎么叫的；.env 里 GATEWAY_CONTROL 指的也是一个替身，
    它记下自己拿到的参数，然后装作一直有一条 docker compose 命令在跑；
    Requires=docker.service、After= 里的 docker.service 和两个 target、Wants=network-online.target 去掉了：
    它们是系统级的单元，用户级的 systemd 不认识；
    User=、Group= 去掉了：用户级的 systemd 换不了账号；
    WorkingDirectory、EnvironmentFile 指到本次运行的目录。

没有看的：系统级的 systemd，开机和关机，与 docker.service 的先后，User= 换账号，以及真的命令在单元里跑。
真的看守、真的 docker compose 由 run.py 的 SH-16 到 SH-18 在单元之外跑；两个单元里写的命令由 SH-19 原样跑一遍，
也不经 systemd。两个单元都没有装到哪台机器上跑过。

单元文件放在 $XDG_RUNTIME_DIR/systemd/user 里（内存文件系统），跑完就删。用户级的 systemd 里已经有
这两个名字的单元时，本脚本不动手。
"""
from __future__ import annotations
import difflib, json, os, re, shutil, signal, subprocess, sys, time, traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEPLOY = ROOT / 'deploy/compose'
WORK = HERE / '.run' / 'units'    # 本次运行的东西：两个替身、.env、它们写的日志
LOG = WORK / 'log'
RESULT = HERE / '.run' / 'units-result.json'
RUNTIME = Path(os.environ.get('XDG_RUNTIME_DIR') or f'/run/user/{os.getuid()}')
UNITS = RUNTIME / 'systemd' / 'user'
POOL, KEEP = 'idp-gateway-pool.service', 'idp-gateway-pool-keep.service'
MARK = '# tests/integration/compose/units.py 放在这里的，跑完就删。'
RESTART_SECONDS = 5   # 看守的单元里的 RestartSec

# 运维会写进 .env 的那些变量在这次运行里的值。文件不必真的有：替身不去读它们。
SETTINGS = {
    'CALLERS_LISTEN': '127.0.0.1:27620', 'READBACK_PORT': '27619', 'READBACK_NAME': 'readback.gateway.idp.test',
    'POOL_DIR': str(WORK / 'pool'), 'GATEWAY_USER': f'{os.getuid()}:{os.getgid()}', 'CONTROL_USER': f'{os.getuid()}:{os.getgid()}',
    'GATEWAY_ENV_FILE': str(WORK / 'gateway.env'), 'GATEWAY_CONTROL': str(WORK / 'gateway-control'),
    'PUBLISHER_CERT': str(WORK / 'publisher.crt'), 'PUBLISHER_KEY': str(WORK / 'publisher.key'), 'READBACK_CA': str(WORK / 'ca.crt'),
}
# 看守该拿到的参数：deploy/compose/README.md 里要读回读口的命令都带的那一组。
EXPECTED = ['keep', '--config-dir', SETTINGS['POOL_DIR'] + '/config',
            '--read-back', '127.0.0.1:' + SETTINGS['READBACK_PORT'], '--read-back-name', SETTINGS['READBACK_NAME'],
            '--tls-cert', SETTINGS['PUBLISHER_CERT'], '--tls-key', SETTINGS['PUBLISHER_KEY'], '--tls-ca', SETTINGS['READBACK_CA']]

# 两个替身是同一个脚本。docker：记下怎么被叫的，过 1 秒退出；WORK 里有 fail-up 这个文件时，compose up 以 1 退出。
# keeper：记下拿到的参数；WORK 里有 exit-2 时以 2 退出；否则一直跑，手上总有一个要 3 秒才做完的子进程
# （装作一条 docker compose 命令）。收到终止信号时等那个子进程做完，以 0 退出。
# child：那个子进程。它自己收到终止信号会记下来。
STAND_IN = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path

WORK = Path(__file__).resolve().parent


def log(who, event, **more):
    with open(WORK / 'log', 'a', encoding='utf-8') as f:
        f.write(json.dumps({'at': time.time(), 'who': who, 'pid': os.getpid(), 'event': event, **more}) + '\n')


role, argv = sys.argv[1], sys.argv[2:]
if role == 'docker':
    log('docker', 'begin', argv=argv, cwd=os.getcwd())
    time.sleep(1)
    code = 1 if argv[:2] == ['compose', 'up'] and (WORK / 'fail-up').exists() else 0
    log('docker', 'end', argv=argv, code=code)
    sys.exit(code)
if role == 'child':
    def told(*_):
        log('child', 'TERM')
        sys.exit(143)
    signal.signal(signal.SIGTERM, told)
    log('child', 'begin', parent=os.getppid())
    time.sleep(3)
    log('child', 'end')
    sys.exit(0)

names = [line.split('=', 1)[0] for line in (WORK / '.env').read_text(encoding='utf-8').splitlines() if '=' in line]
log('keeper', 'start', argv=argv, cwd=os.getcwd(), env={name: os.environ.get(name) for name in names})
if (WORK / 'exit-2').exists():
    log('keeper', 'exit', code=2)
    sys.exit(2)
stopping, child = [], None


def stop(*_):
    stopping.append(time.time())
    log('keeper', 'TERM', child_running=child is not None and child.poll() is None)


signal.signal(signal.SIGTERM, stop)
while not stopping:
    child = subprocess.Popen([sys.executable, __file__, 'child'])
    child.wait()
log('keeper', 'exit', code=0)
'''


def die(message: str):
    print('units.py:', message, file=sys.stderr)
    raise SystemExit(2)


def sc(*argv: str) -> subprocess.CompletedProcess:
    """systemctl --user：这个账号自己的那个 systemd。"""
    return subprocess.run(['systemctl', '--user', *argv], capture_output=True, text=True, timeout=120,
                          env={**os.environ, 'XDG_RUNTIME_DIR': str(RUNTIME)})


def show(unit: str, what: str) -> str:
    return sc('show', '-p', what, '--value', unit).stdout.strip()


def active(unit: str) -> str:
    return sc('is-active', unit).stdout.strip()


def main_pid(unit: str) -> int:
    return int(show(unit, 'MainPID') or 0)


def events(since: float = 0.0) -> list[dict]:
    """两个替身自 since（Unix 时间）以来记下的事，按先后。"""
    if not LOG.exists():
        return []
    found = [json.loads(line) for line in LOG.read_text(encoding='utf-8').splitlines() if line.strip()]
    return sorted((e for e in found if e['at'] >= since), key=lambda e: e['at'])


def seen(log: list[dict], who: str, event: str) -> list[dict]:
    return [e for e in log if e['who'] == who and e['event'] == event]


def order(log: list[dict]) -> list[str]:
    """一段日志里各件事的先后："谁 事"；docker 的带着它被叫去做什么。"""
    return [f"{e['who']} {e['event']}" + (' ' + ' '.join(e['argv']) if e['who'] == 'docker' else '')
            for e in log if (e['who'], e['event']) != ('child', 'begin')]


def wait_for(predicate, seconds: float, every: float = 0.1):
    """-> predicate() 第一次成立时过了多少秒；到时还不成立则 None。"""
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if predicate():
            return round(time.monotonic() - started, 2)
        time.sleep(every)
    return None


def came_back(pid: int, since: float) -> bool:
    """看守换了一个进程在跑，而且新的那个已经记下了自己的启动（它记下来要比 systemd 说它在跑晚一点）。"""
    return main_pid(KEEP) not in (0, pid) and active(KEEP) == 'active' and bool(seen(events(since), 'keeper', 'start'))


def busy_keeper() -> float:
    """等到看守手上刚开始一条要 3 秒才做完的命令。-> 这一刻的 Unix 时间。"""
    since = time.time()
    if wait_for(lambda: any(e.get('parent') == main_pid(KEEP) for e in seen(events(since), 'child', 'begin')), 10, 0.05) is None:
        raise AssertionError('看守的替身一直没有开始下一条命令')
    return time.time()


# ---- 单元文件 ---------------------------------------------------------------------------------------
def adapted(name: str) -> str:
    """deploy/compose 里的一个单元文件，改成用户级的 systemd 跑得了、命令是替身的样子。别的一个字不动。"""
    lines = [MARK]
    for line in (DEPLOY / name).read_text(encoding='utf-8').splitlines():
        if line.startswith('#'):
            lines.append(line)
            continue
        if line in ('Requires=docker.service', 'Wants=network-online.target') or line.startswith(('User=', 'Group=')):
            continue
        if line.startswith('After='):
            kept = [unit for unit in line.split('=', 1)[1].split() if unit == POOL]
            if not kept:
                continue
            line = 'After=' + ' '.join(kept)
        if line.startswith('WorkingDirectory='):
            line = f'WorkingDirectory={WORK}'
        if line.startswith('EnvironmentFile='):
            line = f'EnvironmentFile={WORK}/.env'
        lines.append(line.replace('/usr/bin/docker ', f'{WORK}/docker '))
    return '\n'.join(lines) + '\n'


def changes(name: str) -> list[str]:
    """改动了哪些行：- 是原来的，+ 是这次运行用的。"""
    original = (DEPLOY / name).read_text(encoding='utf-8').splitlines()
    return [line for line in difflib.unified_diff(original, adapted(name).splitlines(), lineterm='', n=0)
            if line[:1] in '+-' and line[:3] not in ('+++', '---') and line[1:] != MARK]


def example_required() -> list[str]:
    """deploy/compose/.env.example 里要填的变量（"名字=" 开头的行）。"""
    return [m.group(1) for m in (re.match(r'([A-Z][A-Z0-9_]*)=', line)
                                 for line in (DEPLOY / '.env.example').read_text(encoding='utf-8').splitlines()) if m]


def ours(path: Path) -> bool:
    try:
        return path.read_text(encoding='utf-8').startswith(MARK)
    except OSError:
        return False


def remove_units():
    """停下两个单元，把本脚本放的单元文件删掉。不是本脚本放的不碰。"""
    if not any(ours(UNITS / name) for name in (POOL, KEEP)):
        return
    sc('stop', KEEP, POOL)
    sc('disable', '--runtime', KEEP)
    for name in (POOL, KEEP):
        if ours(UNITS / name):
            (UNITS / name).unlink()
    for directory in (UNITS / f'{POOL}.wants', UNITS):
        try:
            directory.rmdir()   # 只删空的：里面还有别人的东西就留着
        except OSError:
            pass
    sc('daemon-reload')
    sc('reset-failed', POOL, KEEP)


def prepare():
    if sc('is-system-running').stdout.strip() not in ('running', 'degraded'):
        die('这台机器上没有在跑的用户级 systemd（systemctl --user is-system-running）')
    remove_units()   # 上一次没跑完留下的
    for name in (POOL, KEEP):
        if show(name, 'LoadState') != 'not-found':
            die(f'用户级的 systemd 里已经有 {name}（{show(name, "FragmentPath")}），本脚本不动它')
    if sorted(SETTINGS) != sorted(example_required()):
        die(f'deploy/compose/.env.example 要填的变量与本脚本给的对不上：{sorted(set(SETTINGS) ^ set(example_required()))}')
    if re.search(r'\s', f'{WORK}{sys.executable}'):
        die(f'路径里有空白，单元文件里的命令行写不了：{WORK}，{sys.executable}')
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    os.chmod(HERE / '.run', 0o700)
    (WORK / 'stand-in.py').write_text(STAND_IN, encoding='utf-8')
    for name, role in (('docker', 'docker'), ('gateway-control', 'keeper')):
        (WORK / name).write_text(f'#!/bin/sh\nexec {sys.executable} {WORK}/stand-in.py {role} "$@"\n', encoding='utf-8')
        os.chmod(WORK / name, 0o755)
    (WORK / '.env').write_text(''.join(f'{name}={value}\n' for name, value in SETTINGS.items()), encoding='utf-8')
    UNITS.mkdir(parents=True, exist_ok=True)
    for name in (POOL, KEEP):
        (UNITS / name).write_text(adapted(name), encoding='utf-8')
    sc('daemon-reload')


# ---- 结果 -------------------------------------------------------------------------------------------
class Results:
    def __init__(self):
        self.cases, self.current, self.broke_in = [], None, None

    def case(self, cid: str, title: str):
        self.current = {'id': cid, 'title': title, 'checks': [], 'notes': {}}
        self.cases.append(self.current)
        print(f'  ...  {cid}  {title}', flush=True)

    def check(self, what: str, ok) -> bool:
        self.current['checks'].append({'check': what, 'ok': bool(ok)})
        return bool(ok)

    def note(self, key: str, value):
        if key in self.current['notes']:
            raise AssertionError(f"{self.current['id']} 里有两条记录都叫 {key!r}")
        self.current['notes'][key] = value

    def broke(self, error: Exception):
        if self.current is None:
            self.case('-', '第一个用例开始之前')
        self.broke_in = self.current['id']
        self.current['checks'].append({'check': f'本脚本在这里出了错，后面的都没有跑：{type(error).__name__}: {error}', 'ok': False})
        self.current['notes']['出错的地方'] = traceback.format_exc().strip().splitlines()[-8:]

    def failed(self) -> list:
        return [c for c in self.cases if not all(k['ok'] for k in c['checks'])]

    def report(self):
        for c in self.cases:
            bad = [k['check'] for k in c['checks'] if not k['ok']]
            print(f"  {'FAIL' if bad else 'PASS'}  {c['id']}  {c['title']}")
            for what in bad:
                print(f'          ✗ {what}')
            for key, value in c['notes'].items():
                print(f'          {key}: {value}')


STOPPED = ['keeper TERM', 'child end', 'keeper exit']   # 看守被叫停：手上的命令跑完，它才退出
UP, STOP = ['docker begin compose up -d', 'docker end compose up -d'], ['docker begin compose stop', 'docker end compose stop']


def cases(r: Results):
    r.case('UN-01', '启动：看守跟着池的单元启动，在启动命令跑完之后，拿到的是 gateway-control keep 要的那组参数')
    for name in (POOL, KEEP):
        r.note(f'{name}：这次运行改动的行（- 原来的，+ 这次用的）', changes(name))
    verified = subprocess.run(['systemd-analyze', '--user', 'verify', str(UNITS / POOL), str(UNITS / KEEP)], capture_output=True, text=True,
                              env={**os.environ, 'XDG_RUNTIME_DIR': str(RUNTIME)})
    r.note('systemd-analyze verify 说了什么', (verified.stdout + verified.stderr).strip())
    r.check('systemd-analyze verify 对这两个文件没有话说', verified.returncode == 0 and not (verified.stdout + verified.stderr).strip())
    enabled = sc('enable', '--runtime', KEEP)
    r.check('enable 看守：它挂到了池的单元名下（[Install] 里的 WantedBy=idp-gateway-pool.service）',
            enabled.returncode == 0 and (UNITS / f'{POOL}.wants' / KEEP).is_symlink())
    since = time.time()
    started = sc('start', POOL)
    up = wait_for(lambda: bool(seen(events(since), 'keeper', 'start')), 10)
    log = events(since)
    calls, keeper = [e for e in log if e['who'] == 'docker'], (seen(log, 'keeper', 'start') or [{}])[0]
    r.note('启动池的单元：两个替身记下的事，按先后', order(log))
    r.check('启动池的单元（systemctl start）：它在 WorkingDirectory 里跑了 docker compose up -d，就这一条',
            started.returncode == 0 and order(calls) == UP and {e.get('cwd') for e in calls[:1]} == {str(WORK)})
    r.check('看守跟着启动了，在启动命令跑完之后；两个单元都是 active',
            up is not None and len(calls) == 2 and keeper.get('at', 0) >= calls[-1]['at'] and active(POOL) == 'active' and active(KEEP) == 'active')
    r.note('看守拿到的参数', keeper.get('argv'))
    r.check('看守拿到的参数就是 gateway-control keep 要的那一组，值取自 .env；它的当前目录是 WorkingDirectory',
            keeper.get('argv') == EXPECTED and keeper.get('cwd') == str(WORK))
    r.check('.env 里的变量也都在看守的环境里，值与文件里写的相同：它跑 docker compose 时带着的就是这些',
            keeper.get('env') == SETTINGS)

    r.case('UN-02', '看守自己死了：systemd 把它重新起来，池的单元不受影响；它以退出码 2 结束就不再起')
    pid, since = main_pid(KEEP), time.time()
    os.kill(pid, signal.SIGKILL)
    back = wait_for(lambda: came_back(pid, since), 20)
    r.note('看守被强行杀掉之后过了多少秒重新起来（RestartSec 是 5 秒）', back)
    r.check('看守被强行杀掉（SIGKILL）：5 秒之后由 systemd 重新起来，换了一个进程',
            pid > 0 and back is not None and back >= RESTART_SECONDS - 1 and show(KEEP, 'NRestarts') == '1'
            and len(seen(events(since), 'keeper', 'start')) == 1)
    r.check('池的单元没有动：还是 active，这期间没有哪条 docker 命令被叫', active(POOL) == 'active' and not [e for e in events(since) if e['who'] == 'docker'])
    pid, since = main_pid(KEEP), busy_keeper()
    os.kill(pid, signal.SIGTERM)
    back = wait_for(lambda: came_back(pid, since), 20)
    log = events(since)
    r.note('有人直接给看守发终止信号：替身记下的事，按先后', order(log))
    r.check('有人直接给看守发终止信号（不经 systemctl）：它把手上的命令跑完，以 0 退出；systemd 照样把它重新起来。要停它得用 systemctl stop',
            back is not None and order(log)[:3] == STOPPED and seen(log, 'keeper', 'exit')[0].get('code') == 0
            and len(seen(log, 'keeper', 'start')) == 1 and not seen(log, 'child', 'TERM'))
    (WORK / 'exit-2').touch()
    pid, since = main_pid(KEEP), time.time()
    os.kill(pid, signal.SIGKILL)
    failed = wait_for(lambda: active(KEEP) == 'failed', 20)
    time.sleep(RESTART_SECONDS + 2)   # 它要是还会被重新起来，这时看得见
    log = events(since)
    r.check('看守以退出码 2 结束（命令行写得不对时是这样）：不再重新起，单元的状态是 failed',
            failed is not None and len(seen(log, 'keeper', 'start')) == 1 and seen(log, 'keeper', 'exit')[0].get('code') == 2
            and active(KEEP) == 'failed' and show(KEEP, 'ExecMainStatus') == '2')
    (WORK / 'exit-2').unlink()
    since = time.time()
    again = sc('start', POOL)
    up = wait_for(lambda: active(KEEP) == 'active' and bool(seen(events(since), 'keeper', 'start')), 10)
    r.check('池的单元已经是 active 时再 start 它：看守被带着起来了，启动命令没有再跑',
            again.returncode == 0 and up is not None and not [e for e in events(since) if e['who'] == 'docker'])

    r.case('UN-03', '停：看守先停，它手上的那条命令让它跑完，然后才是池的停止命令；之后没有谁再起来')
    since = busy_keeper()
    stopped = sc('stop', POOL)
    log = events(since)
    r.note('停池的单元：两个替身记下的事，按先后', order(log))
    r.check('停池的单元（systemctl stop）：看守先收到终止信号，这时它手上有一条命令在跑',
            stopped.returncode == 0 and bool(seen(log, 'keeper', 'TERM')) and seen(log, 'keeper', 'TERM')[0].get('child_running') is True)
    r.check('那条命令没有收到信号，自己跑完了；看守这才以 0 退出（KillMode=mixed）',
            not seen(log, 'child', 'TERM') and order(log)[:3] == STOPPED and seen(log, 'keeper', 'exit')[0].get('code') == 0)
    r.check('看守退出之后才是池的停止命令 docker compose stop，就这一条；两个单元都是 inactive',
            order(log) == STOPPED + STOP and active(POOL) == 'inactive' and active(KEEP) == 'inactive')
    time.sleep(RESTART_SECONDS + 2)
    r.check('停下之后看守没有被重新起来（Restart=always 不管 systemctl stop 停下的）',
            active(KEEP) == 'inactive' and len(events(since)) == len(log))

    r.case('UN-04', '池的单元启动失败：看守照样起来；这时停池的单元，看守停了，池的停止命令却不会跑')
    (WORK / 'fail-up').touch()
    since = time.time()
    failed = sc('start', POOL)
    up = wait_for(lambda: bool(seen(events(since), 'keeper', 'start')), 10)
    log = events(since)
    r.note('启动命令失败时启动池的单元：两个替身记下的事，按先后', order(log))
    r.check('启动命令以非零码结束：systemctl start 也以非零码结束，池的单元的状态是 failed',
            failed.returncode != 0 and active(POOL) == 'failed' and order(log)[:2] == UP and seen(log, 'docker', 'end')[0].get('code') == 1)
    r.check('看守照样被起来了，在那条失败的启动命令之后', up is not None and active(KEEP) == 'active'
            and seen(log, 'keeper', 'start')[0]['at'] >= seen(log, 'docker', 'end')[0]['at'])
    since = busy_keeper()
    stopped = sc('stop', POOL)
    log = events(since)
    r.note('池的单元是 failed 时停它：两个替身记下的事，按先后', order(log))
    r.check('池的单元是 failed 时停它：看守停了；池的停止命令没有跑（单元不是 active，systemd 不跑它的 ExecStop）',
            stopped.returncode == 0 and order(log) == STOPPED and active(KEEP) == 'inactive' and active(POOL) == 'failed')
    (WORK / 'fail-up').unlink()
    sc('start', KEEP)   # 看守在跑，池的单元还是 failed：看守把池修好之后就是这个样子
    since = busy_keeper()   # 等它真的跑起来再往下：systemctl start 回来的时候，替身还没来得及记下自己的启动
    pid = main_pid(KEEP)
    again = sc('start', POOL)
    log = events(since)
    r.note('看守在跑、池的单元是 failed 时再 start 池的单元：两个替身记下的事，按先后', order(log))
    r.check('看守在跑、池的单元是 failed 时再 start 池的单元（这一次启动命令成了）：单元回到 active，看守没有被动过',
            again.returncode == 0 and active(POOL) == 'active' and pid > 0 and main_pid(KEEP) == pid
            and order([e for e in log if e['who'] != 'child']) == UP)

    r.case('UN-05', '重启池的单元：看守先停，池停，池起，看守再起')
    since = busy_keeper()
    restarted = sc('restart', POOL)
    up = wait_for(lambda: bool(seen(events(since), 'keeper', 'start')), 10)
    log = events(since)
    r.note('重启池的单元：两个替身记下的事，按先后', order(log))
    r.check('重启池的单元（systemctl restart）：看守先停，然后 docker compose stop，再 docker compose up -d，最后看守重新起来',
            restarted.returncode == 0 and up is not None and order(log)[:8] == STOPPED + STOP + UP + ['keeper start']
            and active(POOL) == 'active' and active(KEEP) == 'active')

    r.case('UN-06', '跑完不留东西')
    remove_units()
    r.check('两个单元都停了，单元文件删了，用户级的 systemd 里没有这两个名字了',
            not (UNITS / POOL).exists() and not (UNITS / KEEP).exists() and not (UNITS / f'{POOL}.wants').exists()
            and [show(name, 'LoadState') for name in (POOL, KEEP)] == ['not-found', 'not-found'])


def main() -> int:
    prepare()
    r = Results()
    try:
        cases(r)
    except Exception as error:   # 本脚本自己出了错：前面查到的不能跟着丢掉
        r.broke(error)
    finally:
        remove_units()
        shutil.rmtree(WORK, ignore_errors=True)
    version = subprocess.run(['systemctl', '--version'], capture_output=True, text=True).stdout.splitlines()[:1]
    print(f"\n{(version or ['systemd ?'])[0]}，用户级")
    r.report()
    failed = r.failed()
    RESULT.write_text(json.dumps({'systemd': (version or [''])[0], 'broke_in': r.broke_in, 'cases': r.cases}, ensure_ascii=False, indent=1),
                      encoding='utf-8')
    print(f'\n{len(r.cases) - len(failed)}/{len(r.cases)}（详细结果在 {RESULT}）')
    return int(bool(failed))


if __name__ == '__main__':
    sys.exit(main())
