#!/usr/bin/env python3
"""后端的名字后来指到了别处：锁定的 agentgateway 会怎样，deploy/compose/pin-egress.sh 拦不拦得住。

一个隔离的 docker 网络：替身解析器（dns.py），两个替身服务器（hit.py），和接在一个占位容器的网络命名空间里的
网关，摆法与 deploy/compose 相同。没有任何真实的第三方。装规则的脚本就是单机池里跑的那一个，给它的参数与
deploy/compose/compose.yml 里 x-pin-egress 的相同（tests/contracts 核对镜像）。

    python3 tests/integration/egressnet/run.py        # 两分钟左右；自己起，跑完自己拆

占用本机回环上的 27630。逐项结果写在 .run/result.json，不入库。这是机制验证，不是验收。
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RUN = HERE / ".run"
SCRIPT = ROOT / "deploy/compose/pin-egress.sh"
REGISTERED, EVIL, SECOND = "10.31.32.10", "10.31.32.20", "10.31.32.11"   # SECOND：没有人在那里
NAME, PORT = "upstream.idp.test", 8080
HOLDER, GATEWAY, WATCHER = "idp-gw-egressnet-netns", "idp-gw-egressnet-gw", "idp-gw-egressnet-watch"
IPTABLES = "docker@sha256:b36f28717b43f23f56c7c72e97eeba80aeb24fc3f4dbf9fa409b25b074bf1260"
PYTHON = "public.ecr.aws/docker/library/python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca"
QUIET = 20   # 秒。不发请求地等这么久：发请求会让网关接着用它记着的地址
REFUSED_HERE, REFUSED_HERE_V6 = 113, 13   # 被这里的规则拒绝：EHOSTUNREACH；IPv6 是 EACCES。对方自己拒绝是 111
REFUSED_THERE = 111                       # ECONNREFUSED：规则放行了，那个地址上没有人在听那个端口
ENV = {k: v for k, v in os.environ.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}


def docker(*argv, timeout=120):
    return subprocess.run(["docker", *argv], env=ENV, text=True, capture_output=True, timeout=timeout)


def compose(*argv):
    return subprocess.run(["docker", "compose", *argv], cwd=HERE, env=ENV, text=True, capture_output=True, timeout=300)


def answer(*addresses: str):
    """替身解析器从现在起对每个名字答这些地址。"""
    (RUN / "answers" / "a").write_text("".join(address + "\n" for address in addresses), encoding="utf-8")


def hits(name: str) -> int:
    """那个替身服务器到现在收到过多少个请求。"""
    done = docker("run", "--rm", "-v", f"{RUN}/hits/{name}:/hits:ro", PYTHON, "sh", "-c", "cat /hits/log 2>/dev/null | wc -l")
    return int(done.stdout.strip() or 0)


def call(timeout: float = 8):
    """经网关发一个请求。-> 状态码；没有得到应答时是 None。"""
    request = urllib.request.Request("http://127.0.0.1:27630/probe", headers={"Host": "egress.idp.test"})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as refused:
        return refused.code
    except Exception:
        return None


def wait_for(predicate, seconds: float, every: float = 0.5):
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if predicate():
            return round(time.monotonic() - started, 1)
        time.sleep(every)
    return None


def mode(how=None):
    """替身解析器从现在起对每个名字这样回答（dns.py 里写着有哪几种）；None 是照常：A 记录是 answer 写的那些。"""
    path = RUN / "answers" / "mode"
    if how is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(how + "\n", encoding="utf-8")


def cold_gateway(how):
    """一个刚启动的网关，还没有用过后端的名字：替身解析器先改成 how 这样回答，网关换一个进程，等到它就绪（等它的监听口开了，
    不发业务请求）。-> 网关这时的 StartedAt。"""
    # 网关自己的就绪口在回环上，这里的规则不放行回环：看它的日志里"started bind"（监听口开了）的行数多了一行。
    listening = lambda: docker("logs", GATEWAY).stdout.count("started bind") + docker("logs", GATEWAY).stderr.count("started bind")
    mode(how)
    before = listening()
    docker("restart", "-t", "2", GATEWAY)
    if wait_for(lambda: listening() > before, 30) is None:
        raise RuntimeError("网关重启之后 30 秒内没有就绪")
    return docker("inspect", "-f", "{{.State.StartedAt}}", GATEWAY).stdout.strip()


def restart_gateway():
    """网关换一个进程：它记着的地址没有了，下一个请求要重新解析。占位容器不动，命名空间里的规则还在。"""
    docker("restart", "-t", "2", GATEWAY)
    wait_for(lambda: call() is not None, 15)


def pin(mode: str, *more: str):
    """跑一次 pin-egress.sh，接在占位容器的网络命名空间里。参数照 deploy/compose/compose.yml 的 x-pin-egress；
    这里没有 front，所以回环上一个都不另外放行。"""
    return docker("run", *more, "--network", f"container:{HOLDER}",
                  "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges:true",
                  "--user", "0:0", "--tmpfs", "/tmp",
                  "-e", "CONFIG=/work/config/config.yaml", "-e", "LOOP_ALLOW=", "-e", "INTERVAL=1",
                  "-v", f"{SCRIPT}:/opt/pin-egress.sh:ro", "-v", f"{RUN}/config:/work/config:ro",
                  "--entrypoint", "/bin/sh", IPTABLES, "/opt/pin-egress.sh", mode)


def pins() -> dict:
    """规则里现在钉着的：{"名字:端口": [地址, …]}。"""
    listed = docker("run", "--rm", "--network", f"container:{HOLDER}", "--cap-add", "NET_ADMIN",
                    "--entrypoint", "iptables", IPTABLES, "-S", "IDP_EGRESS").stdout
    found = {}
    for line in listed.splitlines():
        words = line.replace('"', "").split()
        if "--comment" in words and "-d" in words:
            key = words[words.index("--comment") + 1]
            if key.startswith("pin:"):
                found.setdefault(key[4:], []).append(words[words.index("-d") + 1].split("/")[0])
    return {key: sorted(addresses) for key, addresses in found.items()}


def inside(code: str, *argv: str) -> dict:
    """在网关所在的网络命名空间里跑一段 Python，它打印一份 JSON。"""
    done = docker("run", "--rm", "--network", f"container:{HOLDER}", PYTHON, "python", "-c", code, *argv)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {"error": (done.stderr or done.stdout).strip()[-300:]}


CONNECT = r'''
import json, socket, sys
seen = {}
for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family) as s:
        s.settimeout(3)
        seen[target] = s.connect_ex((host.strip("[]"), int(port)))
try:
    seen["resolved"] = socket.gethostbyname("upstream.idp.test")
except OSError as failed:
    seen["resolved"] = f"{type(failed).__name__}: {failed}"
print(json.dumps(seen))
'''

# 在网关所在的网络命名空间里问网关用的那个解析器（127.0.0.11，Docker 的）一个名字的 A 记录：rcode（3 是名字不存在，2 是出错），
# 回答里有几条，权威段里的 SOA（有的话）的 TTL；问不到时是 {"error": …}，和等了多少秒。
ASK = r'''
import json, socket, struct, sys, time
name = sys.argv[1]
query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack("!HH", 1, 1)
began = time.monotonic()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(float(sys.argv[2]))
    try:
        s.sendto(query, ("127.0.0.11", 53))
        reply = s.recv(2048)
    except OSError as failed:
        print(json.dumps({"error": type(failed).__name__, "seconds": round(time.monotonic() - began, 1)}))
        raise SystemExit
flags, questions, answers, authority = struct.unpack("!HHHH", reply[2:10])
print(json.dumps({"rcode": flags & 15, "answers": answers, "authority": authority, "seconds": round(time.monotonic() - began, 1)}))
'''

HAMMER = r'''
import collections, json, socket, sys, time
host, port, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
seen, end = collections.Counter(), time.time() + seconds
while time.time() < end:
    with socket.socket() as s:
        s.settimeout(0.3)
        seen[str(s.connect_ex((host, port)))] += 1
    time.sleep(0.002)
print(json.dumps(seen))
'''


class Results:
    def __init__(self):
        self.cases = []

    def case(self, number: str, title: str):
        print(f"  ...  {number}  {title}", flush=True)
        self.cases.append({"id": number, "title": title, "checks": [], "observed": {}})

    def check(self, what: str, ok) -> bool:
        self.cases[-1]["checks"].append({"check": what, "ok": bool(ok)})
        return bool(ok)

    def note(self, name: str, value):
        self.cases[-1]["observed"][name] = value

    def failed(self) -> list:
        return [c for c in self.cases if not all(k["ok"] for k in c["checks"])]

    def report(self):
        for c in self.cases:
            bad = [k["check"] for k in c["checks"] if not k["ok"]]
            print(f"  {'FAIL' if bad else 'PASS'}  {c['id']}  {c['title']}")
            for what in bad:
                print(f"          x {what}")
            for name, value in c["observed"].items():
                print(f"          {name}: {value}")


def prepare():
    teardown()
    for path in (RUN / "answers", RUN / "hits" / "registered", RUN / "hits" / "evil", RUN / "config"):
        path.mkdir(parents=True, exist_ok=True)
    # 装规则的容器是 root，但除了 NET_ADMIN 什么 capability 都没有：配置要对所有人可读，与发布器写的一样（0644，目录 0755）。
    shutil.copyfile(HERE / "config.yaml", RUN / "config" / "config.yaml")
    os.chmod(RUN / "config", 0o755)
    os.chmod(RUN / "config" / "config.yaml", 0o644)
    answer(REGISTERED)


def teardown():
    docker("rm", "-f", WATCHER)
    compose("down", "--volumes", "--remove-orphans", "--timeout", "2")
    if RUN.exists():   # 替身服务器是以 root 写的记录
        docker("run", "--rm", "-v", f"{RUN}:/run-dir", PYTHON, "sh", "-c", "rm -rf /run-dir/hits /run-dir/answers /run-dir/config")


def add_host(spec: str):
    with open(RUN / "config" / "config.yaml", "a", encoding="utf-8") as config:
        config.write(f"- name: {spec.split('.')[0]}\n  backends:\n  - host: {spec}\n")


def remove_host(spec: str) -> bool:
    """add_host 写进去的那一条拿掉。文件整份换成新的（改名），脚本读到的要么是旧的整份，要么是新的整份；
    模式照 prepare() 的，0644。-> 原来有没有这一条。"""
    path = RUN / "config" / "config.yaml"
    block = f"- name: {spec.split('.')[0]}\n  backends:\n  - host: {spec}\n"
    text = path.read_text(encoding="utf-8")
    replacement = path.with_name(".config.yaml.next")
    replacement.write_text(text.replace(block, ""), encoding="utf-8")
    os.chmod(replacement, 0o644)
    os.replace(replacement, path)
    return block in text


def cases(r: Results):
    key = f"{NAME}:{PORT}"

    r.case("EG-01", "不装规则：后端的名字改指到另一个地址之后，网关跟着去了那个地址")
    up = compose("up", "-d")
    first = wait_for(lambda: call() == 200, 30)
    r.check("名字指着登记的地址时，请求得到 200，收到它的是登记的那个服务器",
            up.returncode == 0 and first is not None and hits("registered") >= 1 and hits("evil") == 0)
    before = hits("evil")
    answer(EVIL)
    time.sleep(QUIET)
    status = call()
    r.note(f"名字改指之后不发请求地等了 {QUIET} 秒，再发的那个请求得到", status)
    r.check("那个请求到了另一个地址。这是被测的这个二进制的行为；它变了，这一条不通过，要回头看规则还需不需要",
            hits("evil") > before)

    r.case("EG-02", "装上规则之后：登记的地址照常连得通，名字照常解析得了")
    answer(REGISTERED)
    restart_gateway()
    r.check("装之前：名字指回登记的地址，网关重启之后请求得到 200", wait_for(lambda: call() == 200, 20) is not None)
    once = pin("once", "--rm")
    r.note("pin-egress.sh once 说了什么", (once.stdout + once.stderr).strip())
    r.check("pin-egress.sh once：退出码 0，把这个名字钉在它这时解析到的地址上",
            once.returncode == 0 and f"pinned {key} -> {REGISTERED}" in once.stdout and pins() == {key: [REGISTERED]})
    restart_gateway()   # 它得在规则底下重新解析这个名字
    served = hits("registered")
    r.check("网关重启之后（它要重新解析这个名字）：请求得到 200，收到它的是登记的那个服务器",
            wait_for(lambda: call() == 200, 20) is not None and hits("registered") > served)
    seen = inside(CONNECT, f"{REGISTERED}:{PORT}")
    r.check("从这个网络命名空间里：名字解析得了，登记的地址连得上", seen.get("resolved") == REGISTERED and seen.get(f"{REGISTERED}:{PORT}") == 0)

    r.case("EG-03", "装上规则之后名字改指：另一个地址收不到请求，网关重启、规则再装一遍之后也一样")
    reached = hits("evil")
    answer(EVIL)
    time.sleep(QUIET)
    status = call()
    r.note(f"名字改指之后不发请求地等了 {QUIET} 秒，再发的那个请求得到", status)
    r.check("那个请求没有到另一个地址，调用方得到的不是 200", hits("evil") == reached and status not in (None, 200))
    restart_gateway()
    status = call()
    r.note("网关重启之后（它解析到的只有另一个地址）再发的请求得到", status)
    r.check("网关重启之后：另一个地址仍然没有收到请求，调用方得到的不是 200", hits("evil") == reached and status not in (None, 200))
    again = pin("once", "--rm")
    r.check("规则再装一遍（每次 docker compose up -d 都会）：没有把名字现在指的地址加进去，钉着的还是原来那个",
            again.returncode == 0 and "pinned" not in again.stdout and pins() == {key: [REGISTERED]})
    answer(REGISTERED)
    restart_gateway()
    r.check("名字指回登记的地址：请求照常，规则不用动", wait_for(lambda: call() == 200, 20) is not None and hits("evil") == reached)

    r.case("EG-04", "从网关所在的网络命名空间往外连：只有钉住的地址和端口连得上；规则被重写的时候没有空档")
    targets = [f"{REGISTERED}:{PORT}", f"{REGISTERED}:{PORT + 1}", f"{EVIL}:{PORT}", "10.1.2.3:8080", "169.254.169.254:80",
               "127.0.0.1:15000", "[::1]:15000"]
    seen = inside(CONNECT, *targets)
    r.note("connect 的结果（0 是连上了，113 和 13 是被这里的规则拒绝，111 是对方拒绝）", seen)
    r.check("钉住的地址和端口连得上", seen.get(targets[0]) == 0)
    r.check("同一个地址的另一个端口、另一个服务器、一个内网地址、链路本地的元数据地址：都被这里的规则拒绝",
            all(seen.get(target) == REFUSED_HERE for target in targets[1:5]))
    r.check("回环上网关自己的管理地址（配置里没有写它，这里也没有另外放行）被拒绝；IPv6 的回环也被拒绝",
            seen.get(targets[5]) == REFUSED_HERE and seen.get(targets[6]) == REFUSED_HERE_V6)
    watching = pin("watch", "-d", "--name", WATCHER, "--pid", f"container:{HOLDER}")
    time.sleep(2)
    counted = inside(HAMMER, EVIL, str(PORT), "10")
    r.note("常驻的那个每秒重写一遍规则的 10 秒里，连另一个服务器的结果各有多少次", counted)
    r.check("这 10 秒里连了不少于 500 次，每一次都被这里的规则拒绝",
            watching.returncode == 0 and sum(counted.values()) >= 500 and set(counted) == {str(REFUSED_HERE)})
    r.check("这之后钉住的地址仍然连得上，请求照常", inside(CONNECT, targets[0]).get(targets[0]) == 0 and call() == 200)

    r.case("EG-05", "配置里多了后端：常驻的那个把它放行；一个名字有两个地址，两个都钉住；forget 之后重新解析")
    add_host("other.idp.test:9090")
    r.check("配置里多了一个后端：几秒之内它被钉在这时解析到的地址上",
            wait_for(lambda: pins().get("other.idp.test:9090") == [REGISTERED], 10) is not None)
    answer(REGISTERED, SECOND)
    add_host("multi.idp.test:9091")
    r.check("一个名字解析出两个地址：两个都钉住",
            wait_for(lambda: pins().get("multi.idp.test:9091") == sorted([REGISTERED, SECOND]), 10) is not None)
    r.check("先前钉住的没有跟着变", pins().get(key) == [REGISTERED] and pins().get("other.idp.test:9090") == [REGISTERED])
    answer(REGISTERED)
    forgotten = pin("forget", "--rm")
    time.sleep(3)   # 常驻的那个这期间又跑过几遍
    now = pins()
    r.note("forget 之后钉着的", now)
    r.check("pin-egress.sh forget（常驻的那个同时在跑）：退出码 0，三个名字都按现在的解析重新钉过，多出来的那个地址不在了",
            forgotten.returncode == 0 and now == {key: [REGISTERED], "other.idp.test:9090": [REGISTERED], "multi.idp.test:9091": [REGISTERED]})
    r.check("请求照常", call() == 200)

    # 这时常驻的那个在跑，配置里是三个名字，都钉在登记的地址上。登记的服务器没有在 9090 上听：连 地址:9090，
    # 放行时得到 111（对方拒绝），不放行时得到 113（这里的规则拒绝）。EG-06 要杀占位容器，之后什么都跑不了，所以这个在它前面。
    r.case("EG-07", "配置里去掉一个后端：几秒之内它不再放行；放回去时放行的是它原来的地址，名字现在指的地址不放行；配置文件不在时放行的不变")
    spec, others = "other.idp.test:9090", "multi.idp.test:9091"
    target, elsewhere = f"{REGISTERED}:9090", f"{EVIL}:9090"
    seen = inside(CONNECT, target)
    r.check("去掉之前：other.idp.test:9090 在放行的里面；从这个网络命名空间连它钉着的地址和端口得到 111（规则放行，那里没有人在听）",
            pins().get(spec) == [REGISTERED] and seen.get(target) == REFUSED_THERE)
    had = remove_host(spec)
    gone = wait_for(lambda: spec not in pins(), 10)
    seen = inside(CONNECT, target)
    r.note("配置里去掉它之后，过了多少秒它不在放行的里面", gone)
    r.check("配置里去掉这个后端：几秒之内它不在放行的里面，另外两个还在；同一个地址和端口现在得到 113（被这里的规则拒绝）",
            had and gone is not None and pins() == {key: [REGISTERED], others: [REGISTERED]} and seen.get(target) == REFUSED_HERE)
    r.check("经网关去剩下的那个后端的请求照常：200", call() == 200)

    answer(EVIL)
    add_host(spec)
    back = wait_for(lambda: spec in pins(), 10)
    seen = inside(CONNECT, target, elsewhere)
    now = pins()
    r.note("后端放回去之后放行的", now)
    r.note("放回去之后，名字现在解析到", seen.get("resolved"))
    r.check("解析器对每个名字答另一个服务器的地址，后端放回配置：几秒之内它又放行，放行的是它原来的地址，另外两个没有变；"
            "原来的地址得到 111，名字现在解析到的地址得到 113",
            back is not None and now == {key: [REGISTERED], spec: [REGISTERED], others: [REGISTERED]}
            and seen.get("resolved") == EVIL and seen.get(target) == REFUSED_THERE and seen.get(elsewhere) == REFUSED_HERE)
    answer(REGISTERED)

    # 脚本读的是 .run/config/config.yaml；网关容器挂的是 tests/integration/egressnet/config.yaml 的另一份，这里不动它。
    path, away = RUN / "config" / "config.yaml", RUN / "config" / ".config.yaml.away"
    before = pins()
    try:
        os.rename(path, away)
        time.sleep(4)   # 常驻的那个每秒跑一遍：这期间它跑过几遍，每一遍都找不到配置文件
        during = pins()
        seen = inside(CONNECT, target, elsewhere)
        status = call()
    finally:
        if away.exists():
            os.replace(away, path)
    time.sleep(3)
    after = pins()
    r.note("常驻的那个到现在说过什么（标准错误）", docker("logs", WATCHER).stderr.strip().splitlines())
    r.check("配置文件拿走八秒左右（常驻的那个跑了几遍）：放行的还是三个、地址不变；原来的地址得到 111，名字现在解析到的地址得到 113；"
            "请求仍然得到 200",
            before == {key: [REGISTERED], spec: [REGISTERED], others: [REGISTERED]} and during == before
            and seen.get(target) == REFUSED_THERE and seen.get(elsewhere) == REFUSED_HERE and status == 200)
    r.check("文件放回去：放行的和拿走之前一样", after == before)
    running = lambda name: docker("inspect", "-f", "{{.State.Running}}", name).stdout.strip() == "true"
    r.check("这个用例结束时常驻的那个在跑，占位容器也在（EG-06 要用）", running(WATCHER) and running(HOLDER))

    # 配置文件改成 0600：属主是跑本脚本的用户，脚本是 root 但没有 CAP_DAC_OVERRIDE，读不了。这时常驻的那个每遍都读不了。
    r.case("EG-08", "配置文件读不了：常驻的那个一遍没跑成也不退出，规则不动，同一行不每遍都说；读得了之后它自己恢复")
    fresh, three = "fresh.idp.test:9092", {key: [REGISTERED], spec: [REGISTERED], others: [REGISTERED]}
    cannot_read = lambda lines: sum("cannot read" in line for line in lines)
    already = cannot_read(docker("logs", WATCHER).stderr.splitlines())
    before = pins()
    began = time.monotonic()
    try:
        os.chmod(path, 0o600)
        time.sleep(8)   # 常驻的那个每秒跑一遍：这期间它跑了好几遍，每一遍都读不了配置文件
        during = pins()
        seen = inside(CONNECT, f"{REGISTERED}:{PORT}", target)
        status = call()
        lines = docker("logs", WATCHER).stderr.splitlines()
        alive = running(WATCHER)
        unreadable = round(time.monotonic() - began, 1)
    finally:
        os.chmod(path, 0o644)   # 不管上面出了什么错，文件的模式都要回到 prepare() 给的
    new = cannot_read(lines) - already
    r.note("文件读不了的这段时间（秒），其间标准错误上说读不了的有几行", [unreadable, new])
    r.note("这段时间里常驻的那个在标准错误上说的（最后几行）", lines[-5:])
    r.check("配置文件读不了的这段时间里：常驻的那个还在跑；放行的还是原来的三个、地址不变（没有清空，也没有少）；"
            "放行的地址和端口照常连得上（登记的服务器的 8080 得到 0，9090 得到 111）；经网关的请求仍然得到 200",
            before == three and alive and during == three
            and seen.get(f"{REGISTERED}:{PORT}") == 0 and seen.get(target) == REFUSED_THERE and status == 200)
    r.check("常驻的那个在标准错误上说了读不了配置文件（cannot read）", new >= 1)
    r.check("文件一直读不了，这一行没有每遍都说：它在 8 秒以上里出现不多于 2 次（每秒跑一遍、每遍都说的话，这段时间里会有 8 次左右）",
            unreadable >= 8 and new <= 2)

    add_host(fresh)
    recovered = wait_for(lambda: pins().get(fresh) == [REGISTERED], 10)
    lines = docker("logs", WATCHER).stderr.splitlines()
    r.note("文件读得了、配置里多一个后端之后，过了多少秒它被钉住", recovered)
    r.note("恢复之后常驻的那个说的（最后几行）", lines[-3:])
    r.check("文件读得了之后配置里多一个后端：几秒之内它被钉在登记的地址上（常驻的那个自己恢复了），原来的三个没有变；"
            "标准错误上说了又能跑了（passes work again）",
            recovered is not None and pins() == {**three, fresh: [REGISTERED]} and any("passes work again" in line for line in lines))
    remove_host(fresh)
    tidy = wait_for(lambda: fresh not in pins(), 10)
    r.check("再把这个后端去掉：几秒之内它不再放行，原来的三个还在；常驻的那个和占位容器都在（EG-06 要用）",
            tidy is not None and pins() == three and running(WATCHER) and running(HOLDER))

    # 下面几个用例接着 EG-08 的状态（常驻的那个在跑，三个名字钉在登记的地址上；名字 upstream.idp.test 钉的就是登记的地址），
    # 在 EG-06 之前：EG-06 要杀占位容器。每个都从一个刚启动的网关做起（cold_gateway）：第一个请求到来时它才去解析后端的名字，
    # 这时替身解析器对每个名字都答"不存在"（或出错、不应答；EG-14、EG-15 是够不着）；之后把解析器改回照常，不重启网关，看它多久恢复。
    # 时间都用 time.monotonic()；判断留余量，不卡在边界上。
    resolves = lambda: inside(CONNECT, f"{REGISTERED}:{PORT}").get("resolved") == REGISTERED   # 从网关所在的命名空间里按名字去问

    SHORT = 10   # 秒。否定缓存时间：等得起，又与"下一个请求"分得清
    r.case("EG-09", f"名字第一次用到时不存在，回答带着短的否定缓存时间（{SHORT} 秒）：这段时间之内请求得到 503，过了之后得到 200，网关没有重启过")
    started = cold_gateway(f"nxdomain-soa-{SHORT}")
    began = time.monotonic()
    first = call()
    mode(None)
    r.check("名字不存在（带着 SOA，缓存时间 %d 秒）：第一个请求得到 503" % SHORT, first == 503)
    r.check("解析器改回照常之后，从网关所在的命名空间里名字解析得了，指的是登记的地址", resolves())
    time.sleep(max(0, began + SHORT / 2 - time.monotonic()))
    middle, at_middle = call(), round(time.monotonic() - began, 1)
    r.note("名字解析得了之后，缓存时间的一半时的请求（距第一个请求多少秒，得到）", [at_middle, middle])
    r.check("缓存时间过了一半、名字早已解析得了：请求仍然得到 503", middle == 503)
    time.sleep(max(0, began + SHORT - 2 - time.monotonic()))
    series = []
    while time.monotonic() - began < SHORT + 15:   # 每秒一个请求，到得到 200 为止：记下是哪一秒起恢复的
        series.append([round(time.monotonic() - began, 1), call()])
        if series[-1][1] == 200:
            break
        time.sleep(1)
    healed = series[-1][0] if series and series[-1][1] == 200 else None
    r.note("缓存时间快到时每秒一个请求（距第一个请求多少秒，得到）", series)
    r.note("第一次得到 200 是在第一个请求之后多少秒", healed)
    r.check(f"缓存时间过了之后：请求得到 200（第一个请求之后 {SHORT // 2} 秒以上、{SHORT + 6} 秒以内）",
            healed is not None and SHORT // 2 < healed <= SHORT + 6)
    r.check("这期间网关没有重启过（同一个进程：StartedAt 不变）",
            docker("inspect", "-f", "{{.State.StartedAt}}", GATEWAY).stdout.strip() == started)

    LONG = 600
    r.case("EG-10", f"名字第一次用到时不存在，回答带着长的否定缓存时间（{LONG} 秒）：名字解析得了之后等 20 秒仍是 503，重启网关之后立刻是 200")
    cold_gateway(f"nxdomain-soa-{LONG}")
    first = call()
    mode(None)
    r.check("名字不存在（带着 SOA，缓存时间 600 秒）：第一个请求得到 503", first == 503)
    r.check("解析器改回照常之后，从网关所在的命名空间里名字解析得了，指的是登记的地址", resolves())
    time.sleep(QUIET)
    still = call()
    r.note(f"名字解析得了之后等了 {QUIET} 秒再发的请求得到", still)
    r.check(f"名字解析得了、又等了 {QUIET} 秒：请求仍然得到 503，网关没有重启", still == 503)
    restart_gateway()
    r.check("重启网关之后，它的第一个请求就得到 200", call() == 200)

    def recovers_at_once(number: str, how: str, what: str):
        r.case(number, f"名字第一次用到时{what}：名字解析得了之后，下一个请求就是 200，网关没有重启过")
        started = cold_gateway(how)
        # 不应答时，第一个请求要等网关自己的解析超时：留够时间
        first = call(timeout=60)
        mode(None)
        r.note(f"第一个请求得到", first)
        r.check(f"名字第一次用到时{what}：第一个请求没有得到 200", first != 200)
        r.check("解析器改回照常之后，从网关所在的命名空间里名字解析得了，指的是登记的地址", resolves())
        after = call()
        r.check("名字解析得了之后的下一个请求就得到 200，网关没有重启过（同一个进程：StartedAt 不变）",
                after == 200 and docker("inspect", "-f", "{{.State.StartedAt}}", GATEWAY).stdout.strip() == started)

    recovers_at_once("EG-11", "nxdomain", "不存在，回答里没有 SOA（没有缓存时间）")
    recovers_at_once("EG-12", "servfail", "解析器答出错（SERVFAIL）")
    recovers_at_once("EG-13", "drop", "解析器不应答")

    def unreachable(number: str, title: str, how, make, restore, what: str):
        """网关第一次用到名字时上游解析器够不着（make 做成这样），之后够得着了（restore）：不重启网关，看它多久恢复。"""
        r.case(number, title)
        said = len(docker("logs", WATCHER).stderr.splitlines())
        make()
        started = cold_gateway(how)
        began = time.monotonic()
        first = call(timeout=90)
        waited = round(time.monotonic() - began, 1)
        asked = inside(ASK, NAME, "20")
        r.note("第一个请求得到，等了多少秒", [first, waited])
        r.note("这时从网关所在的命名空间里问 Docker 的解析器这个名字", asked)
        r.check(f"{what}：第一个请求没有得到 200", first != 200)
        restored = time.monotonic()
        restore()
        back = wait_for(resolves, 60)
        r.note("解析器够得着了之后，过了多少秒名字从网关所在的命名空间里解析得了", back)
        r.check("解析器够得着了之后，名字从网关所在的命名空间里解析得了，指的是登记的地址", back is not None)
        series = []
        for _ in range(3):
            series.append([round(time.monotonic() - restored, 1), call()])
            if series[-1][1] == 200:
                break
            time.sleep(1)
        r.note("名字解析得了之后的请求（距解析器够得着多少秒，得到）", series)
        r.check("名字解析得了之后的下一个请求就得到 200，网关没有重启过（同一个进程：StartedAt 不变）",
                series[0][1] == 200 and docker("inspect", "-f", "{{.State.StartedAt}}", GATEWAY).stdout.strip() == started)
        more = docker("logs", WATCHER).stderr.splitlines()[said:]
        r.note("这个用例里常驻的那个在标准错误上多说的", more)
        r.check("解析器够不着的这段时间里，常驻的那个一直在跑，也没有多说什么，钉着的还是原来的三个（它只解析还没钉住的名字）",
                running(WATCHER) and not more and pins() == three)

    unreachable("EG-14", "解析器够不着（端口不可达）：网关第一次用到名字时 53 端口上没有人听，之后解析器回来，下一个请求就是 200，网关没有重启过", "closed", lambda: None, lambda: mode(None), "解析器那台机器在，53 端口上没有人听（回 ICMP 端口不可达）")
    unreachable("EG-15", "解析器够不着（主机不可达）：网关第一次用到名字时解析器的容器停着、那个地址上没有主机，之后它回来，下一个请求就是 200，网关没有重启过", None, lambda: compose("stop", "dns", "--timeout", "2"), lambda: compose("start", "dns"), "解析器的容器停了，那个地址上没有主机")

    r.case("EG-06", "占着网络命名空间的容器死了：常驻的那个跟着死，不会留在已经没用的命名空间里")
    state = lambda: docker("inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", WATCHER).stdout.split()
    r.check("这之前它在跑", state()[:1] == ["true"])
    docker("kill", HOLDER)
    gone = wait_for(lambda: state()[:1] == ["false"], 5, every=0.1)
    r.note("占位容器被杀掉之后过了多少秒它停了，退出码", [gone, state()[1:]])
    r.check("占位容器被杀掉：3 秒之内它也停了", gone is not None and gone <= 3)


def main() -> int:
    if not SCRIPT.exists():
        print(f"run.py: 找不到 {SCRIPT}", file=sys.stderr)
        return 2
    r = Results()
    prepare()
    try:
        cases(r)
    finally:
        teardown()
    print()
    r.report()
    failed = r.failed()
    RUN.mkdir(exist_ok=True)
    (RUN / "result.json").write_text(json.dumps({"finished": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "cases": r.cases},
                                                ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n{len(r.cases) - len(failed)}/{len(r.cases)}（详细结果在 {RUN / 'result.json'}）")
    return int(bool(failed))


if __name__ == "__main__":
    sys.exit(main())
