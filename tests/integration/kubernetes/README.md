# 在 Kubernetes 上经 ConfigMap 下发配置

[ADR-0010](../../../docs/adr/ADR-0010.md) 提议数据面用 standalone 模式的 agentgateway；在 Kubernetes 上，每个池是一个 Deployment 加一个只读挂载的 ConfigMap。这里在本机的一个 kind 集群里验证这种做法里与 Kubernetes 有关的那一半：配置怎么到各个副本，各个副本怎么报告。

> 这是机制验证，不是验收，通过不改变验收矩阵里任何用例的 `NOT_RUN`。  
> 集群只有一个节点。配置是一份只有几条路由的小文件，路由的后端不存在；没有 JWT、ExtAuthZ 和凭证，那些在黑盒套件里。

## 怎么跑

```bash
tests/integration/kubernetes/stack.sh up                 # 建集群、打包并装入网关镜像，约半分钟
.venv/bin/python tests/integration/kubernetes/run.py     # 约六分钟，大部分时间在等 ConfigMap 同步
tests/integration/kubernetes/stack.sh down               # 删除集群、它的 kubeconfig 和本地打包的镜像
```

需要 kind、kubectl、docker、jq，以及本机已有的两个镜像：`kindest/node:v1.35.0` 和 alpine 3.22（本机到不了 Docker Hub）。

- 集群叫 `idp-gateway-k8s`。它的 kubeconfig 只写在 `.run/kubeconfig`（已被 git 忽略）；脚本不读也不改 `~/.kube/config`，不动本机上别的 kind 集群。
- 网关镜像是在本地用锁定的那个二进制打包的（`stack.sh` 经 `tests/acceptance/blackbox/pin.py` 核对），**不是上游发布的容器镜像**。
- 回读用 `kubectl exec`：网关的管理地址在 Pod 里只绑了回环。
- `run.py` 只动 `egress-test` 这一个命名空间，每次从头建起。

## 结果

2026-11-11，Kubernetes v1.35.0（kind v0.31.0，单节点），agentgateway 1.7.0，三个副本：5 个用例全部通过，同一份脚本连跑两轮都是 5/5。逐项结果写在 `.run/result.json`，不入库。

| 用例 | 内容 | 结果 |
|---|---|---|
| K8-01 | 三个副本从同一个 ConfigMap 启动：都报告配置已加载、存储模式为 `readOnly`，`/config_dump` 的摘要相同；Pod 里的配置文件写不进去；Pod 里跑的就是锁定的发布版 | PASS |
| K8-02 | ConfigMap 换成多一条路由的版本：每个副本都重新加载，摘要一致，新路由生效；没有 Pod 被重建或重启 | PASS |
| K8-03 | ConfigMap 换成一份加载不了的版本：每个副本都报告失败并给出原因，继续用上一份；被拒绝的文件里那条没有问题的路由也没有生效；换回后恢复 | PASS |
| K8-04 | ConfigMap 里改一项只在启动时读取的设置（`storage.mode`）：不重启不生效，滚动重启后生效 | PASS |
| K8-05 | 同一个 ConfigMap，另起一个 CPU 限额为 1 的副本：随文件重载的那部分摘要相同，整个 `/config_dump` 的摘要不同 | PASS |

## 看清的事

### 1. ConfigMap 的变更要几十秒才到 Pod，各副本到的时间不一样

从 `kubectl apply` 到某个副本换上新配置，三轮运行、十二次变更量到的是：

| 情形 | 次数 | 最快的副本 | 最慢的副本 |
|---|---|---|---|
| Pod 启动 45 秒之后做的第一次变更 | 2 | 24 秒 | 37 到 40 秒 |
| 紧接着上一次变更做的变更 | 9 | 55 到 77 秒 | 65 到 84 秒 |
| Pod 刚就绪就做的变更 | 1 | 1.3 秒 | 1.5 秒 |

- 三轮里的头一轮用的是更早的版本：只有前 4 个用例，Pod 一就绪就做第一次变更，表里最后一行就是那一次。那样量到的一两秒不是常态，所以现在的脚本先等 45 秒。为什么刚就绪时这么快，没有去证实。
- 这段时间花在 kubelet 上。按 Kubernetes 文档，kubelet 在每次周期同步时检查挂载的 ConfigMap 是否是新的，延迟最长是一个同步周期加上缓存传播的时间；这个集群的 kubelet 是默认设置（`syncFrequency` 1 分钟，变更检测方式 `Watch`）。文件一变，网关立刻重载（黑盒套件里量到约 0.3 秒）。紧接着上一次变更做的变更，正好赶在各个 Pod 刚同步完，所以等了差不多一整个周期。
- **同一次变更，最先和最后一个副本相差 4 到 17 秒**（不算 Pod 刚就绪的那一次）。这段时间里同一个池的副本跑着不同的配置。
- 数字是每隔一秒多轮询一遍得到的，精确到一两秒。

对发布器的含义：

- 发出 ConfigMap 之后要等一到两分钟才能下"没有生效"的结论。
- 回读必须逐个副本做，不能看到一个副本变了就算整个池变了。
- 一个池内分不了批：ConfigMap 一换，这个池的全部副本都会换上。要分批只能以池为单位。
- G03 §4 说撤销、封禁这类安全变更不能等普通发布的最终一致。这条路属于"普通发布"。

### 2. 加载不了的配置：每个副本各自拒绝，继续用上一份

与黑盒套件在单个实例上看到的一样，只是每个副本各自到达、各自拒绝：`configReload` 变成 `synchronized: false` 并带上原因，`/config_dump` 的摘要不变，原有路由照常，被拒绝的文件里的东西一样都不生效。没有 Pod 因此重启。换回上一份之后各自恢复。

### 3. 只在启动时读取的设置，要滚动重启才生效，而且看得出来

`K8-04` 在 ConfigMap 里把 `storage.mode` 从 `readOnly` 改成 `file`，同时加一条路由。各副本重载之后新路由生效了，但报告的存储模式仍是 `readOnly`；`kubectl rollout restart` 之后才是 `file`。

没重启的副本和重启后的副本，`/config_dump` 里**只有 `config` 段的 `storage` 一项不同**，其余完全相同。也就是说，一项启动时设置"文件里已经改了但还没生效"，从 `/config_dump` 的 `config` 段看得出来。

### 4. `/config_dump` 的摘要不能整个拿来跨实例比

`/config_dump` 的 `config` 段里，除了文件里写的设置，还有网关从运行环境里得出的值。`K8-05` 里 CPU 限额为 1 的副本和没有限额的副本加载同一个 ConfigMap，整个 `/config_dump` 的摘要不同，差别只有一项：`numWorkerThreads`，一边是 1，一边是 20。这一段里还有 DNS 搜索域（带着命名空间的名字），没有专门去试。

去掉 `config` 段之后，四个副本的摘要相同。所以跨实例比对要分成两步：

- 路由、策略、后端这些随文件重载的部分：去掉 `config` 段再算摘要，各实例应当相同。
- `config` 段里发布的文件写了的那几项（`storage.mode`、管理地址等）：逐项比对，不要整段算摘要。

### 5. 回读要进到 Pod 里

网关的管理地址只绑回环，这里是用 `kubectl exec` 进到每个 Pod 里去读的。发布器不该有 `pods/exec` 这样的权限；它怎么够到每个副本的 `/config_dump`、又不让别人够到，还没有设计（见 ADR-0010 的剩余风险）。

## 没有覆盖的

- 多节点集群、节点或 kubelet 重启、Pod 被驱逐后重建；kubelet 同步周期用的是默认值。
- 上游发布的容器镜像、上游的 standalone Helm chart。这里的镜像和清单都是自己写的。
- Service、NetworkPolicy、自动扩缩、PodDisruptionBudget；有流量时换配置。
- 黑盒套件那份带 JWT、ExtAuthZ 和凭证的配置，以及它引用的密钥和证书文件怎么进 Pod。
- 命名空间不同、节点规格不同的实例之间 `config` 段还有哪些项不同。
