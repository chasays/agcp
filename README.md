# AGCP MVP (Rust)

一个端到端的 AGCP 最小可用实现，覆盖：
- Policy Engine
- Capability Token (Ed25519)
- Tool Gateway (mock)
- Audit Ledger (append-only WAL + hash chain)
- Governor (kill/degrade)
- Human Approval

## 目录结构

- `/Users/rikxiao/source/AGCP/src/proto.rs`: 协议核心类型
- `/Users/rikxiao/source/AGCP/src/crypto.rs`: JSON+JCS、签名验签、哈希
- `/Users/rikxiao/source/AGCP/src/policy.rs`: 策略评估与预算
- `/Users/rikxiao/source/AGCP/src/token.rs`: capability token 签发/校验
- `/Users/rikxiao/source/AGCP/src/governor.rs`: kill/degrade 状态机
- `/Users/rikxiao/source/AGCP/src/gateway.rs`: tool gateway 与 mock 执行
- `/Users/rikxiao/source/AGCP/src/ledger.rs`: WAL 与链完整性校验
- `/Users/rikxiao/source/AGCP/src/api.rs`: HTTP API
- `/Users/rikxiao/source/AGCP/config/policy.devops.toml`: DevOps 策略模板
- `/Users/rikxiao/source/AGCP/scripts/regression.sh`: 6 场景回归脚本

## 启动

1. 安装 Rust 稳定版（`rustup`, `cargo`）。
2. 在项目目录执行：

```bash
cargo run
```

服务监听：`http://127.0.0.1:8080`

## API

- `POST /v1/actions/submit`
- `POST /v1/actions/{action_id}/approve`
- `POST /v1/governor/kill`
- `POST /v1/governor/degrade`
- `GET /v1/audit/{action_id}`
- `GET /v1/health`

## 生成签名请求样例

```bash
cargo run --example make_payload -- low act-low-1 run-low
cargo run --example make_payload -- high act-esc-1 run-esc
cargo run --example make_payload -- read_only_write act-ro-1 run-ro
```

## 回归脚本

先启动服务，再执行：

```bash
./scripts/regression.sh
```

脚本覆盖：
1. 健康检查
2. 低风险动作直接执行
3. 高风险动作进入 ESCALATE
4. 人审批准后执行
5. read-only 下写操作阻断
6. 审计查询

## 当前限制

- `runtime_attestation` 仅占位，不做真实 TEE 证明。
- tool 执行器是 mock，不触达生产系统。
- 单进程单节点，不含分布式一致性。
- 密钥本地文件管理（`/Users/rikxiao/source/AGCP/data/policy_signing_key.b64`）。
