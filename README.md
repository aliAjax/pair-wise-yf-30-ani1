# 药物警戒案例处理系统

使用 Python 标准库实现的独立原型，覆盖多渠道案例接入、去重、随访更正、严重性医学裁定、分国家报告、逾期升级、跨区域权限、案例合并审计和患者隐私处置单。

## 运行

要求 Python 3.11+。

```bash
python3 app.py --db pharmacovigilance.db
```

默认监听 `127.0.0.1:8201`。首页为 `http://127.0.0.1:8201/`，健康检查为 `/health`。

所有接口使用请求头 `X-User-Id`、`X-Role` 和区域角色必需的 `X-Region`。角色为 `reporter`、`regional_lead`、`medical_reviewer`、`global_admin`。

## 主要接口

- `POST /api/cases`：录入案例，`dedupe_key` 相同则返回已存在案例。
- `GET /api/cases`、`GET /api/cases/{id}`：按权限查询。
- `POST /api/cases/{id}/followups`：用 `expected_revision` 防止覆盖随访。
- `POST /api/cases/{id}/medical-review`：医学审核员更新严重性、死亡和关联性。
- `POST /api/cases/{id}/reports`、`POST /api/reports/{id}/submit`：生成并提交分国家报告。
- `POST /api/cases/{id}/merge`：全局管理员合并重复案例。
- `POST /api/escalate-overdue`、`GET /api/overdue`：逾期检查与升级。
- `POST /api/privacy-requests`：全局管理员登记隐私处置单；`request_key` 相同的申请返回首次结果（幂等）。响应列出同患者案例、未完成报告与待发监管动作及阻塞原因。
- `GET /api/privacy-requests`、`GET /api/privacy-requests/{id}`：医学审核员与全局管理员查看处置单，状态为待处理或已脱敏。
- `POST /api/privacy-requests/{id}/execute`：执行脱敏。存在未提交报告时返回 409 与阻塞原因、申请保持待处理；报告全部结清后才执行。

## 隐私处置流程

1. 登记：按 `patient_ref` 精确匹配同患者案例（含跨区域与登记后新录入的案例），生成处置单并评估阻塞。
2. 阻塞：任一关联案例存在未提交（pending/overdue）监管报告时，申请保持待处理，页面与接口展示阻塞原因；报告结清后才能执行。
3. 执行：`cases.patient_ref` 替换为 HMAC 派生的不可逆代号（同一患者代号一致，无法反推），`intakes.payload_json` 与 `followups.content` 等原始录入内容清除；案例、报告、提交记录与 `audit_log` 处置审计全部保留，审计中不写入原始患者标识。
4. 幂等：相同 `request_key` 重复登记或重复执行均返回首次结果，不产生重复记录。

代码按层分开维护：数据存储在 `app.py` 的 `Repository`，脱敏范围、代号生成与阻塞文案等规则在 `privacy_rules.py`，HTTP 接口在 `app.py` 的 `Handler`，页面在 `static/index.html`。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 主要局限

该实现使用请求头模拟身份，不含生产级登录、签名和密钥管理；SQLite 与标准库 HTTP 服务适合单机原型。分国家规则采用内置严重 15 天、死亡 7 天、非严重 90 天规则，接入真实监管网关前需按当地法规扩展。隐私代号密钥生成后存于 `privacy_meta` 表，销毁密钥即不可再推导代号；生产环境应改用 KMS 管理密钥，且 `request_key` 应使用工单号等不含患者信息的标识。
