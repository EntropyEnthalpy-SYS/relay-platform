# 公告

0.26.0 增加全局/租户公告，作为运营模块的第一个可独立验收部分。

## 模型与可见性

```json
{
  "tenant_id": null,
  "title": "维护通知",
  "body": "今晚 23:00 进行维护",
  "severity": "warning",
  "starts_at_ms": 1790000000000,
  "ends_at_ms": null,
  "enabled": true
}
```

- `tenant_id=null` 是全局公告，所有租户可见；`tenant_id=...` 只对该租户可见。
- 用户列表只返回 `enabled=true` 且 `starts_at_ms <= now < ends_at_ms` 的公告；`ends_at_ms=null` 表示长期。
- 严重级别为 `info`、`warning`、`critical`，列表按级别和开始时间排序。
- 租户管理员可创建/编辑/删除本租户公告，只能查看全局公告；系统管理员可管理全部。普通用户没有管理接口。
- 标题 1..200 字节，正文最多 10,000 字节；结束时间必须晚于开始时间。
- 记录保存在 metadata（`announcement:<id>`），不改变 schema v5、恢复日志和备份。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/announcements` | 当前账号可见的生效公告 |
| GET | `/api/v1/announcements/manage` | 管理员管理列表（租户管理员含全局只读） |
| POST | `/api/v1/announcements` | 创建；全局仅系统管理员 |
| PUT/DELETE | `/api/v1/announcements/{id}` | 编辑/删除，受租户边界约束 |

API 令牌读取需要 `read`，写入需要 `users:write`；仍受账号角色约束。面板“公告”页显示当前公告，管理员可新建/编辑/删除；全局公告对租户管理员只读。

## 验证与限制

- Store/HTTP 测试覆盖全局与租户可见性、其他租户不可见、未来公告不显示、租户管理员不能创建全局/编辑全局、可编辑本租户、删除。
- HTTP 测试覆盖管理员发布、普通用户读取、普通用户写 403、管理列表 403 和删除。
- 未实现公告富文本/附件、已读回执、按用户分组、邮件/推送、定时发布 worker、审批流和多语言。该模块仍未完成完整运营交易（套餐、钱包、订单、支付、退款、佣金、工单）。
