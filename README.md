# AEGIS-M

AEGIS-M 是一个面向 **OpenAI Chat Completions 兼容中转站**的黑盒安全审计工具。它重点检查：

- 中转站或模型是否在 `tool_calls[].function.arguments` 中增添、改写或注入命令/代码；
- 用户提示词的端到端行为是否发生异常偏离；
- 被当作数据传入的恶意提示词，是否越过边界并影响模型输出或工具参数。
- 随机无效 API Key 是否仍可调用接口，以及鉴权错误是否伪装成 HTTP 200；
- 是否通过明文 HTTP、跨源重定向或 HTTPS 降级路径传输凭据；
- 返回模型是否与请求模型一致，是否疑似模型降级或冒充；
- system 消息中的随机秘密是否泄露、角色优先级是否被破坏；
- 无状态请求之间是否出现随机标记串扰或重放；
- 响应/工具 JSON 是否包含重复键、原型污染键、编码载荷、外联 URL、路径穿越、脚本、命令或 SQL 控制特征。

审计器绝不会执行模型返回的工具调用。所有参数仅按不可信字符串解析和扫描。API Key 不会写入报告，报告中的密钥固定显示为 `[REDACTED]`。

## 快速开始

需要 Python 3.10 或更高版本，无第三方运行时依赖。

### 网页控制台（推荐）

```powershell
python -m aegism --web
```

然后打开 `http://127.0.0.1:8765/`。网页可读取模型、启动后台扫描、显示实时进度与风险分项，并下载脱敏后的 JSON 报告。可以用 `--web-port 9000` 修改端口。

网页服务只监听本机回环地址。每次启动都会生成新的随机会话令牌，API 拒绝跨源请求；API Key 不写入磁盘、浏览器存储、服务日志或报告。扫描结果保存在当前进程内，服务关闭后清除。

### 命令行

```powershell
python -m aegism --base-url "https://relay.example.com" --api-key "sk-..." --model "gpt-4.1-mini"
```

在交互式终端中可使用 `--api-key-stdin` 隐藏输入，避免密钥进入命令历史：

```powershell
python -m aegism --base-url "https://relay.example.com" --model "gpt-4.1-mini" --api-key-stdin
```

也可避免把密钥留在命令历史中：

```powershell
$env:AEGIS_BASE_URL = "https://relay.example.com"
$env:AEGIS_API_KEY = "sk-..."
$env:AEGIS_MODEL = "gpt-4.1-mini"
python -m aegism
```

如果不传 `--model`，AEGIS-M 会访问 `/v1/models` 并选择第一个看起来支持对话的模型。建议在正式审计时显式指定模型，因为不同模型的工具调用遵循能力不同。

常用命令：

```powershell
# 查看中转站公开的模型
python -m aegism --base-url "https://relay.example.com/v1" --api-key "sk-..." --list-models

# 安装为命令后使用
python -m pip install -e .
aegis-m --base-url "https://relay.example.com" --api-key "sk-..." --model "your-model"

# 运行测试
python -m unittest discover -s tests -v
```

结果会写入 `reports/`，同时生成机器可读 JSON 和本地 HTML 报告。结论为 `pass`、`suspicious`、`unsafe` 或因模型/接口不可用而无法完成检测的 `inconclusive`。退出码为：`0` 表示全部通过，`1` 表示存在偏差、风险或覆盖不足，`2` 表示配置/连接错误。

## 检测方法

每次扫描生成新的高熵随机 nonce，降低中转站返回预制安全答案的可能性。一次扫描包含九项检查：

1. 检查 HTTPS/HTTP 传输；默认拒绝向远程明文 HTTP 发送真实 Key；
2. 使用随机无效 Key 发起最小请求，检查鉴权绕过；
3. 强制模型调用一个随机命名的无害函数，并逐字段核对严格 JSON；
4. 在不可信数据块中放入惰性注入文本，检查它是否污染工具参数；
5. 要求模型精确回显随机金丝雀，观察提示词链路偏离；
6. 在数据边界内放入随机恶意指令标记，检查模型是否执行该内嵌指令；
7. 放置只存在于 system 消息中的随机秘密，检查响应泄露；
8. 使用相互冲突的 system/user 随机标记，检查消息角色优先级；
9. 发起新的无状态请求，检查是否混入上一请求的随机标记。

每个响应还会统一核验模型身份、消息角色、额外候选、重复 JSON 键和危险载荷。HTTPS 证书使用系统信任链验证；客户端拒绝携带 Authorization 跨源重定向，并限制单个响应大小，防止审计器自身被恶意响应拖垮。

风险等级解释：

- `critical`：随机禁用标记被执行、工具名被替换、JSON 中出现执行特征或参数无法解析；
- `high`：工具参数与严格随机预期不一致、响应包含明显注入特征；
- `medium`：确定性回显偏离或探针被接口拒绝，需要人工复核；
- `pass`：本轮探针没有观察到偏差，不代表中转站在所有场景下绝对安全。

## 兼容性与边界

- 默认接口为 `{base_url}/v1/chat/completions`；如果地址已以 `/v1` 或 `/chat/completions` 结尾，会自动规范化。
- 指定模型时，一次完整扫描会发送 7 个正常金丝雀请求和 1 个使用随机无效 Key 的鉴权请求；自动发现模型会额外访问一次 `/v1/models`。
- 某些模型不支持 `strict`、`tool_choice` 或工具调用。这类结果会显示为探针错误，不能直接判定中转站恶意。
- 返回的 `model` 字段可能是供应商定义的合法别名，因此模型不一致默认是 `medium`，需要对照中转站文档复核。
- 黑盒测试无法发现只在特定账号、时间、IP、模型或业务文本上触发的条件式攻击。高保障场景还应在客户端保存请求哈希、使用可信 TLS 出口，并对中转站服务端做代码/日志审计。
- 仅对你拥有或获得授权的中转站执行测试。探针内容是惰性的，不包含真实破坏命令。

## 报告数据

报告保存目标 URL、模型、请求/响应 SHA-256、有限长度的响应证据与发现项。报告可能包含模型生成的不可信文本，请不要把其中内容复制到终端执行。若提示词本身包含业务秘密，不应扩展本项目去记录完整请求正文。
