[English](./README.md) | 中文

# VulSolver

[![离线检查](https://github.com/l3s10n/llm-code-analysis/actions/workflows/offline-checks.yml/badge.svg)](https://github.com/l3s10n/llm-code-analysis/actions/workflows/offline-checks.yml)

VulSolver 是一个通过逐步约束求解实现仓库级漏洞检测的 LLM 框架。它分析潜在的 source-to-sink 调用路径，区分可利用的路径与受到检查、数据变换或业务逻辑阻断的路径。

VulSolver 沿候选路径逐跳分析调用者与被调用者，考虑相关旁支方法的影响，并传播漏洞相关数据的紧凑状态。维护的状态及支持证据用于判断路径可达性和 sink 可利用性，避免在每一步反复提供整条调用链。

论文在 [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) 的 1,023 个用例上评估 VulSolver，覆盖命令注入、路径穿越和 SQL 注入，并测试了 GLM-4.7、Kimi-K2、DeepSeek-V3、DeepSeek-V4-Pro、GPT-4o 和 GPT-4-Turbo 六种模型。下表报告整体表现最好的 **DeepSeek-V4-Pro** 的结果，所有行均使用这一模型；包括 F1 在内的全部指标统一使用百分比。

| 漏洞类型 | 准确率 | 精确率 | 召回率 | F1-Score |
| :--- | :--- | :--- | :--- | :--- |
| Overall | 99.41% | 100.00% | 98.87% | 99.43% |
| Command Injection | 99.20% | 100.00% | 98.41% | 99.20% |
| Path Traversal | 99.63% | 100.00% | 99.25% | 99.62% |
| SQL Injection | 99.40% | 100.00% | 98.90% | 99.45% |

论文在基线比较及后续实验中默认统一使用 Kimi-K2，另有说明的除外；它在整个基准上的 F1 为 97.97%，召回率为 100%。不同漏洞类型的最佳模型可能不同，例如 GLM-4.7 的 SQL 注入 F1 最高，为 99.63%。这些结果来自不同配置，没有混合到上表中。

VulSolver 目前支持路径穿越、命令注入、代码注入、SQL 注入和 SSRF 漏洞检测。上面的受控基准只评估了命令注入、路径穿越和 SQL 注入，不包含代码注入或 SSRF 的基准测试分数。

论文的真实项目研究覆盖十个广泛使用的开源项目（统计时的 star 数为 1.4k–38.2k），发现了 **40+ 个漏洞**。以下列出部分早期披露的 CVE 编号，并非此次研究的完整漏洞清单。

- CVE-2025-50745
- CVE-2025-5384
- CVE-2025-5385
- CVE-2025-5386
- CVE-2025-5387
- CVE-2025-5388
- CVE-2025-5389
- CVE-2025-5390

漏洞发现过程自动执行，报告的发现随后经过人工代码审查、在测试环境中编写并执行 PoC 以及受影响项目维护者确认。有效告警的比例衡量的是告警精确率，不表示已经发现项目中的全部漏洞。由于与其他研究者同期重复报告，部分 CVE 编号被分配给了其他发现者。

# 安装与配置

通过以下命令安装 VulSolver 的必要依赖：

```bash
pip3 install -r requirements.txt
```

在 `config.yaml` 配置文件中补充模型调用信息：

```
llm:
  base_url: "普通模型的base_url"
  api_key: "普通模型的api_key"
  model: "普通模型的模型名称"

decision_llm:
  base_url: "复杂决策模型的base_url"
  api_key: "复杂决策模型的api_key"
  model: "复杂决策模型名称"
```

`decision_llm` 是可选配置，三个字段全部填写时用于最终可利用性判断，否则该阶段回退到 `llm`。保持未配置即可让整个分析过程使用同一模型，与论文中每次实验的设置一致。修改配置后需要重新启动进程。

> 由于 VulSolver 目前基于 Claude Code SDK 搭建必要的 agents，请确保你的 `base_url` 支持 Anthropic 的接口格式。

# 使用

以下命令均从 VulSolver 仓库根目录执行。结果、日志和缓存文件的路径相对于当前工作目录。

如果已有 SAST 生成的候选路径，可直接使用下文的[独立路径验证入口](#与-sast-结合使用)；路径中已经记录入口，不需要额外指定接口参数。若希望使用内置的 `path_explore` 模块从指定接口发现路径，再验证这些路径，则运行：

```bash
python3 main.py <待分析项目根目录> <待分析项目接口名> # 例如：python3 main.py '/tmp/helloProject' '/sample/hello'
```

如果希望一次分析多个接口，可以通过 `--interface-file` 提供一个接口列表文件，每行一个接口。空行和以 `#` 开头的行会被忽略，接口按文件中的顺序处理：

```bash
python3 main.py <待分析项目根目录> --interface-file <接口列表文件>
```

例如：

```bash
python3 main.py '/tmp/helloProject' --interface-file './interfaces.txt'
```

如果你希望禁用 Textual TUI、直接在终端输出分析进度，可以添加 `--no-tui`：

```bash
python3 main.py <待分析项目根目录> <待分析项目接口名> --no-tui
```

你也可以将 `--interface-file` 和 `--no-tui` 组合使用：

```bash
python3 main.py <待分析项目根目录> --interface-file <接口列表文件> --no-tui
```

**注意：** 请勿使用 `sudo` 或以 root 用户身份运行。

执行过程中，VulSolver 默认会以 TUI 的形式实时展示模型分析过程：

![VulSolver 示例](assets/example.jpg)

如果指定了 `--no-tui`，VulSolver 会直接在终端输出分析进度和总结信息。

# 结果详情查阅

结果保存在相对于工作目录的 `results/<项目名>/<接口名>/` 下。构造目录名时，接口名首尾的 `/` 会被去掉，其余 `/` 会替换为 `_`，例如 `/example/read` 对应 `example_read`。

`potential_paths.json` 记录候选调用链。每个 `Path` 节点使用相对于目标项目根目录的 `file_path`、`function_name`，以及**从 1 开始、包含首尾两行**的 `start_line` 和 `end_line`。节点按入口方法到调用 sink 的方法排序，sink 表达式单独放在 `SinkExpression` 中。验证器从目标代码中按这些位置读取源码。以下示例同时提供了[JSON 文件及对应的 Java 源码](examples/sast_paths/potential_paths.json)：

```json
[
  {
    "InterfaceName": "/example/read",
    "Type": "PathTraversal",
    "SinkExpression": "Files.readString(Path.of(fileName))",
    "Path": [
      {
        "file_path": "ExampleController.java",
        "function_name": "read",
        "start_line": 7,
        "end_line": 9
      },
      {
        "file_path": "ExampleController.java",
        "function_name": "readFile",
        "start_line": 11,
        "end_line": 13
      }
    ]
  }
]
```

`verified_paths.json` 保留 `InterfaceName`、`Type`、`SinkExpression` 和同样的 `Path` 位置信息，并增加以下字段：

| 字段 | 内容 |
| :--- | :--- |
| `IsVulnerable` | 当前候选路径的可利用性布尔判断。 |
| `Confidence` | 决策阶段返回的置信度标签。 |
| `Summary` | 判断结果的解释。 |
| `DataflowAnalysis` | 每条记录包含 `NodeIndex`（从 0 开始）、`NodeName`、`Parameters`、`MemberVariables` 和 `NonLocalSources`。最后一项记录影响 sink 关键语义的非局部数据读取描述。 |
| `FilterLogics` | 每条记录包含 `Dataflow`（受影响的调用者侧数据项）、`Description`、`File` 和 `Lines`（如 `10-20`，无法确定时为 `Unknown`）。 |

探索阶段发现候选路径时写入 `potential_paths.json`，验证阶段产生结果时写入 `verified_paths.json`。独立验证入口读取已有候选路径文件，不会重新生成候选文件。

# 日志详情查阅

日志保存在相对于工作目录的 `logs/<项目名>/<接口名>/` 下。执行探索阶段时，`path_explore.log` 记录接口探索过程；`path_verify.log` 记录路径验证过程。探索日志末尾会展示从接口到 sink 的路径树，例如：

```
<VulSolver 探索调用树的过程>

BenchmarkTest00011.java#doPost
    ├── Sink
    └── Sink
```

`path_verify.log` 则记录了对探索树上提取到的若干调用路径的分析详情，以调用链条开头，随后是整个链路的详细验证过程：

```
Type: PathTraversal
Sink Expression: new java.io.File(param, "/Test.txt")

Call Chain:
  doPost → sink

Path Nodes:
  [0] doPost
      File: BenchmarkTest00011.java

<VulSolver 验证该条链路的过程>
```

# 与 SAST 结合使用

VulSolver 将候选路径构建与可利用性分析分开：SAST 前端根据调用图及 source/sink 规则提供候选调用链，`path_verify` 模块通过 LLM 语义分析判断这些路径的可利用性，不要求或采用前端给出的可利用性判断。内置的 `path_explore` 模块也可以提供候选路径。

将 SAST 候选路径导出为上文的 `potential_paths.json` 格式，源码位置必须对应同一份目标代码。不同 `InterfaceName` 的路径应分别存入不同文件，因为验证器使用第一条路径的接口名命名本次运行的结果和日志目录。随后运行：

```bash
python3 -m path_verify.verify <待分析项目的代码根目录> <potential_paths.json 的文件路径> --no-tui
```

配置好模型后，可以直接运行仓库中的合成示例：

```bash
python3 -m path_verify.verify ./examples/sast_paths ./examples/sast_paths/potential_paths.json --no-tui
```

该示例直接导入候选路径并读取匹配的 Java 源码，不调用 `path_explore`，也不需要启动 Java 应用；验证仍然需要调用配置的 LLM。可通过包含目录部分的路径指定输出文件，例如 `-o ./results/example_verified.json`；去掉 `--no-tui` 则使用 Textual 界面。

# 开发说明

离线回归测试方法以及配置、缓存和重试行为见[开发说明](docs/DEVELOPMENT.md)。向 `main` 推送或发起合并请求时，GitHub Actions 会在 Python 3.11 和 3.12 上执行这些检查；上方徽章展示实际运行状态。测试使用临时占位配置并阻断模型请求，不需要 API 凭据。
