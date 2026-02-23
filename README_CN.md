[English](./README.md) | 中文

# VulSolver

大语言模型（LLM）因其能够理解代码语义（传统静态应用程序安全测试（SAST）工具所缺乏的能力），正在被探索用于漏洞发现。典型的方法以构建基于 LLM 的智能体为核心，LLM 作为"大脑"，协调工具和知识来识别漏洞。然而，由于 LLM 输出的不可预测性以及在处理大型代码库时准确性的严重下降，这种方法存在关键的不稳定性和不准确性。某些方法以 SAST 为中心，使用 LLM 生成规则或验证告警。虽然这些方法更加稳定，但它们仍然受限于 SAST 的固有局限性，无法充分利用 LLM 的语义理解能力。

受人类专家进行安全审计方式的启发，我们推出了 VulSolver，一种与现有方法不同的 LLM 驱动漏洞检测新范式。VulSolver 在分析过程中通过受控的方式增量构建并主动复用已验证的安全结论。这使 LLM 无需反复重新检查或记忆之前的代码，同时保持完整的上下文感知，从而显著提高了稳定性和准确性。

实验证明了 VulSolver 在多个指标上识别漏洞的卓越性能。具体而言，VulSolver 在 OWASP Benchmark（https://github.com/OWASP-Benchmark/BenchmarkJava）的 Path Traversal、Command Injection 和 SQL Injection 漏洞（共 1,023 个测试用例）上取得了以下结果：

| 漏洞类型 | 准确率 | 精确率 | 召回率 | F1-Score |
| :--- | :--- | :--- | :--- | :--- |
| Overall | 99.12% | 99.81% | 98.49% | 0.9915 |
| Command Injection | 98.41% | 100.00% | 96.83% | 0.9839 |
| Path Traversal | 98.88% | 100.00% | 97.74% | 0.9886 |
| SQL Injection | 99.60% | 99.63% | 99.63% | 0.9963 |

VulSolver 目前支持路径穿越、命令执行、代码执行和 SQL 注入漏洞的检测，并正在持续扩展以支持更多漏洞类型。

# 安装与配置

通过以下命令安装 VulSolver 的必要依赖：

```bash
pip install -r requirements.txt
```

在 `config.yaml` 配置文件中补充模型调用信息：

```
llm:
  base_url: "你的base_url"
  api_key: "你的api_key"
  model: "你的模型名称"
```

> 由于 VulSolver 目前基于 Claude Code SDK 搭建必要的 agents，请确保你的 `base_url` 支持 Anthropic 的接口格式。

# 使用

VulSolver 以接口（HTTP 接口、RPC 接口等入口）为维度深入分析代码，通过以下简单的命令即可对项目的接口做深入分析：

```python
python3 main.py <待分析项目根目录> <待分析项目接口名> # 例如：python3 main.py '/tmp/helloProject' '/sample/hello'
```

执行过程中 VulSolver 会以 TUI 的形式实时展示模型分析过程：

<table>
  <tr>
    <td><img src="assets/path_explore_sample.png" alt="path_explore"></td>
    <td><img src="assets/path_verify_sample.png" alt="path_verify"></td>
  </tr>
</table>

执行结束后，VulSolver 会在终端展示必要的总结信息。

# 结果详情查阅

VulSolver 执行结束后，你可以在 VulSolver 根目录下的 `results/<项目名>/<接口名>` 看到名为 `potential_paths.json` 与 `verified_paths.json` 的结果文件。前者详细记录了从给定接口出发潜在的漏洞调用链条，后者详细记录了调用链条是否存在漏洞、以及其中导致漏洞无法利用的逻辑的位置等。具体而言，两个文件的内容如下：

potential_paths.json:

```json
[
  {
    "InterfaceName": <分析的接口名称>,
    "Type": <漏洞类型>,
    "SinkExpression": <sink的表达式>,
    "Path": [
      {
        "file": <该函数节点所在文件>,
        "name": <该函数节点名称>,
        "source_code": <该函数节点源码>
      },
      <调用链路上其他节点信息，格式同上>
    ]
  },
  <其他调用链路信息，格式同上>
]
```

verified_paths.json:

```json
[
  {
    "InterfaceName": <分析的接口名称>,
    "Type": <漏洞类型>,
    "SinkExpression": <sink的表达式>,
    "Path": [
      {
        "file": <该函数节点所在文件>,
        "name": <该函数节点名称>,
        "source_code": <该函数节点源码>
      },
      <调用链路上其他节点信息，格式同上>
    ],
    "IsVulnerable": <是否存在漏洞>,
    "Confidence": <置信度>,
    "Summary": <分析总结>,
    "DataflowAnalysis": [
      {
        "NodeIndex": 0,
        "NodeName": <该函数节点名称>,
        "Parameters": <当前函数中，所有最终流向 sink 的参数列表>,
        "MemberVariables": <当前函数中，所有最终流向 sink 的成员变量列表>
      },
      <其他函数节点的数据流信息>
    ],
    "FilterLogics": [
      {
        "Dataflow": <发生在什么数据流传递过程中>,
        "Description": <该逻辑的描述>,
        "File": <该逻辑所在文件>,
        "Lines": <该逻辑所在行>
      },
      <其他导致漏洞无法利用的逻辑>
    ]
  },
  <其他调用链路分析结果信息，格式同上>
]
```

# 日志详情查阅

VulSolver 执行结束后，你可以在 VulSolver 根目录下的 `logs/<项目名>/<接口名>` 看到名为 `path_explore.log` 与 `path_verify.log` 的日志文件。两者详细记录了 VulSolver 的分析过程。其中 `path_explore.log` 包含详细的接口探索过程，其结尾会展示该接口的探索树，记录了从该接口到若干 sink 的路径，例如：

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

VulSolver 总体上分为两个模块 —— `path_explore` 与 `path_verify`，前者用于发现调用链路，后者用于验证调用链路。如果你认为某些 SAST 的漏洞发现能力较强，但是误报较高，可以将 SAST 与 VulSolver 结合使用，用 SAST 替代 `path_explore` 模块，使用 `path_verify` 进一步验证 SAST 的告警。

你需要做的是将 SAST 的告警按照上文 `potential_paths.json` 的格式维护起来，然后执行如下命令即可使用 VulSolver 对路径做验证：

```bash
python3 -m path_verify.verify <待分析项目的代码根目录> <上文 potential_paths.json 的文件路径>
```
