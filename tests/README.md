# 回归测试

构建脚本和 GitHub Actions 不连接手机。设备测试默认禁用；未显式设置 `RPM_ALLOW_DEVICE_TESTS=1` 与 `RPM_TEST_SERIAL` 时，在首次 ADB 调用前退出。

手机上的大型数据处理会占用内存、swap 和 IO，严重时会导致 SystemUI ANR。不要把大量日志、递归 grep 或多个编译任务同时放到日用手机运行；批量检索、日志处理和构建应放在电脑。测试目录隔离只能保护文件，不能隔离资源占用。

本次 APK 的回归结果记录于根目录的发布说明。发布到仓库时另外收紧了测试入口：默认关闭、必须指定设备，小型集成测试默认 Java 堆为 512 MiB。没有为了验证这些入口调整再次运行手机测试。

确认设备资源允许后，可在 Windows 设置以下参数。这里只给显式手动入口，不自动探测或选择手机：

```powershell
$env:PYTHONUTF8 = '1'
$env:RPM_ALLOW_DEVICE_TESTS = '1'
$env:RPM_TEST_SERIAL = '你明确选定的测试设备序列号'
$env:RPM_TEST_APK = '/data/local/tmp/你已经推送的测试APK.apk'
$env:RPM_TEST_HEAP = '512m'
python tests/device_tests.py
python tests/integration_tests.py
```

ADB 可放在 PATH 或用 `RPM_ADB` 指定；JDK 使用 `JAVA_HOME`。设备需 root；集成测试还读取已安装 `dev.rompolicy.merge` 的原生工具目录，必须确认其 secilc/policytool 与待测试 APK 一致。

`device_tests.py` 创建新的 `/data/local/tmp/rpm-app-test-*` 目录并写入本地状态，其他测试使用这个目录。随后可按需逐项运行 `context_priority_tests.py`、`legacy_version_tests.py`、`ota_debug_tests.py`、`source_namespace_tests.py`、`transaction_recovery_tests.py`；不要同时运行，旧事务不能复用。

`real_ota_replay.py` 属于额外的大型策略测试，还必须显式设置 `RPM_ALLOW_REAL_REPLAY=1`。其两个位置参数分别是目标策略和来源策略的只读解包根目录，可选 `--extra` 指定规则文件。脚本只复制约定分区的 `etc/selinux` 到临时目录，验证后重复合并再恢复；摘要计算限定在这些策略目录，数据解析在电脑进行。它仍会运行原生完整编译器，不能仅凭 Java 堆限制保证手机不发生内存或 IO 压力。

遇到设备断开或进程被终止，先检查测试任务的 `transaction.json`，必要时恢复对应测试副本；不要把未完成候选当作成功结果。不要把这些脚本的测试路径替换成正在使用的 ROM 写回目标。
