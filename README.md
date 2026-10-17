# ROM 规则合并

一个在手机上离线合并 ROM SELinux 的小工具，需要 root，Android 9 起，支持 ARM64。

第一栏填要补规则的 ROM 解包目录，第二栏填提供规则的 ROM。点“开始修改”后，先备份，再合并、编译和检查，通过后写回第一栏。来源目录只读，不刷镜像，也不往正在运行的内核注入规则。

处理 system、system_ext、product、vendor、odm 的 CIL 和 contexts。可以另外选 `sepolicy.rule` 或基础 TE 文件，也可以把当前手机各分区的静态 SELinux 文件作为来源。不会读取内核里 KSU/Magisk 动态注入的策略。

它偏向移植调试：保留宽权限，不因 neverallow 裁掉 allow；来源的 neverallow 和 dontaudit 不导入。contexts 同键冲突时优先平台侧，并记录日志。验证能通过不代表一定开机，建议拿解包目录副本试，备份另外留一份。

界面有实时日志和“保存日志”，做过的任务也能恢复备份。更细的行为见[使用说明](使用说明.txt)。

APK 在 [Releases](https://github.com/Maga-King/ROMPolicyMerge/releases)，[Actions](https://github.com/Maga-King/ROMPolicyMerge/actions/workflows/build.yml) 可以手动编译。原生工具和 Java 都从源码构建，当前 1.0.4 固定工具版本、ZIP 时间戳和原签名，用完整 APK 的 SHA-256 核对；压缩包本身的 digest 是另一个值。

[编译方法](编译.md) · [第三方来源](第三方说明.md)
