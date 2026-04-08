# Docker容器Web终端功能修复计划

## 问题分析

当前Docker容器的web终端功能存在以下问题：
- 前端页面能成功建立WebSocket连接
- 但无法进行正常的终端操作
- 输入任何命令都没有反应
- 前端和后端都不报错

## 实现计划

### [x] 任务1：诊断前端输入问题
- **Priority**: P0
- **Depends On**: None
- **Description**:
  - 检查前端键盘输入是否正确发送到后端
  - 验证WebSocket连接是否正常
  - 检查xterm.js的配置和事件处理
- **Success Criteria**:
  - 前端能正确捕获键盘输入并发送到后端
  - WebSocket连接状态正常
- **Test Requirements**:
  - `programmatic` TR-1.1: 前端能捕获键盘输入并通过WebSocket发送
  - `human-judgement` TR-1.2: 浏览器控制台能看到发送的WebSocket消息
- **Notes**: 使用浏览器开发者工具监控WebSocket通信

### [x] 任务2：诊断后端接收和处理问题
- **Priority**: P0
- **Depends On**: 任务1
- **Description**:
  - 检查后端是否收到前端发送的输入
  - 验证命令缓冲区是否正确累积输入
  - 检查命令执行逻辑是否正常
- **Success Criteria**:
  - 后端能正确接收前端发送的输入
  - 命令缓冲区能正确累积输入并在收到换行符时执行命令
- **Test Requirements**:
  - `programmatic` TR-2.1: 后端日志能显示接收到的输入
  - `programmatic` TR-2.2: 后端能正确执行命令并获取输出
- **Notes**: 增加详细的日志输出以诊断问题

### [x] 任务3：诊断命令执行和输出问题
- **Priority**: P0
- **Depends On**: 任务2
- **Description**:
  - 检查Docker SDK的命令执行是否正常
  - 验证命令输出是否正确获取
  - 检查输出是否正确发送回前端
- **Success Criteria**:
  - Docker SDK能正确执行命令
  - 命令输出能正确获取并发送回前端
- **Test Requirements**:
  - `programmatic` TR-3.1: 后端能成功执行Docker命令
  - `programmatic` TR-3.2: 命令输出能正确发送到前端
- **Notes**: 测试简单命令如 `ls -la` 和 `pwd`

### [x] 任务4：修复终端功能
- **Priority**: P0
- **Depends On**: 任务3
- **Description**:
  - 根据诊断结果修复终端功能
  - 确保命令能正确执行并显示输出
  - 实现终端提示符和命令历史
- **Success Criteria**:
  - 终端能正确执行命令并显示输出
  - 终端显示提示符
  - 命令执行后能显示新的提示符
- **Test Requirements**:
  - `human-judgement` TR-4.1: 终端能执行 `ls -la` 并显示输出
  - `human-judgement` TR-4.2: 终端能执行 `pwd` 并显示当前目录
  - `human-judgement` TR-4.3: 终端显示提示符并在命令执行后显示新的提示符
- **Notes**: 确保终端功能具备生产环境使用的稳定性

### [x] 任务5：测试和验证
- **Priority**: P1
- **Depends On**: 任务4
- **Description**:
  - 测试各种命令的执行
  - 验证终端在不同场景下的稳定性
  - 确保终端功能符合生产环境要求
- **Success Criteria**:
  - 各种命令都能正确执行
  - 终端在长时间使用后仍然稳定
  - 终端功能符合生产环境要求
- **Test Requirements**:
  - `human-judgement` TR-5.1: 能执行各种Docker容器内的命令
  - `human-judgement` TR-5.2: 终端界面响应及时
  - `human-judgement` TR-5.3: 终端功能稳定可靠
- **Notes**: 测试包括但不限于：文件操作、进程查看、环境变量查看等

## 预期成果

- Docker容器Web终端功能完全正常
- 能执行各种命令并显示输出
- 具备生产环境使用的稳定性和可靠性
- 界面友好，操作流畅