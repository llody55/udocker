# Udocker - 移除外部udocker二进制文件实现计划

## 项目现状分析

当前项目的容器终端功能依赖于：
1. 前端：`docker_terminal.html` 通过WebSocket连接到终端服务
2. 后端：`ProxyConsumer` 类使用Docker SDK直接与Docker守护进程交互
3. 外部工具：`udocker` 二进制文件，在 `start.sh` 中启动，运行在后台

**关键问题**：
- 后端已经使用Docker SDK直接管理容器
- 前端默认连接到外部udocker服务，而不是内部Django WebSocket服务
- 外部udocker二进制文件存在安全隐患，不是长久之计

## 实现计划

### [x] 任务1：分析并完善后端WebSocket终端服务
- **Priority**: P0
- **Depends On**: None
- **Description**:
  - 检查 `ProxyConsumer` 类的完整实现，确保它能正确处理终端连接
  - 验证Docker SDK的 `exec_run` 方法是否能满足终端功能需求
  - 确保WebSocket连接能正确处理输入输出流
- **Success Criteria**:
  - 后端能通过Docker SDK创建容器执行实例并建立WebSocket连接
  - 能正确处理终端输入输出
- **Test Requirements**:
  - `programmatic` TR-1.1: 后端能成功创建容器执行实例
  - `programmatic` TR-1.2: WebSocket连接能正确传输数据
  - `human-judgement` TR-1.3: 代码逻辑清晰，注释完整

### [x] 任务2：修改前端连接地址，使用内部WebSocket服务
- **Priority**: P0
- **Depends On**: 任务1
- **Description**:
  - 修改 `docker_terminal.html` 中的WebSocket连接URL
  - 移除对外部udocker服务的依赖
  - 使用内部Django WebSocket服务的URL
- **Success Criteria**:
  - 前端能正确连接到内部WebSocket服务
  - 终端功能正常工作
- **Test Requirements**:
  - `programmatic` TR-2.1: 前端能成功连接到内部WebSocket服务
  - `human-judgement` TR-2.2: 终端界面显示正常，能执行命令

### [x] 任务3：修改start.sh脚本，移除udocker二进制文件启动
- **Priority**: P1
- **Depends On**: 任务2
- **Description**:
  - 修改 `start.sh` 脚本，移除启动udocker二进制文件的代码
  - 只保留启动Django服务的代码
- **Success Criteria**:
  - 服务能正常启动，不依赖udocker二进制文件
- **Test Requirements**:
  - `programmatic` TR-3.1: 执行start.sh后服务能正常启动
  - `programmatic` TR-3.2: 容器终端功能正常工作

### [x] 任务4：移除bin目录下的udocker二进制文件
- **Priority**: P2
- **Depends On**: 任务3
- **Description**:
  - 移除 `bin/amd64/udocker` 和 `bin/arm64/udocker` 文件
  - 清理相关的依赖和配置
- **Success Criteria**:
  - 项目中不再存在udocker二进制文件
  - 服务能正常运行
- **Test Requirements**:
  - `programmatic` TR-4.1: 项目中不存在udocker二进制文件
  - `programmatic` TR-4.2: 服务能正常启动和运行

### [x] 任务5：测试和验证
- **Priority**: P1
- **Depends On**: 任务4
- **Description**:
  - 测试容器终端功能是否正常
  - 验证所有功能是否与之前一致
  - 确保没有引入新的问题
- **Success Criteria**:
  - 容器终端功能完全正常
  - 所有其他功能不受影响
- **Test Requirements**:
  - `programmatic` TR-5.1: 终端能正常连接和执行命令
  - `programmatic` TR-5.2: 其他Docker管理功能正常
  - `human-judgement` TR-5.3: 用户体验与之前一致

## 实现注意事项

1. **WebSocket连接**：确保前端使用正确的内部WebSocket服务URL
2. **Docker SDK**：验证Docker SDK的exec_run方法是否能满足所有终端功能需求
3. **错误处理**：确保后端有良好的错误处理机制
4. **安全性**：确保新的实现方式符合安全最佳实践
5. **兼容性**：确保修改后的代码与现有系统兼容

## 预期成果

- 移除对外部udocker二进制文件的依赖
- 使用内置的Docker SDK实现容器终端功能
- 提高系统安全性和稳定性
- 简化部署和维护流程