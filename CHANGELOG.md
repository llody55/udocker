# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/llody55/udocker/compare/v1.1.6...HEAD)

## [1.1.8 ](https://github.com/llody55/udocker/compare/v1.1.5...v1.1.6)- 2026-04-09

### Changed

- 容器终端 - 优化容器空格键被锁定的问题。
- 容器终端 - 优化容器的终端提示符全屏模式下被遮挡问题。
- 其他 - 优化部分提示信息。

## [1.1.7](https://github.com/llody55/udocker/compare/v1.1.5...v1.1.6) - 2026-04-08

### Changed

- 主机终端 - 重写主机终端页面，显示更友好一点。
- 系统信息 - 优化提醒功能，提示更友好。
- 容器终端 - 去除容器终端外部依赖程序，后续将外部程序优化为agent
- 容器终端 - 优化终端页面用户体验，修复连接管理问题
- 容器终端 - 修复终端提示符被底部遮挡的问题
- 容器终端 - 优化配置区域空间占用，采用水平布局
- 构建流程 - 优化GitHub流水线，改为在推送tag时触发构建
- 版本管理 - 新增VERSION文件统一管理版本号
- 发布流程 - 新增CHANGELOG.md文件管理发布说明，实现自动化提取

## [1.1.6](https://github.com/llody55/udocker/compare/v1.1.5...v1.1.6) - 2024-11-05

### Changed

- 容器管理 - 修复查看容器详情时，耗时长的问题。
- 容器管理 - 优化因为镜像过长而被隐藏的问题，采用tips方式进行展示，单击镜像字段即可复制完整镜像地址。
- 容器管理 - 新增详情页，磁盘统计功能，通过挂载容器路径，即可实时统计容器的磁盘占用情况。
- 页面优化。
- 其他 - 修复因网络失败导致图标失效问题。

## [1.1.5](https://github.com/llody55/udocker/compare/v1.1.4...v1.1.5) - 2024-10-18

### Changed

- 容器管理 - 修复镜像管理占用判断逻辑。
- 镜像仓库 - 新增compose应用判断。
- 页面优化。
- 流水线优化 - 新增同步国内镜像仓库镜像。

## [1.1.4](https://github.com/llody55/udocker/releases/tag/v1.1.4) - 2024-07-02

### Changed

- 容器管理 - 新增镜像回滚功能，可以对容器正在使用的镜像进行镜像回滚，切换镜像并重新创建容器。
- 镜像仓库 - 新增dockerhub代理,(docker.llody.cn)。
- 页面优化。
- 流水线优化 - 新增同步国内镜像仓库镜像。

