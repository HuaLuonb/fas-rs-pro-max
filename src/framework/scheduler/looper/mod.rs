// Copyright 2023-2024, shadow3 (@shadow3aaa)
//
// This file is part of fas-rs.
//
// fas-rs is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// fas-rs is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along
// with fas-rs. If not, see <https://www.gnu.org/licenses/>.

mod buffer;
mod clean;
mod policy;

use std::time::{Duration, Instant};

use frame_analyzer::Analyzer;
use likely_stable::{likely, unlikely};
#[cfg(debug_assertions)]
use log::debug;
use log::info;
use policy::{controll::calculate_control, ControllerParams};

use super::{thermal::Thermal, topapp::TopAppsWatcher, FasData};
use crate::{
    api::{trigger_load_fas, trigger_start_fas, trigger_stop_fas, trigger_unload_fas},
    framework::{
        config::Config,
        error::Result,
        node::{Mode, Node},
        pid_utils::get_process_name,
        Extension,
    },
    Controller,
};

use buffer::{Buffer, BufferWorkingState};
use clean::Cleaner;

const DELAY_TIME: Duration = Duration::from_secs(3);

#[derive(PartialEq)]
enum State {
    NotWorking,
    Waiting,
    Working,
}

struct FasState {
    mode: Mode,
    working_state: State,
    delay_timer: Instant,
    buffer: Option<Buffer>,
}

struct AnalyzerState {
    analyzer: Analyzer,
    restart_counter: u8,
    restart_timer: Instant,
}

struct ControllerState {
    controller: Controller,
    params: ControllerParams,
    target_fps_offset: f64,
    usage_sample_timer: Instant,
}

pub struct Looper {
    analyzer_state: AnalyzerState,
    config: Config,
    node: Node,
    extension: Extension,
    therminal: Thermal,
    windows_watcher: TopAppsWatcher,
    cleaner: Cleaner,
    fas_state: FasState,
    controller_state: ControllerState,
}

impl Looper {
    pub fn new(
        analyzer: Analyzer,
        config: Config,
        node: Node,
        extension: Extension,
        controller: Controller,
    ) -> Self {
        Self {
            analyzer_state: AnalyzerState {
                analyzer,
                restart_counter: 0,
                restart_timer: Instant::now(),
            },
            config,
            node,
            extension,
            therminal: Thermal::new().unwrap(),
            windows_watcher: TopAppsWatcher::new(),
            cleaner: Cleaner::new(),
            fas_state: FasState {
                mode: Mode::Balance,
                buffer: None,
                working_state: State::NotWorking,
                delay_timer: Instant::now(),
            },
            controller_state: ControllerState {
                controller,
                params: ControllerParams::default(),
                target_fps_offset: 0.0,
                usage_sample_timer: Instant::now(),
            },
        }
    }

    pub fn enter_loop(&mut self) -> Result<()> {
        loop {
            self.switch_mode();
            let _ = self.update_analyzer();
            self.retain_topapp();

            if self.windows_watcher.visible_freeform_window() {
                self.disable_fas();
            }

            if let Some(data) = self.recv_message() {
                #[cfg(debug_assertions)]
                debug!("original frametime: {:?}", data.frametime);
                if let Some(state) = self.buffer_update(&data) {
                    match state {
                        BufferWorkingState::Usable => self.do_policy(),
                        BufferWorkingState::Unusable => self.disable_fas(),
                    }
                }
            } else if let Some(buffer) = self.fas_state.buffer.as_mut() {
                #[cfg(debug_assertions)]
                debug!("janked !");
                buffer.additional_frametime(&self.extension);

                match buffer.state.working_state {
                    BufferWorkingState::Unusable => {
                        self.restart_analyzer();
                        self.disable_fas();
                    }
                    BufferWorkingState::Usable => self.do_policy(),
                }
            }
        }
    }

    fn switch_mode(&mut self) {
        if let Ok(new_mode) = self.node.get_mode() {
            if likely(self.fas_state.mode != new_mode) {
                info!(
                    "Switch mode: {} -> {}",
                    self.fas_state.mode.to_string(),
                    new_mode.to_string()
                );
                self.fas_state.mode = new_mode;

                if self.fas_state.working_state == State::Working {
                    self.controller_state.controller.init_game(&self.extension);
                }
            }
        }
    }

    fn recv_message(&mut self) -> Option<FasData> {
        info!("开始接收 perf event 数据...");
        info!(
            "Analyzer 状态: restart_counter={}, restart_timer={:?}", 
            self.analyzer_state.restart_counter,
            self.analyzer_state.restart_timer.elapsed()
        );
        
        let result = self.analyzer_state
            .analyzer
            .recv_timeout(Duration::from_millis(100))
            .map(|(pid, frametime)| {
                info!("收到 perf event 数据: pid={}, frametime={:?}", pid, frametime);
                FasData { pid, frametime }
            });
        
        if result.is_none() {
            info!("perf event 接收超时,未收到数据");
            info!("当前 topapp pids: {:?}", self.windows_watcher.topapp_pids());
            if let Some(buffer) = &self.fas_state.buffer {
                info!("当前活跃的 buffer pid: {}", buffer.package_info.pid);
            }
        }
        
        result
    }

    fn update_analyzer(&mut self) -> Result<()> {
        for pid in self.windows_watcher.topapp_pids().iter().copied() {
            let pkg = get_process_name(pid)?;
            if self.config.need_fas(&pkg) {
                info!("尝试附加进程到 analyzer: pid={}, pkg={}", pid, pkg);
                match self.analyzer_state.analyzer.attach_app(pid) {
                    Ok(_) => info!("成功附加进程: pid={}", pid),
                    Err(e) => info!("附加进程失败: pid={}, error={:?}", pid, e),
                }
            }
        }
        Ok(())
    }

    fn restart_analyzer(&mut self) {
        info!("准备重启 analyzer, 计数: {}", self.analyzer_state.restart_counter);
        
        if self.analyzer_state.restart_counter == 1 {
            if self.analyzer_state.restart_timer.elapsed() >= Duration::from_secs(1) {
                info!("执行 analyzer 重启");
                self.analyzer_state.restart_timer = Instant::now();
                self.analyzer_state.restart_counter = 0;
                self.analyzer_state.analyzer.detach_apps();
                match self.update_analyzer() {
                    Ok(_) => info!("analyzer 重启成功"),
                    Err(e) => info!("analyzer 重启失败: {:?}", e),
                }
            }
        } else {
            self.analyzer_state.restart_counter += 1;
        }
    }

    fn do_policy(&mut self) {
        if unlikely(self.fas_state.working_state != State::Working) {
            #[cfg(debug_assertions)]
            debug!("Not running policy!");
            return;
        }

        self.controller_state.controller.refresh_cpu_usage();
        let control = if let Some(buffer) = &self.fas_state.buffer {
            let target_fps_offset = self
                .therminal
                .target_fps_offset(&mut self.config, self.fas_state.mode);
            calculate_control(
                buffer,
                &mut self.config,
                self.fas_state.mode,
                &mut self.controller_state,
                target_fps_offset,
            )
            .unwrap_or_default()
        } else {
            return;
        };

        #[cfg(debug_assertions)]
        debug!("control: {control}khz");

        self.controller_state.controller.fas_update_freq(control);
    }

    pub fn retain_topapp(&mut self) {
        if let Some(buffer) = self.fas_state.buffer.as_ref() {
            if !self
                .windows_watcher
                .topapp_pids()
                .contains(&buffer.package_info.pid)
            {
                let _ = self
                    .analyzer_state
                    .analyzer
                    .detach_app(buffer.package_info.pid);
                let pkg = buffer.package_info.pkg.clone();
                trigger_unload_fas(&self.extension, buffer.package_info.pid, pkg);
                self.fas_state.buffer = None;
            }
        }

        if self.fas_state.buffer.is_none() {
            self.disable_fas();
        } else {
            self.enable_fas();
        }
    }

    pub fn disable_fas(&mut self) {
        match self.fas_state.working_state {
            State::Working => {
                self.fas_state.working_state = State::NotWorking;
                self.cleaner.undo_cleanup();
                self.controller_state
                    .controller
                    .init_default(&self.extension);
                trigger_stop_fas(&self.extension);
            }
            State::Waiting => self.fas_state.working_state = State::NotWorking,
            State::NotWorking => (),
        }
    }

    pub fn enable_fas(&mut self) {
        match self.fas_state.working_state {
            State::NotWorking => {
                self.fas_state.working_state = State::Waiting;
                self.fas_state.delay_timer = Instant::now();
                trigger_start_fas(&self.extension);
            }
            State::Waiting => {
                if self.fas_state.delay_timer.elapsed() > DELAY_TIME {
                    self.fas_state.working_state = State::Working;
                    self.cleaner.cleanup();
                    self.controller_state.target_fps_offset = 0.0;
                    self.controller_state.controller.init_game(&self.extension);
                }
            }
            State::Working => (),
        }
    }

    pub fn buffer_update(&mut self, data: &FasData) -> Option<BufferWorkingState> {
        info!("当前活跃的顶层应用 pids: {:?}", self.windows_watcher.topapp_pids());
        
        if unlikely(
            !self.windows_watcher.topapp_pids().contains(&data.pid) || data.frametime.is_zero(),
        ) {
            info!(
                "buffer 更新检查失败: pid={}, frametime={:?}, 原因: {}",
                data.pid,
                data.frametime,
                if !self.windows_watcher.topapp_pids().contains(&data.pid) {
                    "PID 不在顶层应用列表中"
                } else {
                    "frametime 为零"
                }
            );
            return None;
        }

        let pid = data.pid;
        let frametime = data.frametime;

        if let Some(buffer) = self.fas_state.buffer.as_mut() {
            buffer.push_frametime(frametime, &self.extension);
            info!("更新现有 buffer: pid={}, frametime={:?}", pid, frametime);
            Some(buffer.state.working_state)
        } else {
            let Ok(pkg) = get_process_name(data.pid) else {
                info!("获取进程名称失败: pid={}", data.pid);
                return None;
            };
            
            let target_fps = match self.config.target_fps(&pkg) {
                Some(fps) => {
                    info!("获取目标 FPS 成功: pkg={}, target_fps={:?}", pkg, fps);
                    fps
                },
                None => {
                    info!("应用 {} 未配置目标 FPS", pkg);
                    return None;
                }
            };

            info!("创建新的 fas buffer: pid={}, pkg={}", pid, pkg);

            trigger_load_fas(&self.extension, pid, pkg.clone());

            let mut buffer = Buffer::new(target_fps, pid, pkg);
            buffer.push_frametime(frametime, &self.extension);

            self.fas_state.buffer = Some(buffer);

            Some(BufferWorkingState::Unusable)
        }
    }
}
