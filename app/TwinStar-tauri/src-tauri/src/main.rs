//! TwinStar 桌面薄壳：真正的应用逻辑都在 [`twinstar_lib`]（桌面与安卓共用）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    twinstar_lib::run()
}
