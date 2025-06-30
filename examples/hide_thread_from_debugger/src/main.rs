use windows::{
    Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger},
    Win32::System::Threading::GetCurrentThread,
};

pub fn hide_current_thread_from_debuggers() {
    println!("Hiding current thread from debuggers");
    unsafe {
        let status = NtSetInformationThread(
            GetCurrentThread(),
            ThreadHideFromDebugger,
            std::ptr::null(),
            0,
        );
        println!("Set anti debug status: {status:?}");
    }
}

fn main() {
    hide_current_thread_from_debuggers();
}
