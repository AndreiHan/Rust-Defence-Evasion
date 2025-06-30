use windows::Win32::System::{
    SystemServices::{PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, SE_SIGNING_LEVEL_DYNAMIC_CODEGEN},
    Threading::{ProcessDynamicCodePolicy, SetProcessMitigationPolicy},
};

fn enable_arbitrary_code_guard() {
    let mut policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    policy.Anonymous.Flags = SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
    policy.Anonymous.Anonymous._bitfield = 1;
    unsafe {
        let status = SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            std::ptr::from_ref(&policy).cast(),
            std::mem::size_of_val(&policy),
        );
        println!("Set process mitigation policy status: {status:?}");
    }
}

fn main() {
    enable_arbitrary_code_guard();
}
