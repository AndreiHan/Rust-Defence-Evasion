use windows::Win32::System::{
    SystemServices::{PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, SE_SIGNING_LEVEL_MICROSOFT},
    Threading::{ProcessSignaturePolicy, SetProcessMitigationPolicy},
};

fn prevent_third_party_dll_loading() {
    println!("Preventing third party dll loading");
    let mut policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    policy.Anonymous.Flags = SE_SIGNING_LEVEL_MICROSOFT;
    policy.Anonymous.Anonymous._bitfield = 1;
    unsafe {
        let status = SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            std::ptr::from_ref(&policy).cast(),
            std::mem::size_of_val(&policy),
        );
        println!("Set process mitigation policy status: {status:?}");
    }
}

fn main() {
    prevent_third_party_dll_loading();
}
