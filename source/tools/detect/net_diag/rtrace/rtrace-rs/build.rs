use std::path::PathBuf;
fn main() {
    let libpath = PathBuf::from(env!("OBJ_LIB_PATH"));
    let mut librtrace_path = libpath.clone();
    librtrace_path.push("librtrace.a");

    println!("cargo:rerun-if-changed={}", librtrace_path.display());

    println!("cargo:rustc-link-search={}", libpath.display());
    println!("cargo:rustc-link-lib=static=rtrace");
}
 