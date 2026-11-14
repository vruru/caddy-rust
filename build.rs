use std::process::Command;

fn output(program:&std::ffi::OsStr,args:&[&str])->Option<String>{
    let result=Command::new(program).args(args).output().ok()?;
    if !result.status.success(){return None}
    let value=String::from_utf8(result.stdout).ok()?;
    let value=value.trim();
    (!value.is_empty()&&value.len()<=256&&!value.contains(['\n','\r'])).then(||value.to_owned())
}

fn main(){
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=vendor");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/main");
    let rustc=std::env::var_os("RUSTC").unwrap_or_else(||"rustc".into());
    let compiler=output(&rustc,&["--version"]).unwrap_or_else(||"unknown".into());
    let revision=output(std::ffi::OsStr::new("git"),&["rev-parse","HEAD"]).unwrap_or_else(||"source-archive".into());
    println!("cargo:rustc-env=CADDY_RUST_COMPILER={compiler}");
    let dirty=Command::new("git").args(["status","--porcelain","--untracked-files=normal"]).output()
        .ok().is_some_and(|o|o.status.success()&&!o.stdout.is_empty());
    println!("cargo:rustc-env=CADDY_SOURCE_REV={revision}{}",if dirty{"+dirty"}else{""});
    println!("cargo:rustc-env=CADDY_BUILD_TARGET={}",std::env::var("TARGET").unwrap_or_default());
    println!("cargo:rustc-env=CADDY_BUILD_PROFILE={}",std::env::var("PROFILE").unwrap_or_default());
}
