#![allow(clippy::uninlined_format_args)]

use cmake::Config;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

fn main() {
    let target = env::var("TARGET").expect("Cargo did not provide TARGET");
    assert_eq!(
        target, "aarch64-apple-darwin",
        "the admitted Grok Build+ whisper.cpp patch supports macOS arm64 only"
    );
    reject_ambient_build_overrides();

    println!("cargo:rustc-link-lib=dylib=c++");
    println!("cargo:rustc-link-lib=framework=Accelerate");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=src/bindings.rs");
    println!("cargo:rerun-if-changed=whisper.cpp");

    let out = PathBuf::from(env::var("OUT_DIR").expect("Cargo did not provide OUT_DIR"));
    std::fs::copy("src/bindings.rs", out.join("bindings.rs"))
        .expect("copy the admitted bundled bindings");
    let whisper_root = out.join("whisper.cpp");
    if !whisper_root.exists() {
        std::fs::create_dir_all(&whisper_root).expect("create whisper.cpp build source root");
        fs_extra::dir::copy("./whisper.cpp", &out, &Default::default())
            .expect("copy admitted whisper.cpp sources");
    }

    let mut config = Config::new(&whisper_root);
    config
        .profile("Release")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("CMAKE_OSX_ARCHITECTURES", "arm64")
        .define("CMAKE_OSX_DEPLOYMENT_TARGET", "15.0")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("WHISPER_ALL_WARNINGS", "OFF")
        .define("WHISPER_ALL_WARNINGS_3RD_PARTY", "OFF")
        .define("WHISPER_BUILD_TESTS", "OFF")
        .define("WHISPER_BUILD_EXAMPLES", "OFF")
        .define("WHISPER_BUILD_SERVER", "OFF")
        .define("WHISPER_CURL", "OFF")
        .define("WHISPER_FFMPEG", "OFF")
        .define("WHISPER_SDL2", "OFF")
        .define("WHISPER_COREML", "OFF")
        .define("WHISPER_OPENVINO", "OFF")
        .define("WHISPER_USE_SYSTEM_GGML", "OFF")
        .define("GGML_ACCELERATE", "ON")
        .define("GGML_BLAS", "ON")
        .define("GGML_BLAS_VENDOR", "Apple")
        .define("GGML_METAL", "OFF")
        .define("GGML_OPENMP", "OFF")
        .define("GGML_RPC", "OFF")
        .define("GGML_BACKEND_DL", "OFF")
        .define("GGML_NATIVE", "OFF")
        .define("GGML_CCACHE", "OFF")
        .define("GGML_LLAMAFILE", "OFF")
        .define("GGML_BUILD_TESTS", "OFF")
        .define("GGML_BUILD_EXAMPLES", "OFF")
        .very_verbose(true)
        .pic(true);

    let destination = config.build();
    add_link_search_path(&out.join("build")).expect("enumerate native build outputs");
    println!("cargo:rustc-link-search=native={}", destination.display());
    for library in ["whisper", "ggml", "ggml-base", "ggml-cpu", "ggml-blas"] {
        println!("cargo:rustc-link-lib=static={library}");
    }
    println!(
        "cargo:WHISPER_CPP_VERSION={}",
        get_whisper_cpp_version(&whisper_root)
            .expect("read whisper.cpp CMake config")
            .expect("find the whisper.cpp version declaration")
    );
    let _ = std::fs::remove_file("bindings/javascript/package.json");
}

fn reject_ambient_build_overrides() {
    for feature in [
        "CARGO_FEATURE_COREML",
        "CARGO_FEATURE_CUDA",
        "CARGO_FEATURE_FORCE_DEBUG",
        "CARGO_FEATURE_HIPBLAS",
        "CARGO_FEATURE_INTEL_SYCL",
        "CARGO_FEATURE_METAL",
        "CARGO_FEATURE_OPENBLAS",
        "CARGO_FEATURE_OPENMP",
        "CARGO_FEATURE_VULKAN",
    ] {
        assert!(
            env::var_os(feature).is_none(),
            "unadmitted whisper.cpp feature is enabled: {feature}"
        );
    }
    for (key, _) in env::vars_os() {
        let key = key.to_string_lossy();
        if key == "CMAKE"
            || key.starts_with("CMAKE_")
            || key.starts_with("WHISPER_")
            || key.starts_with("GGML_")
        {
            panic!("unadmitted native build override is set: {key}");
        }
    }
}

fn add_link_search_path(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        println!("cargo:rustc-link-search={}", dir.display());
        for entry in std::fs::read_dir(dir)? {
            add_link_search_path(&entry?.path())?;
        }
    }
    Ok(())
}

fn get_whisper_cpp_version(whisper_root: &Path) -> std::io::Result<Option<String>> {
    let cmake_lists = BufReader::new(File::open(whisper_root.join("CMakeLists.txt"))?);
    for line in cmake_lists.lines() {
        let line = line?;
        if let Some(suffix) = line.strip_prefix(r#"project("whisper.cpp" VERSION "#) {
            return Ok(Some(suffix.trim_end_matches(')').into()));
        }
    }
    Ok(None)
}
