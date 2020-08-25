use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=ipset");
    println!("cargo:rustc-link-lib=static=wrapper");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=wrapper.c");

    cc::Build::new()
        .file("wrapper.c")
        .compile("wrapper");

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .whitelist_function("ipset_parse_line")
        .whitelist_function("ipset_init")
        .whitelist_function("ipset_fini")
        .whitelist_function("ipset_parse_argv")
        .whitelist_function("ipset_parse_stream")
        .whitelist_function("ipset_custom_printf")
        .whitelist_function("ipset_custom_errorfn")
        .whitelist_function("ipset_standard_errorfn")
        .whitelist_function("ipset_load_types")
        .whitelist_function("error_callback")
        .whitelist_function("session_callback")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}