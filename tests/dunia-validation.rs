use std::path::PathBuf;

use systemdetection::validate_dunia_file;

#[test]
#[ignore = "requires FC2_DUNIA_DLL to point to a legally obtained Dunia.dll"]
fn validates_user_supplied_dunia_without_loading_it() {
    let path = std::env::var_os("FC2_DUNIA_DLL")
        .map(PathBuf::from)
        .expect("set FC2_DUNIA_DLL to the Dunia.dll path");
    let report = validate_dunia_file(&path)
        .unwrap_or_else(|error| panic!("offline Dunia.dll validation failed: {error}"));

    assert_eq!(report.patches.len(), 5);
    eprintln!(
        "validated {} as {} (file size {}, SizeOfImage 0x{:X})",
        path.display(),
        report.build,
        report.file_size,
        report.image_size
    );
    for patch in report.patches {
        eprintln!(
            "{}: {} ({:?})",
            patch.name,
            patch
                .rvas
                .iter()
                .map(|rva| format!("RVA 0x{rva:08X}"))
                .collect::<Vec<_>>()
                .join(", "),
            patch.state
        );
    }
}
