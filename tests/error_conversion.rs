#[cfg(test)]
mod conversion_regressions {
    use ntfs::NtfsError;
    #[test]
    fn wrapped_io_keeps_kind() {
        let error = binrw::error::Error::Backtrace(binrw::error::Backtrace::new(
            binrw::error::Error::Io(binrw::io::Error::new(
                binrw::io::ErrorKind::Interrupted,
                "cancelled",
            )),
            vec![],
        ));
        let converted: binrw::io::Error = NtfsError::from(error).into();
        assert_eq!(converted.kind(), binrw::io::ErrorKind::Interrupted);
        assert_eq!(converted.to_string(), "cancelled");
    }
    #[test]
    fn malformed_structure_returns_invalid_data() {
        let error = binrw::error::Error::AssertFail {
            pos: 17,
            message: "bad structure".into(),
        };
        let converted: binrw::io::Error = NtfsError::from(error).into();
        assert_eq!(converted.kind(), binrw::io::ErrorKind::InvalidData);
        assert!(converted.to_string().contains("bad structure"));
    }
}
