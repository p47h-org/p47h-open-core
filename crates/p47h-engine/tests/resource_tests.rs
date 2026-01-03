use core_policy::Resource;
use p47h_engine::parse_resource;

#[test]
fn test_parse_resource() {
    assert!(matches!(parse_resource("*"), Resource::All));
    assert!(matches!(parse_resource("file:/docs/*"), Resource::File(_)));
    assert!(matches!(parse_resource("usb:device1"), Resource::Usb(_)));
    assert!(matches!(parse_resource("tunnel:vpn"), Resource::Tunnel(_)));
    assert!(matches!(
        parse_resource("api:/users"),
        Resource::Custom { .. }
    ));
    assert!(matches!(
        parse_resource("/unqualified/path"),
        Resource::File(_)
    ));
}
