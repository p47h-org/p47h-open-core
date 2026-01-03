use core_policy::Resource;

/// Helper function to parse resource string into Resource enum
pub fn parse_resource(resource: &str) -> Resource {
    if resource == "*" {
        return Resource::All;
    }

    if let Some(stripped) = resource.strip_prefix("file:") {
        return Resource::File(stripped.to_string());
    }

    if let Some(stripped) = resource.strip_prefix("usb:") {
        return Resource::Usb(stripped.to_string());
    }

    if let Some(stripped) = resource.strip_prefix("tunnel:") {
        return Resource::Tunnel(stripped.to_string());
    }

    // Try to parse as custom resource (type:path format)
    if let Some((resource_type, path)) = resource.split_once(':') {
        Resource::Custom {
            resource_type: resource_type.to_string(),
            path: path.to_string(),
        }
    } else {
        // Default to File resource for unqualified paths
        Resource::File(resource.to_string())
    }
}
