use anyhow::Result;
use std::fs;
use std::path::PathBuf;

/// Secure keystore for identity management
pub struct Keystore {
    path: PathBuf,
}

impl Keystore {
    /// Get default keystore path based on OS
    pub fn default_path() -> PathBuf {
        #[cfg(unix)]
        {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".p47h").join("identity.json")
        }
        #[cfg(windows)]
        {
            let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(appdata).join("p47h").join("identity.json")
        }
    }

    /// Create a new keystore with the given path
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Save identity to keystore with secure permissions
    pub fn save(&self, content: &str) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write file
        fs::write(&self.path, content)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600); // Read/Write owner only
            fs::set_permissions(&self.path, perms)?;
        }

        // On Windows, ACLs are not implemented yet
        #[cfg(windows)]
        {
            // P47H-SEC-FIX: Warn about OS limitations until proper DACLs are enforced
            eprintln!("SECURITY WARNING: Identity file permissions are not enforced on Windows.");
            eprintln!("                  Ensure your AppData folder is secure or use --output.");
        }

        Ok(())
    }

    /// Get the path to the keystore
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}
