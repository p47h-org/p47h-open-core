//! # if-ipc: IPC Security Interfaces
//!
//! IPC security primitives and authentication traits for validating peer credentials
//! (UID/GID/PID) across Unix (`SO_PEERCRED`) and Windows (Named Pipes) boundaries.
//!
//! Provides `IpcAuthenticator` trait for enforcing user isolation and preventing
//! local privilege escalation in daemon/client communication.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// IPC Authentication errors
#[derive(Debug, Error)]
pub enum IpcAuthError {
    /// Credenciales de peer no disponibles (e.g., Windows sin soporte)
    #[error("Peer credentials not available on this platform")]
    CredentialsUnavailable,

    /// Conexión rechazada: cliente es root/Administrator (política de seguridad)
    #[error("Connection rejected: client running as privileged user (UID {uid})")]
    PrivilegedUserRejected { uid: u32 },

    /// Conexión rechazada: cliente es de otro usuario
    #[error("Connection rejected: client UID {client_uid} does not match daemon UID {daemon_uid}")]
    UnauthorizedUser { client_uid: u32, daemon_uid: u32 },

    /// Error de sistema operativo al obtener credenciales
    #[error("OS error getting peer credentials: {0}")]
    OsError(String),

    /// Error de I/O
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IpcAuthError>;

// ============================================================================
// Data Types
// ============================================================================

/// Client process credentials for IPC
///
/// On Unix: obtained via `SO_PEERCRED` socket option
/// On Windows: obtained via `GetNamedPipeClientProcessId()` + OpenProcess
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerCredentials {
    /// User ID (Unix) or Token User SID (Windows)
    pub uid: u32,

    /// Group ID (Unix) or Primary Group SID (Windows)
    pub gid: u32,

    /// Client process ID
    pub pid: u32,

    /// Username (optional, for logging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl PeerCredentials {
    /// Checks if the client is a privileged user (root/Administrator)
    ///
    /// # Security Policy
    ///
    /// The daemon **MUST** reject connections from privileged users to:
    /// - Prevent a malicious process with root from controlling the daemon
    /// - Implement "Least Privilege": the daemon should not be controlled by root
    ///
    /// **Justification:** If the daemon accepts commands from root, an attacker who
    /// gains root could use the daemon as a persistence or escalation vector.
    pub fn is_privileged(&self) -> bool {
        self.uid == 0 // UID 0 = root (Unix) or Administrator (Windows)
    }

    /// Checks if the client has the same UID as the daemon
    ///
    /// # Security Policy
    ///
    /// Only the user running the daemon can connect. This prevents:
    /// - Attacks from other system users
    /// - Unauthorized use of daemon resources
    ///
    /// **Exception:** In development, a specific group may be allowed (e.g., `users`)
    pub fn matches_uid(&self, daemon_uid: u32) -> bool {
        self.uid == daemon_uid
    }
}

// ============================================================================
// Traits
// ============================================================================

/// Trait for authenticating IPC connections
///
/// Implemented by:
/// - `UnixIpcAuthenticator` (Unix: uses `SO_PEERCRED`)
/// - `WindowsIpcAuthenticator` (Windows: uses named pipe credentials)
/// - `MockIpcAuthenticator` (Tests: allows configuring behavior)
///
/// # Security Contract
///
/// Implementations **MUST**:
/// 1. Obtain peer credentials using OS mechanisms
/// 2. Reject connections from UID 0 (root/Administrator)
/// 3. Reject connections from UIDs different from the daemon
/// 4. Log all rejections with `warn!` level or higher
/// 5. Return detailed `IpcAuthError` (include UID in message)
///
/// # Example
///
/// ```rust,ignore
/// let auth = UnixIpcAuthenticator::new();
/// let stream = accept_connection().await?;
///
/// match auth.authenticate_peer(&stream) {
///     Ok(creds) => {
///         tracing::info!("IPC client authenticated: UID={}, PID={}", creds.uid, creds.pid);
///         // Process client commands
///     }
///     Err(IpcAuthError::PrivilegedUserRejected { uid }) => {
///         tracing::warn!("Rejected IPC connection from privileged user (UID {})", uid);
///         // Close connection
///     }
///     Err(e) => {
///         tracing::error!("IPC authentication failed: {}", e);
///         // Close connection
///     }
/// }
/// ```
pub trait IpcAuthenticator: Send + Sync {
    /// Authenticates an IPC connection by obtaining peer credentials
    ///
    /// # Errors
    ///
    /// - `IpcAuthError::CredentialsUnavailable` - Platform does not support credentials
    /// - `IpcAuthError::PrivilegedUserRejected` - Client is root/Administrator
    /// - `IpcAuthError::UnauthorizedUser` - Client UID does not match daemon
    /// - `IpcAuthError::OsError` - Operating system error
    ///
    /// # Security
    ///
    /// This function **MUST NOT** throw exceptions, always return Result.
    /// Authentication errors must be logged internally.
    fn authenticate_peer(&self, connection: &dyn IpcConnection) -> Result<PeerCredentials>;

    /// Gets the daemon UID (for comparison)
    ///
    /// On Unix: `libc::getuid()`
    /// On Windows: Current user token SID
    fn get_daemon_uid(&self) -> u32;
}

/// Trait for IPC connection abstraction (enables testing)
///
/// Implemented by:
/// - `tokio::net::UnixStream` (Unix)
/// - `tokio::net::windows::NamedPipeServer` (Windows)
/// - `MockIpcConnection` (Tests)
pub trait IpcConnection: Send + Sync {
    /// Gets the native file descriptor or handle of the connection
    ///
    /// Needed to call `getsockopt(SO_PEERCRED)` on Unix
    #[cfg(unix)]
    fn as_raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        None
    }

    /// Gets the Windows handle (for named pipes)
    #[cfg(windows)]
    fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
        None
    }
}

// ============================================================================
// Security Policy Constants
// ============================================================================

/// UID considerado privilegiado (root/Administrator)
pub const PRIVILEGED_UID: u32 = 0;

/// Nivel de logging para autenticación exitosa
pub const AUTH_SUCCESS_LOG_LEVEL: &str = "info";

/// Nivel de logging para autenticación fallida
pub const AUTH_FAILURE_LOG_LEVEL: &str = "warn";
