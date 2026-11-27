//! Windows named-pipe backend for the `local` provider.
//!
//! The pipe is created with a DACL that grants access to its owner only, and the first instance is
//! created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so another local user cannot connect to the
//! listener's instances or take over the first instance. Remote clients are rejected. The pipe
//! namespace is machine-global, so a dial also checks that the server process runs as the current
//! user before the stream is used.

// Win32 FFI for the pipe security descriptor and the server identity check; confined to this
// module.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::policy::ProviderId;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::error::RuntimeError;
use crate::provider::{DEFAULT_WRITE_TIMEOUT, IoPathStream, PathDialer, PathListener, PathStream};

const PIPE_PREFIX: &str = r"\\.\pipe\";
/// A protected DACL granting generic-all to the pipe owner and to nobody else.
const OWNER_ONLY_SDDL: &str = "D:P(A;;GA;;;OW)";
const BUSY_RETRY: Duration = Duration::from_millis(5);
const BUSY_BUDGET: Duration = Duration::from_secs(1);

/// Listener accepting local IPC streams on a named pipe with an owner-only DACL.
pub struct LocalListener {
    path: PathBuf,
    pending: Option<NamedPipeServer>,
    write_timeout: Duration,
}

impl LocalListener {
    /// Creates the first pipe instance at `path` (`\\.\pipe\<name>`), refusing a squatted name.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let path = path.as_ref().to_path_buf();
        require_pipe_path(&path)?;
        let pending = create_instance(&path, true)?;
        Ok(Self {
            path,
            pending: Some(pending),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        })
    }

    /// Overrides the write backpressure timeout applied to accepted streams.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Returns the pipe path bound by this listener.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl PathListener for LocalListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        if self.pending.is_none() {
            self.pending = Some(create_instance(&self.path, false)?);
        }
        // Connect through a shared reference so a cancelled accept leaves the instance in place.
        let pending = self.pending.as_ref().ok_or(RuntimeError::Closed)?;
        let connected = pending.connect().await;
        if let Err(err) = connected {
            // A real connect error leaves this instance unusable; recreate it on the next accept.
            self.pending = None;
            return Err(err.into());
        }
        let server = self.pending.take().ok_or(RuntimeError::Closed)?;
        // Create the next instance for the following client. If that fails, keep serving the
        // stream just accepted and let the next accept retry.
        match create_instance(&self.path, false) {
            Ok(next) => self.pending = Some(next),
            Err(err) => tracing::warn!(error = %err, "local pipe: next instance failed"),
        }
        Ok(Box::new(IoPathStream::new(
            ProviderId::Local,
            None,
            self.write_timeout,
            server,
        )))
    }

    fn local_endpoint(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

/// Dialer connecting to local named-pipe listeners.
#[derive(Debug, Clone)]
pub struct LocalDialer {
    write_timeout: Duration,
}

impl Default for LocalDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalDialer {
    /// Constructs a `LocalDialer` with [`DEFAULT_WRITE_TIMEOUT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Connects directly to `pipe_path` and verifies the server runs as the current user.
    pub async fn connect(
        &self,
        pipe_path: impl AsRef<Path>,
    ) -> Result<Box<dyn PathStream>, RuntimeError> {
        let path = pipe_path.as_ref();
        require_pipe_path(path)?;
        let deadline = tokio::time::Instant::now() + BUSY_BUDGET;
        let client = loop {
            match ClientOptions::new().open(path.as_os_str()) {
                Ok(client) => break client,
                // A pipe carries one connection per instance, so a dial that races the listener
                // re-arming waits briefly instead of failing.
                Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(RuntimeError::Timeout("local pipe is busy"));
                    }
                    tokio::time::sleep(BUSY_RETRY).await;
                }
                Err(err) => return Err(RuntimeError::Io(err)),
            }
        };
        verify_server_user(&client)?;
        Ok(Box::new(IoPathStream::new(
            ProviderId::Local,
            None,
            self.write_timeout,
            client,
        )))
    }
}

#[async_trait]
impl PathDialer for LocalDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Local
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let path = endpoint
            .strip_prefix("local:")
            .or_else(|| endpoint.strip_prefix("unix://"))
            .unwrap_or(endpoint);
        self.connect(path).await
    }
}

fn require_pipe_path(path: &Path) -> Result<(), RuntimeError> {
    let text = path.to_string_lossy();
    if !text.starts_with(PIPE_PREFIX) || text.len() == PIPE_PREFIX.len() {
        return Err(RuntimeError::Protocol(format!(
            "a local pipe path must start with {PIPE_PREFIX}"
        )));
    }
    Ok(())
}

fn create_instance(path: &Path, first: bool) -> Result<NamedPipeServer, RuntimeError> {
    let descriptor = owner_only_descriptor()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` names a live SECURITY_ATTRIBUTES whose descriptor stays valid until
    // `create_with_security_attributes_raw` returns.
    let created = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                path.as_os_str(),
                &mut attributes as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )
    };
    // SAFETY: `descriptor` was allocated by `owner_only_descriptor` and is not used again.
    unsafe { LocalFree(descriptor) };
    created.map_err(|err| {
        if first && err.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            RuntimeError::Storage("local pipe name is already in use".to_owned())
        } else {
            RuntimeError::Io(err)
        }
    })
}

fn owner_only_descriptor() -> Result<PSECURITY_DESCRIPTOR, RuntimeError> {
    let mut sddl: Vec<u16> = OWNER_ONLY_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated UTF-16 and outlives the call; `descriptor` is a valid
    // out-pointer for the returned allocation.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_mut_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(RuntimeError::Io(io::Error::last_os_error()));
    }
    Ok(descriptor)
}

fn verify_server_user(client: &NamedPipeClient) -> Result<(), RuntimeError> {
    let mut server_pid = 0u32;
    // SAFETY: `client` owns a live pipe handle and `server_pid` is a valid out-pointer.
    let ok =
        unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut server_pid) };
    if ok == 0 {
        return Err(unverified());
    }

    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that must not be closed.
    let own = token_user_buffer(unsafe { GetCurrentProcess() }).map_err(|_| unverified())?;
    // SAFETY: `server_pid` names a live pipe server process; a null handle is checked below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
    if process.is_null() {
        return Err(unverified());
    }
    let server = token_user_buffer(process);
    // SAFETY: `process` was opened above and is not used after this close.
    unsafe { CloseHandle(process) };
    let server = server.map_err(|_| unverified())?;

    // SAFETY: both buffers hold a TOKEN_USER whose `Sid` pointer is valid for the buffer's life.
    let equal = unsafe { EqualSid(token_user_sid(&server), token_user_sid(&own)) };
    if equal == 0 {
        return Err(unverified());
    }
    Ok(())
}

fn unverified() -> RuntimeError {
    RuntimeError::Protocol("local pipe server identity could not be verified".to_owned())
}

fn token_user_buffer(process: HANDLE) -> Result<Vec<usize>, RuntimeError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `process` is a live process handle; `token` is a valid out-pointer.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(RuntimeError::Io(io::Error::last_os_error()));
    }
    let buffer = token_user_buffer_of(token);
    // SAFETY: `token` was opened above and is not used after this close.
    unsafe { CloseHandle(token) };
    buffer
}

fn token_user_buffer_of(token: HANDLE) -> Result<Vec<usize>, RuntimeError> {
    let mut needed = 0u32;
    // SAFETY: a null buffer with length zero asks for the required size only.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(RuntimeError::Io(io::Error::last_os_error()));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: `buffer` is large enough for `needed` bytes and aligned for TOKEN_USER.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(RuntimeError::Io(io::Error::last_os_error()));
    }
    Ok(buffer)
}

fn token_user_sid(buffer: &[usize]) -> PSID {
    // SAFETY: `buffer` was filled with a TOKEN_USER by `GetTokenInformation`.
    unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn pipe_path(tag: &str) -> PathBuf {
        PathBuf::from(format!(
            r"\\.\pipe\tendril-test-{}-{}-{tag}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn pipe_round_trip_rearms_and_refuses_a_squatted_name() {
        let path = pipe_path("roundtrip");
        let mut listener = LocalListener::bind(&path).expect("bind");
        assert_eq!(listener.local_endpoint(), path.to_string_lossy());
        assert!(
            matches!(LocalListener::bind(&path), Err(RuntimeError::Storage(_))),
            "a second bind must refuse the existing pipe name"
        );

        let dialer = LocalDialer::new();
        let endpoint = path.to_string_lossy().into_owned();
        for round in 0..2 {
            let (accepted, dialed) = tokio::join!(listener.accept(), dialer.dial(&endpoint));
            let mut server = accepted.expect("accept");
            let mut client = dialed.expect("dial");

            client.send_chunk(b"hello-pipe").await.expect("send");
            let mut buf = [0u8; 32];
            let n = server.recv_chunk(&mut buf).await.expect("recv");
            assert_eq!(&buf[..n], b"hello-pipe", "round {round}");

            server.send_chunk(b"reply").await.expect("send reply");
            let n = client.recv_chunk(&mut buf).await.expect("recv reply");
            assert_eq!(&buf[..n], b"reply", "round {round}");
        }
    }

    #[tokio::test]
    async fn non_pipe_paths_are_refused() {
        assert!(matches!(
            LocalDialer::new().dial(r"\\server\pipe\tendril").await,
            Err(RuntimeError::Protocol(_))
        ));
        assert!(matches!(
            LocalListener::bind(r"C:\tendril.sock"),
            Err(RuntimeError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn dial_endpoint_routes_pipe_paths_to_the_local_provider() {
        let missing = pipe_path("missing");
        let endpoint = format!("local:{}", missing.to_string_lossy());
        let err = match crate::providers::dial_endpoint(&endpoint, None).await {
            Ok(_) => panic!("no listener at this pipe"),
            Err(err) => err,
        };
        assert!(matches!(err, RuntimeError::Io(_)), "{err:?}");
    }

    #[tokio::test]
    async fn pipe_dacl_grants_the_owner_only() {
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
            GetSecurityDescriptorControl, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
            SE_DACL_PROTECTED, WinCreatorOwnerRightsSid,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

        let path = pipe_path("dacl");
        let listener = LocalListener::bind(&path).expect("bind");
        let server = listener.pending.as_ref().expect("pending instance");

        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the pipe handle is live and every out-pointer is valid for the call.
        let rc = unsafe {
            GetSecurityInfo(
                server.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(
            rc,
            0,
            "GetSecurityInfo failed: {}",
            io::Error::last_os_error()
        );
        assert!(!owner.is_null(), "pipe has no owner");
        assert!(!dacl.is_null(), "pipe has no DACL");

        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `descriptor` is the live security descriptor returned above.
        let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        assert_ne!(ok, 0, "GetSecurityDescriptorControl failed");
        assert_ne!(
            control & SE_DACL_PROTECTED,
            0,
            "the pipe DACL must be protected"
        );

        // SAFETY: `dacl` is the live DACL returned above; the ACE follows the ACL header.
        let acl = unsafe { &*dacl };
        assert_eq!(acl.AceCount, 1, "the pipe DACL must hold exactly one ACE");
        // SAFETY: `AceCount` is one, so the first ACE is present and inside the ACL.
        let ace = unsafe { &*dacl.add(1).cast::<ACCESS_ALLOWED_ACE>() };
        assert_eq!(u32::from(ace.Header.AceType), ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace.Header.AceFlags & INHERITED_ACE as u8, 0);
        // `GA` is mapped to the file-object rights when the instance is created.
        assert_eq!(ace.Mask, FILE_ALL_ACCESS, "the ACE must grant full access");

        // `OW` is the Owner Rights SID (S-1-3-4), applied to the object owner at access check.
        let mut rights = [0u32; 17];
        let mut len = std::mem::size_of_val(&rights) as u32;
        // SAFETY: `rights` is large enough for any well-known SID and 4-byte aligned.
        let ok = unsafe {
            CreateWellKnownSid(
                WinCreatorOwnerRightsSid,
                ptr::null_mut(),
                rights.as_mut_ptr().cast(),
                &mut len,
            )
        };
        assert_ne!(ok, 0, "CreateWellKnownSid failed");
        let ace_sid = (&ace.SidStart as *const u32).cast_mut().cast::<c_void>();
        // SAFETY: both pointers name valid SIDs.
        assert_eq!(
            unsafe { EqualSid(ace_sid, rights.as_mut_ptr().cast()) },
            1,
            "the single ACE must grant the owner rights"
        );
        let own = token_user_buffer(unsafe { GetCurrentProcess() }).expect("own token");
        // SAFETY: both pointers name valid SIDs.
        assert_eq!(
            unsafe { EqualSid(owner, token_user_sid(&own)) },
            1,
            "the pipe must be owned by the current user"
        );
        // SAFETY: `descriptor` was allocated by `GetSecurityInfo` and is not used again.
        unsafe { LocalFree(descriptor) };
    }
}
