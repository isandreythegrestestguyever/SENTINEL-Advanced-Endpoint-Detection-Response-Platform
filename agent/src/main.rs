#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    use windows_service::service_dispatcher;
    service_dispatcher::start("SENTINEL", ffi_service_main)
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, sentinel_service_main);

#[cfg(windows)]
fn sentinel_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(error) = run_service() {
        sentinel_agent::log("error", &format!("service stopped: {error}"));
    }
}

#[cfg(windows)]
fn run_service() -> windows_service::Result<()> {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_from_handler = stop.clone();
    let status_handle =
        service_control_handler::register("SENTINEL", move |control| match control {
            ServiceControl::Stop => {
                stop_from_handler.store(true, Ordering::Release);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let result = (|| -> Result<(), String> {
        let config = sentinel_agent::Config::from_env()?;
        let agent = sentinel_agent::Agent::new(config)?;
        agent.run(stop.clone())
    })();
    let failed = result.is_err();
    if let Err(error) = result {
        sentinel_agent::log("error", &format!("service failed: {error}"));
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if failed { 1 } else { 0 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    sentinel_agent::log("error", "agent service requires Windows");
}
