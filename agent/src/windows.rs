use std::{
    ffi::c_void,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use windows_sys::{
    Win32::{
        Foundation::{ERROR_SUCCESS, GetLastError},
        System::EventLog::{
            EVT_HANDLE, EvtClose, EvtCreateBookmark, EvtRender, EvtRenderBookmark,
            EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeActionError,
            EvtSubscribeStartAfterBookmark, EvtSubscribeToFutureEvents, EvtUpdateBookmark,
        },
    },
    core::PCWSTR,
};

use crate::{Channel, Config, Event, Spool, normalize_windows_event, parse_windows_event};

struct CallbackContext {
    channel: String,
    host_id: String,
    hostname: String,
    bookmark: EVT_HANDLE,
    spool: Arc<Mutex<Spool>>,
    stop: Arc<AtomicBool>,
    serial: Mutex<()>,
    failure: Mutex<Option<String>>,
    active_callbacks: AtomicUsize,
}

impl Drop for CallbackContext {
    fn drop(&mut self) {
        if self.bookmark != 0 {
            unsafe {
                EvtClose(self.bookmark);
            }
        }
    }
}

struct Subscription {
    handle: EVT_HANDLE,
    context: *const CallbackContext,
}

unsafe impl Send for Subscription {}

struct DeliveredEvent(EVT_HANDLE);

impl Drop for DeliveredEvent {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                EvtClose(self.0);
            }
        }
    }
}

struct CallbackCount(Arc<CallbackContext>);

impl Drop for CallbackCount {
    fn drop(&mut self) {
        self.0.active_callbacks.fetch_sub(1, Ordering::Release);
    }
}

pub fn collect(
    config: Config,
    spool: Arc<Mutex<Spool>>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut subscriptions = Vec::new();
    for channel in &config.channels {
        match subscribe(channel, &config, spool.clone(), stop.clone()) {
            Ok(subscription) => subscriptions.push(subscription),
            Err(error) => crate::log(
                "error",
                &format!("could not subscribe to {}: {error}", channel.name),
            ),
        }
    }
    if subscriptions.is_empty() {
        return Err("no configured Windows Event Log channel could be opened".into());
    }
    crate::log(
        "info",
        &format!("subscribed to {} event channel(s)", subscriptions.len()),
    );
    while !stop.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(200));
    }
    let mut collection_failure = None;
    for subscription in subscriptions {
        unsafe {
            EvtClose(subscription.handle);
        }
        while unsafe {
            (*subscription.context)
                .active_callbacks
                .load(Ordering::Acquire)
        } > 0
        {
            thread::sleep(Duration::from_millis(10));
        }
        let context = unsafe { Arc::from_raw(subscription.context) };
        if collection_failure.is_none() {
            if let Ok(failure) = context.failure.lock() {
                if let Some(error) = failure.as_ref() {
                    collection_failure = Some(error.clone());
                }
            }
        }
    }
    collection_failure.map_or(Ok(()), Err)
}

fn subscribe(
    channel: &Channel,
    config: &Config,
    spool: Arc<Mutex<Spool>>,
    stop: Arc<AtomicBool>,
) -> Result<Subscription, String> {
    let bookmark_xml = spool
        .lock()
        .map_err(|_| "spool lock poisoned".to_owned())?
        .bookmark(&channel.name)?;
    let bookmark_wide = bookmark_xml.as_deref().map(wide);
    let bookmark = unsafe {
        EvtCreateBookmark(
            bookmark_wide
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
        )
    };
    if bookmark == 0 {
        return Err(format!(
            "create bookmark: {}",
            std::io::Error::last_os_error()
        ));
    }
    let query_text = format!(
        "*[System[{}]]",
        channel
            .event_ids
            .iter()
            .map(|id| format!("EventID={id}"))
            .collect::<Vec<_>>()
            .join(" or ")
    );
    let channel_wide = wide(&channel.name);
    let query_wide = wide(&query_text);
    let context = Arc::new(CallbackContext {
        channel: channel.name.clone(),
        host_id: config.host_id.clone(),
        hostname: config.hostname.clone(),
        bookmark,
        spool,
        stop,
        serial: Mutex::new(()),
        failure: Mutex::new(None),
        active_callbacks: AtomicUsize::new(0),
    });
    let callback_context = Arc::into_raw(context);
    let flags = if bookmark_xml.is_some() {
        EvtSubscribeStartAfterBookmark
    } else {
        EvtSubscribeToFutureEvents
    };
    let subscription_bookmark = if bookmark_xml.is_some() { bookmark } else { 0 };
    let subscription = unsafe {
        EvtSubscribe(
            0,
            0,
            channel_wide.as_ptr(),
            query_wide.as_ptr(),
            subscription_bookmark,
            callback_context.cast::<c_void>(),
            Some(on_event),
            flags,
        )
    };
    if subscription == 0 {
        let error = unsafe { GetLastError() };
        unsafe {
            drop(Arc::from_raw(callback_context));
        }
        return Err(format!("EvtSubscribe failed with Windows error {error}"));
    }
    Ok(Subscription {
        handle: subscription,
        context: callback_context,
    })
}

unsafe extern "system" fn on_event(
    action: i32,
    user_context: *const c_void,
    event: EVT_HANDLE,
) -> u32 {
    if user_context.is_null() {
        return ERROR_SUCCESS;
    }
    let context_pointer = user_context.cast::<CallbackContext>();
    unsafe {
        Arc::increment_strong_count(context_pointer);
    }
    let context = unsafe { Arc::from_raw(context_pointer) };
    context.active_callbacks.fetch_add(1, Ordering::Acquire);
    let _callback_count = CallbackCount(context.clone());
    if action == EvtSubscribeActionError {
        crate::log(
            "error",
            &format!(
                "Windows Event Log subscription error on {}",
                context.channel
            ),
        );
        set_failure(
            &context,
            "Windows Event Log subscription reported an error".into(),
        );
        context.stop.store(true, Ordering::Release);
        return ERROR_SUCCESS;
    }
    if action != EvtSubscribeActionDeliver || event == 0 {
        return ERROR_SUCCESS;
    }
    let _event = DeliveredEvent(event);
    let _serial = match context.serial.lock() {
        Ok(lock) => lock,
        Err(_) => {
            set_failure(&context, "event callback lock was poisoned".into());
            context.stop.store(true, Ordering::Release);
            return ERROR_SUCCESS;
        }
    };
    let xml = match unsafe { render(event, EvtRenderEventXml) } {
        Ok(xml) => xml,
        Err(error) => {
            crate::log(
                "error",
                &format!("could not render event from {}: {error}", context.channel),
            );
            set_failure(&context, error);
            context.stop.store(true, Ordering::Release);
            return ERROR_SUCCESS;
        }
    };
    let raw = match crate::parse_windows_event(&xml) {
        Ok(raw) => raw,
        Err(error) => {
            crate::log(
                "error",
                &format!("could not parse event from {}: {error}", context.channel),
            );
            set_failure(&context, error);
            context.stop.store(true, Ordering::Release);
            return ERROR_SUCCESS;
        }
    };
    let normalized = normalize_windows_event(&raw, &context.host_id, &context.hostname);
    if let Err(error) = persist_event(&context, normalized.as_ref(), event) {
        crate::log(
            "error",
            &format!(
                "could not durably spool event from {}: {error}",
                context.channel
            ),
        );
        set_failure(&context, error);
        context.stop.store(true, Ordering::Release);
    }
    ERROR_SUCCESS
}

fn set_failure(context: &CallbackContext, error: String) {
    if let Ok(mut failure) = context.failure.lock() {
        if failure.is_none() {
            *failure = Some(format!("{}: {error}", context.channel));
        }
    }
}

fn persist_event(
    context: &CallbackContext,
    event: Option<&Event>,
    native_event: EVT_HANDLE,
) -> Result<(), String> {
    loop {
        if context.stop.load(Ordering::Acquire) {
            return Err("agent stopping".into());
        }
        let bookmark_xml = unsafe {
            if EvtUpdateBookmark(context.bookmark, native_event) == 0 {
                return Err(format!(
                    "update bookmark: {}",
                    std::io::Error::last_os_error()
                ));
            }
            render(context.bookmark, EvtRenderBookmark)?
        };
        let result = {
            let mut spool = context
                .spool
                .lock()
                .map_err(|_| "spool lock poisoned".to_owned())?;
            if let Some(event) = event {
                spool
                    .enqueue_with_bookmark(event, Some((&context.channel, &bookmark_xml)))
                    .map(|_| ())
            } else {
                spool.save_bookmark(&context.channel, &bookmark_xml)
            }
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.contains("spool is full") => {
                crate::log(
                    "warn",
                    "outbox is full; blocking event delivery until space is available",
                );
                thread::sleep(Duration::from_secs(1));
            }
            Err(error) => return Err(error),
        }
    }
}

unsafe fn render(handle: EVT_HANDLE, flags: u32) -> Result<String, String> {
    let mut bytes_needed = 0;
    let mut property_count = 0;
    unsafe {
        EvtRender(
            0,
            handle,
            flags,
            0,
            ptr::null_mut(),
            &mut bytes_needed,
            &mut property_count,
        );
    }
    if bytes_needed == 0 || bytes_needed > 1024 * 1024 {
        return Err("event render buffer is empty or exceeds 1 MiB".into());
    }
    let mut buffer = vec![0u64; (bytes_needed as usize).div_ceil(8)];
    let result = unsafe {
        EvtRender(
            0,
            handle,
            flags,
            bytes_needed,
            buffer.as_mut_ptr().cast(),
            &mut bytes_needed,
            &mut property_count,
        )
    };
    if result == 0 {
        return Err(format!(
            "EvtRender failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let wide = unsafe {
        std::slice::from_raw_parts(buffer.as_ptr().cast::<u16>(), bytes_needed as usize / 2)
    };
    let length = wide
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(wide.len());
    Ok(String::from_utf16_lossy(&wide[..length]))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
