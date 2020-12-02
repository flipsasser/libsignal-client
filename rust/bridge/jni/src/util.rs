//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures::pin_mut;
use futures::task::noop_waker_ref;
use jni::objects::{JObject, JString, JThrowable, JValue};
use jni::sys::{jbyteArray, jint, jlong, jobject};
use jni::JNIEnv;
use libsignal_bridge::support_jni::*;
use libsignal_protocol_rust::SignalProtocolError;
use std::convert::TryFrom;
use std::future::Future;
use std::task::{self, Poll};

pub unsafe fn native_handle_cast<T>(
    handle: ObjectHandle,
) -> Result<&'static mut T, SignalJniError> {
    /*
    Should we try testing the encoded pointer for sanity here, beyond
    being null? For example verifying that lowest bits are zero,
    highest bits are zero, greater than 64K, etc?
    */
    if handle == 0 {
        return Err(SignalJniError::NullHandle);
    }

    Ok(&mut *(handle as *mut T))
}

pub unsafe fn native_handle_cast_optional<T>(
    handle: ObjectHandle,
) -> Result<Option<&'static mut T>, SignalJniError> {
    if handle == 0 {
        return Ok(None);
    }

    Ok(Some(&mut *(handle as *mut T)))
}

#[track_caller]
pub fn expect_ready<F: Future>(future: F) -> F::Output {
    pin_mut!(future);
    match future.poll(&mut task::Context::from_waker(noop_waker_ref())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("future was not ready"),
    }
}

pub fn to_jbytearray<T: AsRef<[u8]>>(
    env: &JNIEnv,
    data: Result<T, SignalProtocolError>,
) -> Result<jbyteArray, SignalJniError> {
    let data = data?;
    let data: &[u8] = data.as_ref();
    let out = env.new_byte_array(data.len() as i32)?;
    let buf: Vec<i8> = data.iter().map(|i| *i as i8).collect();
    env.set_byte_array_region(out, 0, buf.as_slice())?;
    Ok(out)
}

pub fn jint_to_u32(v: jint) -> Result<u32, SignalJniError> {
    if v < 0 {
        return Err(SignalJniError::IntegerOverflow(format!("{} to u32", v)));
    }
    Ok(v as u32)
}

pub fn jlong_to_u64(v: jlong) -> Result<u64, SignalJniError> {
    if v < 0 {
        return Err(SignalJniError::IntegerOverflow(format!("{} to u64", v)));
    }
    Ok(v as u64)
}

pub fn jint_to_u8(v: jint) -> Result<u8, SignalJniError> {
    match u8::try_from(v) {
        Err(_) => Err(SignalJniError::IntegerOverflow(format!("{} to u8", v))),
        Ok(v) => Ok(v),
    }
}

pub fn jint_from_u32(value: Result<u32, SignalProtocolError>) -> Result<jint, SignalJniError> {
    match value {
        Ok(value) => {
            let result = value as jint;
            if result as u32 != value {
                return Err(SignalJniError::IntegerOverflow(format!(
                    "{} to jint",
                    value
                )));
            }
            Ok(result)
        }
        Err(e) => Err(SignalJniError::Signal(e)),
    }
}

pub fn jlong_from_u64(value: Result<u64, SignalProtocolError>) -> Result<jlong, SignalJniError> {
    match value {
        Ok(value) => {
            let result = value as jlong;
            if result as u64 != value {
                return Err(SignalJniError::IntegerOverflow(format!(
                    "{} to jlong",
                    value
                )));
            }
            Ok(result)
        }
        Err(e) => Err(SignalJniError::Signal(e)),
    }
}

pub fn call_method_with_exception_as_null<'a>(
    env: &JNIEnv<'a>,
    obj: impl Into<JObject<'a>>,
    fn_name: &'static str,
    sig: &'static str,
    args: &[JValue<'_>],
    exception_to_treat_as_null: Option<&'static str>,
) -> Result<JValue<'a>, SignalJniError> {
    // Note that we are *not* unwrapping the result yet!
    // We need to check for exceptions *first*.
    let result = env.call_method(obj, fn_name, sig, args);

    fn exception_class_name(env: &JNIEnv, exn: JThrowable) -> Result<String, SignalJniError> {
        let class_type = env.call_method(exn, "getClass", "()Ljava/lang/Class;", &[])?;
        if let JValue::Object(class_type) = class_type {
            let class_name =
                env.call_method(class_type, "getCanonicalName", "()Ljava/lang/String;", &[])?;

            if let JValue::Object(class_name) = class_name {
                let class_name: String = env.get_string(JString::from(class_name))?.into();
                Ok(class_name)
            } else {
                Err(SignalJniError::UnexpectedJniResultType(
                    "getCanonicalName",
                    class_name.type_name(),
                ))
            }
        } else {
            Err(SignalJniError::UnexpectedJniResultType(
                "getClass",
                class_type.type_name(),
            ))
        }
    }

    if env.exception_check()? {
        let throwable = env.exception_occurred()?;
        env.exception_clear()?;

        if let Some(exception_to_treat_as_null) = exception_to_treat_as_null {
            if env.is_instance_of(throwable, exception_to_treat_as_null)? {
                return Ok(JValue::Object(JObject::null()));
            }
        }

        let getmessage_sig = "()Ljava/lang/String;";

        let exn_type = exception_class_name(env, throwable).ok();
        // Clear again in case we got an exception looking up the class name.
        env.exception_clear()?;

        if let Ok(jmessage) = env.call_method(throwable, "getMessage", getmessage_sig, &[]) {
            if let JValue::Object(o) = jmessage {
                let message: String = env.get_string(JString::from(o))?.into();
                return Err(SignalJniError::Signal(
                    SignalProtocolError::ApplicationCallbackThrewException(
                        fn_name, exn_type, message,
                    ),
                ));
            }
        }
        // Clear *again* in case we got an exception reading the message.
        env.exception_clear()?;

        return Err(SignalJniError::Signal(
            SignalProtocolError::ApplicationCallbackThrewException(
                fn_name,
                exn_type,
                "<exception did not implement getMessage>".to_string(),
            ),
        ));
    }

    Ok(result?)
}

pub fn call_method_checked<'a>(
    env: &JNIEnv<'a>,
    obj: impl Into<JObject<'a>>,
    fn_name: &'static str,
    sig: &'static str,
    args: &[JValue<'_>],
) -> Result<JValue<'a>, SignalJniError> {
    call_method_with_exception_as_null(env, obj, fn_name, sig, args, None)
}

pub fn check_jobject_type(
    env: &JNIEnv,
    obj: jobject,
    class_name: &'static str,
) -> Result<(), SignalJniError> {
    if obj.is_null() {
        return Err(SignalJniError::NullHandle);
    }

    let class = env.find_class(class_name)?;

    if !env.is_instance_of(obj, class)? {
        return Err(SignalJniError::BadJniParameter(class_name));
    }

    Ok(())
}

pub fn get_object_with_native_handle<T: 'static + Clone>(
    env: &JNIEnv,
    store_obj: jobject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
    exception_to_treat_as_none: Option<&'static str>,
) -> Result<Option<T>, SignalJniError> {
    let rvalue = call_method_with_exception_as_null(
        env,
        store_obj,
        callback_fn,
        callback_sig,
        &callback_args,
        exception_to_treat_as_none,
    )?;

    let obj = match rvalue {
        JValue::Object(o) => *o,
        _ => {
            return Err(SignalJniError::UnexpectedJniResultType(
                callback_fn,
                rvalue.type_name(),
            ))
        }
    };

    if obj.is_null() {
        return Ok(None);
    }

    let handle = call_method_checked(env, obj, "nativeHandle", "()J", &[])?;
    match handle {
        JValue::Long(handle) => {
            if handle == 0 {
                return Ok(None);
            }
            let object = unsafe { native_handle_cast::<T>(handle)? };
            Ok(Some(object.clone()))
        }
        _ => Err(SignalJniError::UnexpectedJniResultType(
            "nativeHandle",
            handle.type_name(),
        )),
    }
}

pub fn get_object_with_serialization(
    env: &JNIEnv,
    store_obj: jobject,
    callback_args: &[JValue],
    callback_sig: &'static str,
    callback_fn: &'static str,
) -> Result<Option<Vec<u8>>, SignalJniError> {
    let rvalue = call_method_checked(env, store_obj, callback_fn, callback_sig, &callback_args)?;

    let obj = match rvalue {
        JValue::Object(o) => *o,
        _ => {
            return Err(SignalJniError::UnexpectedJniResultType(
                callback_fn,
                rvalue.type_name(),
            ))
        }
    };

    if obj.is_null() {
        return Ok(None);
    }

    let bytes = call_method_checked(env, obj, "serialize", "()[B", &[])?;

    match bytes {
        JValue::Object(o) => Ok(Some(env.convert_byte_array(*o)?)),
        _ => Err(SignalJniError::UnexpectedJniResultType(
            "serialize",
            bytes.type_name(),
        )),
    }
}

pub fn jobject_from_serialized<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    serialized: &[u8],
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = "([B)V";
    let ctor_args = [JValue::from(to_jbytearray(env, Ok(serialized))?)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

pub fn jobject_from_native_handle<'a>(
    env: &'a JNIEnv,
    class_name: &str,
    boxed_handle: ObjectHandle,
) -> Result<JObject<'a>, SignalJniError> {
    let class_type = env.find_class(class_name)?;
    let ctor_sig = "(J)V";
    let ctor_args = [JValue::from(boxed_handle)];
    Ok(env.new_object(class_type, ctor_sig, &ctor_args)?)
}

#[macro_export]
macro_rules! jni_fn_get_new_boxed_obj {
    ( $nm:ident($rt:ty) from $typ:ty, $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            env: JNIEnv,
            _class: JClass,
            handle: ObjectHandle,
        ) -> ObjectHandle {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                box_object::<$rt>($body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_new_boxed_optional_obj {
    ( $nm:ident($rt:ty) from $typ:ty, $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            env: JNIEnv,
            _class: JClass,
            handle: ObjectHandle,
        ) -> ObjectHandle {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                let result: Option<$rt> = $body(obj)?;
                if let Some(result) = result {
                    box_object::<$rt>(Ok(result))
                } else {
                    Ok(0 as ObjectHandle)
                }
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_jint {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(env: JNIEnv, _class: JClass, handle: ObjectHandle) -> jint {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                jint_from_u32($body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_jlong {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(env: JNIEnv, _class: JClass, handle: ObjectHandle) -> jlong {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                jlong_from_u64($body(obj))
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_jboolean {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            env: JNIEnv,
            _class: JClass,
            handle: ObjectHandle,
        ) -> jboolean {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                let r: bool = $body(obj)?;
                Ok(r as jboolean)
            })
        }
    };
}

/*
Without the indirection of inner_get, rust can't deduce the Error type
if the provided lambda just returns Ok(something)
*/
#[macro_export]
macro_rules! jni_fn_get_jstring {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(env: JNIEnv, _class: JClass, handle: ObjectHandle) -> jstring {
            fn inner_get(t: &$typ) -> Result<String, SignalProtocolError> {
                $body(&t)
            }
            run_ffi_safe(&env, || {
                let obj: &mut $typ = native_handle_cast::<$typ>(handle)?;
                Ok(env.new_string(inner_get(&obj)?)?.into_inner())
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_optional_jstring {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(env: JNIEnv, _class: JClass, handle: ObjectHandle) -> jstring {
            run_ffi_safe(&env, || {
                let obj: &mut $typ = native_handle_cast::<$typ>(handle)?;
                match $body(&obj)? {
                    Some(s) => Ok(env.new_string(s)?.into_inner()),
                    None => Ok(std::ptr::null_mut()),
                }
            })
        }
    };
}

#[macro_export]
macro_rules! jni_fn_get_jbytearray {
    ( $nm:ident($typ:ty) using $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            env: JNIEnv,
            _class: JClass,
            handle: ObjectHandle,
        ) -> jbyteArray {
            run_ffi_safe(&env, || {
                let obj = native_handle_cast::<$typ>(handle)?;
                to_jbytearray(&env, $body(obj))
            })
        }
    };
}
