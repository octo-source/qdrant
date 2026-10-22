use std::future::Future;
use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::rt::time::Instant;
use actix_web::web::Query;
use actix_web::{HttpResponse, Responder, get, post, web};
use actix_web_validator::Json;
use collection::operations::verification::new_unchecked_verification_pass;
use common::types::{DetailsLevel, TelemetryDetail};
use schemars::JsonSchema;
use segment::common::anonymize::Anonymize;
use serde::{Deserialize, Serialize};
use storage::content_manager::errors::StorageError;
use storage::dispatcher::Dispatcher;
use storage::rbac::AccessRequirements;
use tokio::sync::Mutex;

use crate::actix::auth::ActixAccess;
use crate::actix::helpers::{self, process_response_error};
use crate::common::health;
use crate::common::helpers::LocksOption;
use crate::common::metrics::MetricsData;
use crate::common::stacktrace::get_stack_trace;
use crate::common::telemetry::TelemetryCollector;
use crate::tracing;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct TelemetryParam {
    pub anonymize: Option<bool>,
    pub details_level: Option<usize>,
}

#[get("/telemetry")]
fn telemetry(
    telemetry_collector: web::Data<Mutex<TelemetryCollector>>,
    params: Query<TelemetryParam>,
    ActixAccess(access): ActixAccess,
) -> impl Future<Output = HttpResponse> {
    helpers::time(async move {
        let anonymize = params.anonymize.unwrap_or(false);
        let details_level = params
            .details_level
            .map_or(DetailsLevel::Level0, Into::into);
        let detail = TelemetryDetail {
            level: details_level,
            histograms: false,
        };
        let telemetry_collector = telemetry_collector.lock().await;
        let telemetry_data = telemetry_collector.prepare_data(&access, detail).await;
        let telemetry_data = if anonymize {
            telemetry_data.anonymize()
        } else {
            telemetry_data
        };
        Ok(telemetry_data)
    })
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MetricsParam {
    pub anonymize: Option<bool>,
}

#[get("/metrics")]
async fn metrics(
    telemetry_collector: web::Data<Mutex<TelemetryCollector>>,
    params: Query<MetricsParam>,
    ActixAccess(access): ActixAccess,
) -> HttpResponse {
    if let Err(err) = access.check_global_access(AccessRequirements::new()) {
        return process_response_error(err, Instant::now(), None);
    }

    let anonymize = params.anonymize.unwrap_or(false);
    let telemetry_collector = telemetry_collector.lock().await;
    let telemetry_data = telemetry_collector
        .prepare_data(
            &access,
            TelemetryDetail {
                level: DetailsLevel::Level3,
                histograms: true,
            },
        )
        .await;
    let telemetry_data = if anonymize {
        telemetry_data.anonymize()
    } else {
        telemetry_data
    };

    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(MetricsData::from(telemetry_data).format_metrics())
}

#[post("/locks")]
fn put_locks(
    dispatcher: web::Data<Dispatcher>,
    locks_option: Json<LocksOption>,
    ActixAccess(access): ActixAccess,
) -> impl Future<Output = HttpResponse> {
    // Not a collection level request.
    let pass = new_unchecked_verification_pass();

    helpers::time(async move {
        let toc = dispatcher.toc(&access, &pass);
        access.check_global_access(AccessRequirements::new().manage())?;
        let result = LocksOption {
            write: toc.is_write_locked(),
            error_message: toc.get_lock_error_message(),
        };
        toc.set_locks(locks_option.write, locks_option.error_message.clone());
        Ok(result)
    })
}

#[get("/locks")]
fn get_locks(
    dispatcher: web::Data<Dispatcher>,
    ActixAccess(access): ActixAccess,
) -> impl Future<Output = HttpResponse> {
    // Not a collection level request.
    let pass = new_unchecked_verification_pass();

    helpers::time(async move {
        access.check_global_access(AccessRequirements::new())?;
        let toc = dispatcher.toc(&access, &pass);
        let result = LocksOption {
            write: toc.is_write_locked(),
            error_message: toc.get_lock_error_message(),
        };
        Ok(result)
    })
}

#[get("/stacktrace")]
fn get_stacktrace(ActixAccess(access): ActixAccess) -> impl Future<Output = HttpResponse> {
    helpers::time(async move {
        access.check_global_access(AccessRequirements::new().manage())?;
        Ok(get_stack_trace())
    })
}

#[get("/healthz")]
async fn healthz() -> impl Responder {
    kubernetes_healthz()
}

#[get("/livez")]
async fn livez() -> impl Responder {
    kubernetes_healthz()
}

#[get("/readyz")]
async fn readyz(health_checker: web::Data<Option<Arc<health::HealthChecker>>>) -> impl Responder {
    let is_ready = match health_checker.as_ref() {
        Some(health_checker) => health_checker.check_ready().await,
        None => true,
    };

    let (status, body) = if is_ready {
        (StatusCode::OK, "all shards are ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "some shards are not ready")
    };

    HttpResponse::build(status)
        .content_type(ContentType::plaintext())
        .body(body)
}

/// Basic Kubernetes healthz endpoint
fn kubernetes_healthz() -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body("healthz check passed")
}

#[get("/logger")]
async fn get_logger_config(
    ActixAccess(access): ActixAccess,
    handle: web::Data<tracing::LoggerHandle>,
) -> impl Responder {
    let timing = Instant::now();

    let future = async {
        let _ = access.check_global_access(AccessRequirements::new())?;
        let config = handle.get_config().await;
        Ok(config)
    };

    helpers::process_response(future.await, timing, None)
}

#[post("/logger")]
async fn update_logger_config(
    ActixAccess(access): ActixAccess,
    handle: web::Data<tracing::LoggerHandle>,
    mut config: web::Json<tracing::LoggerConfig>,
) -> impl Responder {
    let timing = Instant::now();

    let future = async {
        let _ = access.check_global_access(AccessRequirements::new().manage())?;

        // Log file can only be set in Qdrant config file
        config.on_disk.log_file = None;

        handle
            .update_config(config.into_inner())
            .await
            .map_err(|err| StorageError::service_error(err.to_string()))?;

        Ok(true)
    };

    helpers::process_response(future.await, timing, None)
}

// Configure services
pub fn config_service_api(cfg: &mut web::ServiceConfig) {
    cfg.service(telemetry)
        .service(metrics)
        .service(put_locks)
        .service(get_locks)
        .service(get_stacktrace)
        .service(healthz)
        .service(livez)
        .service(readyz)
        .service(get_logger_config)
        .service(update_logger_config);
}

#[cfg(test)]
mod logger_security_tests {
    use actix_web::{App, HttpMessage, test};
    use serde_json::json;
    use storage::rbac::{Access, CollectionAccessList};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::reload;

    use super::*;

    #[actix_web::test]
    async fn logger_security_access_and_fixed_path() {
        let directory = tempfile::tempdir().unwrap();
        let configured_path = directory.path().join("configured.log");
        let requested_path = directory.path().join("untrusted.log");
        let mut config = tracing::LoggerConfig::default();
        config.on_disk.log_file = Some(configured_path.to_str().unwrap().to_owned());

        // Retain a subscriber without changing process-global logging.
        let (disk, disk_handle) =
            reload::Layer::new(tracing::on_disk::new_logger(&mut config.on_disk));
        let subscriber = tracing_subscriber::registry().with(disk);
        let (default, default_handle) =
            reload::Layer::new(tracing::default::new_logger(&config.default));
        let _subscriber = subscriber.with(default);
        let handle = tracing::LoggerHandle::new(config.clone(), default_handle, disk_handle);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(handle.clone()))
                .service(get_logger_config)
                .service(update_logger_config),
        )
        .await;

        for access in [
            Access::full_ro("test"),
            Access::Collection(CollectionAccessList(vec![])),
        ] {
            let request = test::TestRequest::post()
                .uri("/logger")
                .set_json(json!({"on_disk": {"enabled": true, "log_file": requested_path}}))
                .to_request();
            request.extensions_mut().insert(access);
            let response = test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(handle.get_config().await, config);
            assert!(!requested_path.exists());
            assert!(!configured_path.exists());
        }

        let request = test::TestRequest::get().uri("/logger").to_request();
        request
            .extensions_mut()
            .insert(Access::Collection(CollectionAccessList(vec![])));
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::FORBIDDEN
        );
        let request = test::TestRequest::get().uri("/logger").to_request();
        request.extensions_mut().insert(Access::full_ro("test"));
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK
        );

        let request = test::TestRequest::post()
            .uri("/logger")
            .set_json(json!({"on_disk": {"enabled": true, "log_file": requested_path}}))
            .to_request();
        request.extensions_mut().insert(Access::full("test"));
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK
        );
        let updated = handle.get_config().await;
        assert_eq!(updated.on_disk.log_file, config.on_disk.log_file);
        assert_eq!(updated.on_disk.enabled, Some(true));
        assert!(configured_path.exists());
        assert!(!requested_path.exists());

        let request = test::TestRequest::post()
            .uri("/logger")
            .set_json(json!({"log_level": "warn", "on_disk": {"enabled": false}}))
            .to_request();
        request.extensions_mut().insert(Access::full("test"));
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            handle.get_config().await.default.log_level.as_deref(),
            Some("warn")
        );
        assert_eq!(handle.get_config().await.on_disk.enabled, Some(false));
    }
}
