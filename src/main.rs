use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;

use async_compression::tokio::bufread::GzipDecoder;
use async_compression::tokio::bufread::GzipEncoder;
use base64::prelude::*;
use chrono::Utc;
use dns_lookup::lookup_addr;
use futures::stream::StreamExt;
use futures::TryStreamExt;
use hmac_sha1::hmac_sha1;
use http_body_util::{combinators::BoxBody, BodyExt, BodyStream, Full, StreamBody};
use hyper::{
    body::{Bytes, Frame, Incoming},
    header::InvalidHeaderValue,
    http::uri::InvalidUri,
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, Error as HyperUtilError},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use lazy_static::lazy_static;
use prometheus_exporter::prometheus::register_int_counter_vec;
use prometheus_exporter::prometheus::IntCounterVec;
use tokio::net::TcpListener;
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::{error, info};
use tracing_logfmt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Registry;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Hyper error: {0}")]
    HyperError(#[from] hyper::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] hyper::http::Error),

    #[error("Invalid header value: {0}")]
    InvalidHeaderValueError(#[from] InvalidHeaderValue),

    #[error("Invalid URI: {0}")]
    InvalidUriError(#[from] InvalidUri),

    #[error("Hyper util error: {0}")]
    HyperUtilError(#[from] HyperUtilError),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Tracing subscriber initialization error: {0}")]
    TracingInitError(#[from] tracing_subscriber::util::TryInitError),

    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("Boxed error: {0}")]
    BoxedError(#[from] Box<dyn Error + Send + Sync>),
}

impl ProxyError {
    pub fn new<S: Into<String>>(message: S) -> Self {
        ProxyError::GenericError(message.into())
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, ProxyError> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn proxy_handler(
    mut request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, ProxyError>>, ProxyError> {
    let s3_host = request
        .headers_mut()
        .remove("S3-Host")
        .ok_or_else(|| ProxyError::new("400 Missing required header 'S3-Host'!"))?
        .to_str()
        .map_err(|_| ProxyError::new("400 Invalid characters in header 'S3-Host'!"))?
        .to_owned();
    let access_key = request
        .headers_mut()
        .remove("Access-Key")
        .ok_or_else(|| ProxyError::new("400 Missing required header 'Access-Key'!"))?
        .to_str()
        .map_err(|_| ProxyError::new("400 Invalid characters in header 'Access-Key'!"))?
        .to_owned();
    let secret_key = request
        .headers_mut()
        .remove("Secret-Key")
        .ok_or_else(|| ProxyError::new("400 Missing required header 'Secret-Key'!"))?
        .to_str()
        .map_err(|_| ProxyError::new("400 Invalid characters in header 'Secret-Key'!"))?
        .to_owned();
    let compress_file = request
        .headers_mut()
        .remove("Compress-File")
        .unwrap_or_else(|| "".parse().unwrap())
        .to_str()
        .map_err(|_| ProxyError::new("400 Invalid characters in header 'Compress-File'!"))?
        .to_owned();
    let decompress_file = request
        .headers_mut()
        .remove("Decompress-File")
        .unwrap_or_else(|| "".parse().unwrap())
        .to_str()
        .map_err(|_| ProxyError::new("400 Invalid characters in header 'Decompress-File'!"))?
        .to_owned();
    let content_type = request
        .headers_mut()
        .entry("content-type")
        .or_insert_with(|| "application/octet_stream".parse().unwrap())
        .to_str()
        .map_err(|_| ProxyError::new("400 Invalid characters in header 'Content-Type'!"))?
        .to_owned();

    request.headers_mut().insert("host", s3_host.parse()?);

    let date = Utc::now().format("%a, %d %b %Y %T %z").to_string();
    request.headers_mut().insert("Date", date.parse()?);

    let signature = format!(
        "{}\n\n{}\n{}\n{}",
        request.method(),
        content_type,
        date,
        request.uri().path()
    );
    let signature_hash = hmac_sha1(secret_key.as_bytes(), signature.as_bytes());

    let authorization = format!(
        "AWS {}:{}",
        access_key,
        BASE64_STANDARD.encode(signature_hash)
    );
    request
        .headers_mut()
        .insert("Authorization", authorization.parse()?);

    let url = format!("https://{}{}", s3_host, request.uri().path());
    *request.uri_mut() = url.parse()?;

    let https = HttpsConnector::new();
    let response = if request.method() == "PUT" && compress_file == "gzip" {
        let (mut parts, body) = request.into_parts();
        parts.headers.remove("Content-Length");
        let stream = body
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .into_data_stream();
        let stream_reader = StreamReader::new(stream);
        let encoder = GzipEncoder::new(stream_reader);
        let stream = ReaderStream::new(encoder).map_ok(Frame::data);
        let body = StreamBody::new(stream);
        let request = Request::from_parts(parts, BodyExt::boxed(body));
        let client = Client::builder(TokioExecutor::new()).build(https);
        let response = client.request(request).await?;
        let (parts, body) = response.into_parts();
        let response = Response::from_parts(parts, BodyExt::boxed(body.map_err(ProxyError::from)));
        response
    } else if request.method() == "GET" && decompress_file == "gzip" {
        let client = Client::builder(TokioExecutor::new()).build(https);
        let response = client.request(request).await?;
        let (mut parts, body) = response.into_parts();
        parts.headers.remove("Content-Length");
        let stream = body
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .into_data_stream();
        let stream_reader = StreamReader::new(stream);
        let decoder = GzipDecoder::new(stream_reader);
        let stream = ReaderStream::new(decoder)
            .map_ok(Frame::data)
            .map_err(ProxyError::from);
        let body = StreamBody::new(stream);
        let response = Response::from_parts(parts, BodyExt::boxed(body));
        response
    } else {
        let client = Client::builder(TokioExecutor::new()).build(https);
        let response = client.request(request).await?;
        let (parts, body) = response.into_parts();
        let response = Response::from_parts(parts, BodyExt::boxed(body.map_err(ProxyError::from)));
        response
    };

    Ok(response)
}

fn client_ip(request: &Request<Incoming>, addr: SocketAddr) -> IpAddr {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| addr.ip())
}

fn log_response<B>(
    client_ip: &IpAddr,
    method: &str,
    path: &str,
    reason: &str,
    response: &Response<B>,
) {
    let size = response
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|length| length.to_str().ok())
        .unwrap_or("-");
    let status = response.status().as_u16();

    let (service, namespace) = match lookup_addr(&client_ip) {
        Ok(name) if name.ends_with("svc.cluster.local") => {
            info!(client_ip = %client_ip, name = name, "Reverse DNS lookup succedded");
            let parts: Vec<_> = name.split('.').collect();
            (
                parts.get(1).map(|&s| s.to_string()).unwrap_or_default(),
                parts.get(2).map(|&s| s.to_string()).unwrap_or_default(),
            )
        }
        Ok(name) => {
            info!(client_ip = %client_ip, name = name, "Reverse DNS lookup doesn't end with svc.cluster.local");
            (String::new(), String::new())
        }
        Err(e) => {
            error!(client_ip = %client_ip, error = %e, "Reverse DNS lookup failed");
            (String::new(), String::new())
        }
    };

    REQUEST_COUNTER
        .with_label_values(&[
            method,
            &status.to_string(),
            &service,
            &namespace,
            &service,
            &reason,
        ])
        .inc();

    // let span = Span::current();
    // span.record("status", status);
    // span.record("size", size);

    info!(
        remote_addr = client_ip.to_string(),
        method = method,
        path = path,
        status = status,
        size = size,
    );
}

async fn proxy_handler_wrapper(
    mut request: Request<Incoming>,
    addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, ProxyError>>, ProxyError> {
    let client_ip = client_ip(&request, addr);
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let request_reason = request
        .headers_mut()
        .remove("Request-Reason")
        .unwrap_or_else(|| "".parse().unwrap())
        .to_str()
        .map_err(|_| ProxyError::new("400 Invalid characters in header 'Request-Reason'!"))?
        .to_owned();
    match proxy_handler(request).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            if parts.status.is_client_error() || parts.status.is_server_error() {
                parts.headers.remove("Content-Length");
                let prefix = "Upstream: ";
                let suffix = "\r\n";
                let stream = BodyStream::new(full(prefix))
                    .chain(BodyStream::new(body))
                    .chain(BodyStream::new(full(suffix)));
                let body = StreamBody::new(stream);
                let response = Response::from_parts(parts, BodyExt::boxed(body));
                log_response(&client_ip, &method, &path, &request_reason, &response);
                Ok(response)
            } else {
                let response = Response::from_parts(parts, body.boxed());
                log_response(&client_ip, &method, &path, &request_reason, &response);
                Ok(response)
            }
        }
        Err(error) => {
            error!(error = %error, "Proxy error occurred");
            let status: StatusCode = error.to_string()[0..3]
                .parse()
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let response = Response::builder()
                .status(status)
                .body(full(format!("S3-Proxy: {}\n", error)).boxed())
                .unwrap();
            log_response(&client_ip, &method, &path, &request_reason, &response);
            Ok(response)
        }
    }
}

lazy_static! {
    static ref REQUEST_COUNTER: IntCounterVec = register_int_counter_vec!("s3proxy_requests_total", "Number of HTTP requests", &["method", "code", "service", "namespace", "job", "reason"]).unwrap();
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Initialize logging with logfmt format and env-filter
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    Registry::default()
        .with(env_filter)
        .with(tracing_logfmt::Builder::new().with_target(false).layer())
        .try_init()?;

    prometheus_exporter::start("0.0.0.0:8081".parse()?)?;
    //let request_counter = register_counter_vec!("s3proxy_requests_total", "Number of HTTP requests", &["method", "code", "service", "namespace", "job", "instance"])?;

    info!(port = 8080, "Starting server");

    let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        let io = TokioIo::new(tcp);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, service_fn(move |req| proxy_handler_wrapper(req, addr)))
                .await
            {
                // Ignore "Transport endpoint is not connected" errors caused by curl on connection shutdown
                if let Some(io_err) = err.source().and_then(|e| e.downcast_ref::<std::io::Error>()) {
                    if io_err.kind() == std::io::ErrorKind::NotConnected && io_err.raw_os_error() == Some(107) {
                        return;
                    }
                }

                error!(error = ?err, "Error serving connection");
            }
        });
    }
}
