use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::backtrace::Backtrace;

use async_compression::tokio::bufread::GzipEncoder;
use async_compression::tokio::bufread::GzipDecoder;
use base64::prelude::*;
use chrono::Utc;
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
use tokio::net::TcpListener;
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::{error, info, Span};
use tracing_logfmt;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug)]
pub struct ProxyError {
    inner: Box<dyn Error + Send + Sync>,
    backtrace: Backtrace,
}

impl ProxyError {
    fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            inner: error.into(),
            backtrace: Backtrace::capture(),
        }
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl Error for ProxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source()
    }
}

impl From<&str> for ProxyError {
    fn from(s: &str) -> Self {
        ProxyError::new(s.to_string())
    }
}

impl From<String> for ProxyError {
    fn from(s: String) -> Self {
        ProxyError::new(s)
    }
}

impl From<hyper::Error> for ProxyError {
    fn from(err: hyper::Error) -> Self {
        ProxyError::new(err)
    }
}

impl From<hyper::http::Error> for ProxyError {
    fn from(err: hyper::http::Error) -> Self {
        ProxyError::new(err)
    }
}

impl From<InvalidHeaderValue> for ProxyError {
    fn from(err: InvalidHeaderValue) -> Self {
        ProxyError::new(err)
    }
}

impl From<InvalidUri> for ProxyError {
    fn from(err: InvalidUri) -> Self {
        ProxyError::new(err)
    }
}

impl From<HyperUtilError> for ProxyError {
    fn from(err: HyperUtilError) -> Self {
        ProxyError::new(err)
    }
}

impl From<io::Error> for ProxyError {
    fn from(err: io::Error) -> Self {
        ProxyError::new(err)
    }
}

impl From<Box<dyn Error + Send + Sync>> for ProxyError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        ProxyError::new(err)
    }
}

impl From<tracing_subscriber::util::TryInitError> for ProxyError {
    fn from(err: tracing_subscriber::util::TryInitError) -> Self {
        ProxyError::new(err)
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
        let stream = ReaderStream::new(decoder).map_ok(Frame::data).map_err(ProxyError::from);
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

fn client_ip(request: &Request<Incoming>, addr: Option<SocketAddr>) -> String {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| {
            addr.map(|a| a.ip().to_string())
                .unwrap_or_else(|| "-".to_string())
        })
}

fn log_response<B>(client_ip: &str, method: &str, path: &str, response: &Response<B>) {
    let span = Span::current();
    let status = response.status().as_u16();
    span.record("status", status);
    
    let size = response
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|length| length.to_str().ok())
        .unwrap_or("-");
    span.record("size", size);
    
    info!(
        remote_addr = client_ip,
        method = method,
        path = path,
        status = status,
        size = size,
    );
}

async fn proxy_handler_wrapper(
    request: Request<Incoming>,
    addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, ProxyError>>, ProxyError> {
    let client_ip = client_ip(&request, Some(addr));
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
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
                log_response(&client_ip, &method, &path, &response);
                Ok(response)
            } else {
                let response = Response::from_parts(parts, body.boxed());
                log_response(&client_ip, &method, &path, &response);
                Ok(response)
            }
        }
        Err(error) => {
            error!(
                error = %error,
                backtrace = ?error.backtrace,
                "Proxy error occurred"
            );
            let status: StatusCode = error.to_string()[0..3]
                .parse()
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let response = Response::builder()
                .status(status)
                .body(full(format!("S3-Proxy: {}\n", error)).boxed())
                .unwrap();
            log_response(&client_ip, &method, &path, &response);
            Ok(response)
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), ProxyError> {
    // Initialize logging with logfmt format and env-filter
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    Registry::default()
        .with(env_filter)
        .with(tracing_logfmt::Builder::new()
            .with_target(false)
            .layer())
        .try_init()?;

    let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();

    info!(port = 8080, "Starting server");

    let listener = TcpListener::bind(addr).await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        let io = TokioIo::new(tcp);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(
                    io,
                    service_fn(move |req| proxy_handler_wrapper(req, addr)),
                )
                .await
            {
                error!(
                    error = ?err,
                    "Error serving connection"
                );
            }
        });
    }
}
