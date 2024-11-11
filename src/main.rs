use std::error::Error;
use std::process::exit;
use std::{convert::Infallible, net::SocketAddr};

use chrono::Utc;
use futures::stream::{self, StreamExt};
use hmac_sha1::hmac_sha1;
use http_body_util::{combinators::BoxBody, BodyExt, BodyStream, Empty, Full, StreamBody};
use hyper::{
    body::{Body, Bytes, Frame, Incoming},
    header::HeaderValue,
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};
//use hyper::service::{make_service_fn, service_fn};
//use hyper::{body, Body, Client, Request, Response, Server, StatusCode};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::net::TcpListener;

// type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

// resource="/${bucket}/${file}"
// content_type="application/octet-stream"
// date=`date -R --utc`
// _signature="PUT\n\n${content_type}\n${date}\n${resource}"
// signature=`echo -en ${_signature} | openssl sha1 -hmac ${s3_secret} -binary | base64`

// curl -X PUT -T "${file}" \
//           -H "Host: ${host}" \
//           -H "Date: ${date}" \
//           -H "Content-Type: ${content_type}" \
//           -H "Authorization: AWS ${s3_key}:${signature}" \
//           https://${host}${resource}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn proxy_handler(
    mut request: Request<Incoming>,
) -> Result<Response<Incoming>, Box<dyn Error>> {
    //let mut res = Response::new(Body::empty());

    //let header_access_key = request.headers_mut().remove("Access-Key");
    let s3_host = request
        .headers_mut()
        .remove("S3-Host")
        .ok_or("400 Missing required header 'S3-Host'!")?
        .to_str()
        .map_err(|_| "400 Invalid characters in header 'S3-Host'!")?
        .to_owned();
    let access_key = request
        .headers_mut()
        .remove("Access-Key")
        .ok_or("400 Missing required header 'Access-Key'!")?
        .to_str()
        .map_err(|_| "400 Invalid characters in header 'Access-Key'!")?
        .to_owned();
    let secret_key = request
        .headers_mut()
        .remove("Secret-Key")
        .ok_or("400 Missing required header 'Secret-Key'!")?
        .to_str()
        .map_err(|_| "400 Invalid characters in header 'Secret-Key'!")?
        .to_owned();
    let request_encoding = request
        .headers_mut()
        .remove("Request-Encoding")
        .unwrap_or("".parse()?)
        .to_str()
        .map_err(|_| "400 Invalid characters in header 'Request-Encoding'!")?
        .to_owned();

    let content_type = request
        .headers_mut()
        .entry("content-type")
        .or_insert("application/octet_stream".parse()?)
        .to_str()
        .map_err(|_| "400 Invalid characters in header 'Content-Type'!")?
        .to_owned();
    request.headers_mut().insert("host", s3_host.parse()?);
    let date = Utc::now().format("%a, %d %b %Y %T %z").to_string();
    request.headers_mut().insert("Date", date.parse()?);
    //request.headers_mut().insert("Date", HeaderValue::from_str(&date).unwrap());
    let signature = format!(
        "{}\n\n{}\n{}\n{}",
        request.method(),
        content_type,
        date,
        request.uri().path()
    );
    //let mut mac = Hmac::<Sha1>::new_from_slice(secret_key.as_bytes());
    //mac.update(signature.as_bytes());
    let signature_hash = hmac_sha1(secret_key.as_bytes(), signature.as_bytes());
    println!("{:?}", signature);
    println!("{}", base64::encode(signature_hash));

    // let authorization = format!("AWS {}:{}", String::from_utf8_lossy(access_key.as_bytes()), base64::encode(signature_hash));
    let authorization = format!("AWS {}:{}", access_key, base64::encode(signature_hash));
    request
        .headers_mut()
        .insert("Authorization", authorization.parse()?);
    //request.

    // let url = format!("{}{}", String::from_utf8_lossy(s3_host.as_bytes()), request.uri().path());
    let url = format!("https://{}{}", s3_host, request.uri().path());
    println!("{}", url);
    *request.uri_mut() = url.parse()?;

    let https = HttpsConnector::new();
    let client = Client::builder(TokioExecutor::new()).build::<_, Incoming>(https);
    //let stream = request.into_parts()
    //let request = request.body_mut() = Body::wrap_stream(Gz::new(
    //println!("{:?}", request);
    let response = client.request(request).await;

    println!("{:?}", response);

    Ok(response?)
    //Ok(Response::new(Body::from("Hello World!")))
    //Ok(Response::new(request.into_body()))
}

// fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
//     Full::new(chunk.into())
//         .map_err(|never| match never {})
//         .boxed()
// }

async fn proxy_handler_wrapper(
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match proxy_handler(request).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            if parts.status.is_client_error() || parts.status.is_server_error() {
                // println!("{:?}", body);
                let prefix = "Upstream: ";
                let suffix = "\r\n";
                //let (parts, body) = response.into_parts();
                //let stream = Body::from(prefix).chain(body).chain(Body::from(suffix));
                let stream = BodyStream::new(full(prefix));
                //let stream = Full::new(prefix.into()).into_data_stream();
                //let stream2 = body.into_data_stream();
                let stream2 = BodyStream::new(body);
                //let stream3 = Full::new(suffix.into()).into_data_stream();
                let stream = stream.chain(stream2);
                //response = Response::from_parts(parts, Body::wrap_stream(stream));
                let body = BoxBody::new(StreamBody::new(stream));

                // Update Content-Length header to factor in added prefix and suffix
                if let Some(length) = parts.headers.get("Content-Length") {
                    let mut length = length.to_str().unwrap_or("").parse::<usize>().unwrap_or(0);
                    if length > 0 {
                        length += prefix.len() + suffix.len();
                        parts
                            .headers
                            .insert("Content-Length", HeaderValue::from(length));
                    }
                }
                Ok(Response::from_parts(parts, body))
            } else {
                Ok(Response::from_parts(parts, body.boxed()))
            }
            //let length = response
            //response.headers_mut().header("Content-Length", res
        }
        Err(error) => {
            println!("Error: {}", error);
            let status: StatusCode = error.to_string()[0..3]
                .parse()
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let response = Response::builder()
                .status(status)
                .body(full(format!("S3-Proxy: {}\n", error)).boxed())
                .unwrap();
            Ok(response)
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // For every connection, we must make a `Service` to handle all
    // incoming HTTP requests on said connection.
    /*     let make_svc = make_service_fn(|_conn| {
        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        async { Ok::<_, Infallible>(service_fn(proxy_handler_wrapper)) }
    }); */

    let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();

    //let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    /*     let mut status: i32 = 0;
    let graceful = server.with_graceful_shutdown(shutdown_signal(&mut status));
    if let Err(e) = graceful.await {
        eprintln!("server error: {}", e);
    } */
    // println!("{:?}", graceful);
    // server.await?;

    let listener = TcpListener::bind(addr).await?;
    loop {
        let (tcp, _) = listener.accept().await?;
        let io = TokioIo::new(tcp);

        tokio::task::spawn(async move {
            // Handle the connection from the client using HTTP1 and pass any
            // HTTP requests received on that connection to the `hello` function
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, service_fn(proxy_handler_wrapper))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
    //exit(status);
    //Ok(())
}
