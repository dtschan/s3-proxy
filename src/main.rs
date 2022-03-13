use std::convert::Infallible;
use std::error::Error;
use std::process::exit;

use chrono::Utc;
use hmacsha1::hmac_sha1;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, Client, StatusCode};
use hyper_tls::HttpsConnector;
use signal_hook_tokio::Signals;
use signal_hook::consts::signal::*;
use futures::stream::StreamExt;

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

async fn proxy_handler(mut request: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
    //let mut res = Response::new(Body::empty());

    //let header_access_key = request.headers_mut().remove("Access-Key");
    let s3_host = request.headers_mut().remove("S3-Host").ok_or("400 Missing required header 'S3-Host'!")?.
        to_str().map_err(|_| "400 Invalid characters in header 'S3-Host'!")?.to_owned();
    let access_key = request.headers_mut().remove("Access-Key").ok_or("400 Missing required header 'Access-Key'!")?.
        to_str().map_err(|_| "400 Invalid characters in header 'Access-Key'!")?.to_owned();
    let secret_key = request.headers_mut().remove("Secret-Key").ok_or("400 Missing required header 'Secret-Key'!")?.
        to_str().map_err(|_| "400 Invalid characters in header 'Secret-Key'!")?.to_owned();

    let content_type = request.headers_mut().entry("content-type").or_insert("application/octet_stream".parse()?).
        to_str().map_err(|_| "400 Invalid characters in header 'Content-Type'!")?.to_owned();
    request.headers_mut().insert("host", s3_host.parse()?);
    let date = Utc::now().format("%a, %d %b %Y %T %z").to_string();
    request.headers_mut().insert("Date", date.parse()?);
    //request.headers_mut().insert("Date", HeaderValue::from_str(&date).unwrap());
    let signature = format!("{}\n\n{}\n{}\n{}",
                            request.method(),
                            content_type,
                            date,
                            request.uri().path());
    //let mut mac = Hmac::<Sha1>::new_from_slice(secret_key.as_bytes());
    //mac.update(signature.as_bytes());
    let signature_hash = hmac_sha1(secret_key.as_bytes(), signature.as_bytes());
    println!("{:?}", signature);
    println!("{}", base64::encode(signature_hash));

    // let authorization = format!("AWS {}:{}", String::from_utf8_lossy(access_key.as_bytes()), base64::encode(signature_hash));
    let authorization = format!("AWS {}:{}", access_key, base64::encode(signature_hash));
    request.headers_mut().insert("Authorization", authorization.parse()?);
    //request.

    // let url = format!("{}{}", String::from_utf8_lossy(s3_host.as_bytes()), request.uri().path());
    let url = format!("https://{}{}", s3_host, request.uri().path());
    println!("{}", url);
    *request.uri_mut() = url.parse()?;

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    println!("{:?}", request);
    let response = client.request(request).await;

    println!("{:?}", response);

    Ok(response?)
    //Ok(Response::new(Body::from("Hello World!")))
    //Ok(Response::new(request.into_body()))

}

async fn proxy_handler_wrapper(request: Request<Body>) -> Result<Response<Body>, Infallible> {
  match proxy_handler(request).await {
    Ok(value) => Ok(value),
    Err(value) => {
        println!("{}", value);
        let status: StatusCode = value.to_string()[0..3].parse().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Ok(Response::builder().status(status).body(Body::from(value.to_string() + "\n")).unwrap())
    }
  }
}

async fn shutdown_signal(status: &mut i32) {
    let mut signals = Signals::new(&[SIGTERM, SIGINT, SIGQUIT]).unwrap();
    let handle = signals.handle();

    *status = signals.next().await.unwrap() + 128;
    //println!("\n{}", signal);

    handle.close();

    //Ok(())
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // For every connection, we must make a `Service` to handle all
    // incoming HTTP requests on said connection.
    let make_svc = make_service_fn(|_conn| {
        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        async { Ok::<_, Infallible>(service_fn(proxy_handler_wrapper)) }
    });

    let addr = ([0, 0, 0, 0], 8080).into();

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    let mut status: i32 = 0;
    let graceful = server.with_graceful_shutdown(shutdown_signal(&mut status));
    if let Err(e) = graceful.await {
        eprintln!("server error: {}", e);
    }
    // println!("{:?}", graceful);
    // server.await?;

    exit(status);
    //Ok(())
}
