// Based on sample from:
// https://github.com/actix/examples/tree/master/http-proxy

use std::{fs, process};
use clap::{Parser, CommandFactory};
use actix_web::{error, middleware, web, App, HttpServer, Error, HttpRequest, HttpResponse};
use awc::Client;
use awc::http::StatusCode;
use url::Url;

#[derive(Parser)]
#[clap(name = "multiproxy")]
#[clap(author = "Ryan Morlok <ryan.morlok@morlok.com>")]
#[clap(version)]
#[clap(about = "Proxies requests to a configurable set of fallback hosts", long_about = None)]
struct Cli {
    #[clap(parse(from_os_str), long = "pemPath")]
    pem_path: Option<std::path::PathBuf>,

    #[clap(parse(from_os_str), long = "keyPath")]
    key_path: Option<std::path::PathBuf>,

    #[clap(long = "protocol", default_value_t = String::from("http"))]
    protocol: String,

    #[clap(long = "bindIp", default_value_t = String::from("0.0.0.0"))]
    bind_ip: String,

    #[clap(value_parser = clap::value_parser!(u16).range(1..65535), long = "port", default_value_t = 8888)]
    port: u16,

    #[clap(value_parser,)]
    forward_base_urls: Vec<String>
}

async fn forward(
    req: HttpRequest,
    _payload: web::Payload,
    forward_base_urls: web::Data<Vec<Url>>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    for base_url in forward_base_urls.get_ref() {
        let base_path = base_url.path();
        let path = if base_path == "" || base_path == "/" {
            req.uri().path().to_string()
        } else if base_path.ends_with("/") {
            let req_path = req.uri().path();
            let skip_slash: String = req_path.chars().skip(1).take(req_path.len() - 1).collect();
            format!["{}{}", base_path, skip_slash]
        } else {
            format!["{}{}", base_path, req.uri().path()]
        };

        let mut new_url = base_url.clone();
        new_url.set_path(&path);
        new_url.set_query(req.uri().query());

        log::info!("requesting {}", new_url.to_string());

        // TODO: This forwarded implementation is incomplete as it only handles the unofficial
        // X-Forwarded-For header but not the official Forwarded one.
        let forwarded_req = client
            .request_from(new_url.as_str(), req.head())
            .no_decompress();
        /*let forwarded_req = match req.head().peer_addr {
            Some(addr) => forwarded_req.insert_header(("x-forwarded-for", format!("{}", addr.ip()))),
            None => forwarded_req,
        };*/

        let res = forwarded_req
            .send()
            .await.expect("test");
            //.map_err(error::ErrorInternalServerError)?;

        log::info!("Response status: {}", res.status());

        if res.status() < StatusCode::from_u16(400).unwrap() {
            let mut client_resp = HttpResponse::build(res.status());

            // Remove `Connection` as per
            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
            for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
                client_resp.insert_header((header_name.clone(), header_value.clone()));
            }

            return Ok(client_resp.streaming(res));
        }
    }

    Err(error::ErrorNotFound("Not Found"))
}

fn validate_path_param(path: &std::path::Path, name: &str) -> () {
    let metadata_result = fs::metadata(&path);
    if !metadata_result.is_ok() || !metadata_result.unwrap().is_file() {
        eprintln!("--{} '{}' is not a valid file", name, path.to_string_lossy());
        process::exit(1);
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let args: Cli = Cli::parse();

    if args.forward_base_urls.len() < 1 {
        eprintln!("Must specify at least one proxy base url\n");
        Cli::command().print_help().expect("failed to print usage");
        process::exit(1);
    }

    if args.key_path.is_some() != args.pem_path.is_some() {
        eprintln!("keyPath and pemPath must both be specified to enable TLS\n");
        Cli::command().print_help().expect("failed to print usage");
        process::exit(1);
    }

    if let Some(path) = args.key_path {
        validate_path_param(&path, "keyPath");
    }

    if let Some(path) = args.pem_path {
        validate_path_param(&path, "pemPath");
    }

    let mut forward_base_urls: Vec<Url> = vec![];

    for url_string in args.forward_base_urls {
        let url = match Url::parse(&url_string) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Invalid base url '{}' specified", url_string);
                process::exit(1);
            }
        };

        forward_base_urls.push(url);
    }

    log::info!(
        "starting HTTP server at http://{}:{}",
        &args.bind_ip,
        args.port
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(forward_base_urls.clone()))
            .app_data(web::Data::new(Client::default()))
            .wrap(middleware::Logger::default())
            .default_service(web::to(forward))
    })
        .bind((args.bind_ip, args.port))?
        .workers(2)
        .run()
        .await
}
