// Based on sample from:
// https://github.com/actix/examples/tree/master/http-proxy

use clap::Parser;
use actix_web::{error, middleware, web, App, HttpServer, Error, HttpRequest, HttpResponse};
use awc::Client;
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

    #[clap(value_parser)]
    forward_base_urls: Vec<String>
}

async fn forward(
    req: HttpRequest,
    payload: web::Payload,
    url: web::Data<Url>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    let mut new_url = url.get_ref().clone();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());

    // TODO: This forwarded implementation is incomplete as it only handles the unofficial
    // X-Forwarded-For header but not the official Forwarded one.
    let forwarded_req = client
        .request_from(new_url.as_str(), req.head())
        .no_decompress();
    let forwarded_req = match req.head().peer_addr {
        Some(addr) => forwarded_req.insert_header(("x-forwarded-for", format!("{}", addr.ip()))),
        None => forwarded_req,
    };

    let res = forwarded_req
        .send_stream(payload)
        .await
        .map_err(error::ErrorInternalServerError)?;

    let mut client_resp = HttpResponse::build(res.status());
    // Remove `Connection` as per
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.insert_header((header_name.clone(), header_value.clone()));
    }

    Ok(client_resp.streaming(res))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let args: Cli = Cli::parse();

    log::info!(
        "starting HTTP server at http://{}:{}",
        &args.bind_ip,
        args.port
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Client::default()))
            .app_data(web::Data::new(args.forward_base_urls.clone()))
            .wrap(middleware::Logger::default())
            .default_service(web::to(forward))
    })
        .bind((args.bind_ip, args.port))?
        .workers(2)
        .run()
        .await
}
