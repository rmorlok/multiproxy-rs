// Based on sample from:
// https://github.com/actix/examples/tree/master/http-proxy
// and
// https://quinn-rs.github.io/quinn/quinn/certificate.html

use actix_web::{error, middleware, web, App, HttpServer, Error, HttpRequest, HttpResponse};
use awc::Client;
use awc::http::StatusCode;
use url::Url;
use clap::{Parser, CommandFactory};
use std::{fs, process};
use std::fs::File;
use std::io::BufReader;
use rustls::{ServerConfig};

#[derive(Parser)]
#[clap(name = "multiproxy")]
#[clap(author = "Ryan Morlok <ryan.morlok@morlok.com>")]
#[clap(version)]
#[clap(about = "Proxies requests to a configurable set of fallback hosts", long_about = None)]
pub struct Cli {
    #[clap(parse(from_os_str), long = "pemPath")]
    pub pem_path: Option<std::path::PathBuf>,

    #[clap(parse(from_os_str), long = "keyPath")]
    pub key_path: Option<std::path::PathBuf>,

    #[clap(long = "selfSignedTls")]
    pub self_signed_tls: bool,

    #[clap(long = "protocol", default_value_t = String::from("http"))]
    pub protocol: String,

    #[clap(long = "bindIp", default_value_t = String::from("0.0.0.0"))]
    pub bind_ip: String,

    #[clap(value_parser = clap::value_parser!(u16).range(1..65535), long = "port", default_value_t = 8888)]
    pub port: u16,

    #[clap(value_parser,)]
    pub forward_base_urls: Vec<String>
}

impl Cli {
    fn validate_path_param(path: &std::path::Path, name: &str) -> () {
        let metadata_result = fs::metadata(&path);
        if !metadata_result.is_ok() || !metadata_result.unwrap().is_file() {
            eprintln!("--{} '{}' is not a valid file", name, path.to_string_lossy());
            process::exit(1);
        }
    }

    pub fn validate_forward_base_urls(&self) -> () {
        if self.forward_base_urls.len() < 1 {
            eprintln!("Must specify at least one proxy base url\n");
            Cli::command().print_help().expect("failed to print usage");
            process::exit(1);
        }
    }

    pub fn validate_tls_params(&self) -> () {
        if self.self_signed_tls == true && (self.key_path.is_some() || self.pem_path.is_some()) {
            eprintln!("Cannot specify selfSignedTls in conjunction with keyPath and pemPath\n");
            Cli::command().print_help().expect("failed to print usage");
            process::exit(1);
        }

        if self.key_path.is_some() != self.pem_path.is_some() {
            eprintln!("keyPath and pemPath must both be specified to enable TLS\n");
            Cli::command().print_help().expect("failed to print usage");
            process::exit(1);
        }

        if let Some(path) = self.key_path.clone() {
            Cli::validate_path_param(&path, "keyPath");
        }

        if let Some(path) = self.pem_path.clone() {
            Cli::validate_path_param(&path, "pemPath");
        }
    }

    pub fn forward_base_urls(&self) -> Vec<Url> {
        let mut forward_base_urls: Vec<Url> = vec![];

        for url_string in &self.forward_base_urls {
            let url = match Url::parse(&url_string) {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("Invalid base url '{}' specified", url_string);
                    process::exit(1);
                }
            };

            forward_base_urls.push(url);
        }

        forward_base_urls
    }

    fn generate_self_signed_cert(&self) -> Result<(rustls::PrivateKey, rustls::Certificate), Box<dyn std::error::Error>>
    {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string(), self.bind_ip.to_string()])?;
        let key = rustls::PrivateKey(cert.serialize_private_key_der());
        Ok((key, rustls::Certificate(cert.serialize_der()?)))
    }

    fn read_certs_from_file(
        key_path: std::path::PathBuf,
        pem_path: std::path::PathBuf,
    ) -> Result<(rustls::PrivateKey, Vec<rustls::Certificate>), Box<dyn std::error::Error>> {
        let mut cert_chain_reader = BufReader::new(File::open(pem_path)?);
        let certs = rustls_pemfile::certs(&mut cert_chain_reader)?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        let mut key_reader = BufReader::new(File::open(key_path)?);

        // if the file starts with "BEGIN RSA PRIVATE KEY"
        // let mut key_vec = rustls_pemfile::rsa_private_keys(&mut reader)?;
        // if the file starts with "BEGIN PRIVATE KEY"
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;

        assert_eq!(keys.len(), 1);
        let key = rustls::PrivateKey(keys.remove(0));

        Ok((key, certs))
    }

    pub fn rustls_server_config(&self) -> Result<Option<ServerConfig>, Box<dyn std::error::Error>> {
        match (
            self.self_signed_tls,
            self.key_path.clone(),
            self.pem_path.clone()
        ) {
            (true, _, _) => {
                let (key, cert_chain) = self.generate_self_signed_cert()?;

                return Ok(Some(ServerConfig::builder()
                    .with_safe_default_cipher_suites()
                    .with_safe_default_kx_groups()
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert_chain], key)?));
            }
            (false, Some(key_path), Some(pem_path)) => {
                let (key, cert_chain) = Cli::read_certs_from_file(key_path, pem_path)?;

                return Ok(Some(ServerConfig::builder()
                    .with_safe_default_cipher_suites()
                    .with_safe_default_kx_groups()
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(cert_chain, key)?));
            }
            _ => Ok(None)
        }
    }
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let args: Cli = Cli::parse();

    args.validate_forward_base_urls();
    args.validate_tls_params();

    let forward_base_urls = args.forward_base_urls();

    let s = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(forward_base_urls.clone()))
            .app_data(web::Data::new(Client::default()))
            .wrap(middleware::Logger::default())
            .default_service(web::to(forward))
    });

    let s = match args.rustls_server_config() {
        Ok(Some(config)) => {
            log::info!(
                "starting HTTP server at https://{}:{}",
                &args.bind_ip,
                args.port
            );
            s.bind_rustls((args.bind_ip, args.port), config).unwrap()
        },
        Ok(None) => {
            log::info!(
                "starting HTTP server at https://{}:{}",
                &args.bind_ip,
                args.port
            );
            s.bind((args.bind_ip, args.port)).unwrap()
        },
        Err(error) => {
            eprintln!("Failed to configure for TLS: {}", error);
            process::exit(1);
        }
    };

    s
        .workers(2)
        .run()
        .await
}
