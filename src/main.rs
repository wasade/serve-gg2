// derived from
// https://github.com/tokio-rs/axum/blob/main/examples/sqlx-postgres/src/main.rs

use axum::{
    async_trait,
    extract::{Extension, FromRequest, RequestParts, Path, Form},
    http::StatusCode,
    routing::{get},
    Router,
    response::{Html},
};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::{Row, Error};
use sqlx::sqlite::SqliteRow;
use tracing::{info, instrument};
use std::{net::SocketAddr};
use serde::{Deserialize};
use clap::Parser;
use lazy_static::lazy_static;
use regex::Regex;
use axum_extra::routing::SpaRouter;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
   /// Name of the person to greet
   #[clap(short, long, value_parser)]
   db: String,
   #[clap(short, long, value_parser)]
   listen_on: String,
   #[clap(short, long, value_parser)]
   scheme: String,
   #[clap(short, long, value_parser)]
   host: String
}

fn get_server() -> String {
    let args = Args::parse();
    format!("{}://{}", args.scheme, args.host)
}


#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();
    let dbpath = args.db;
    let db_connection_str = format!("sqlite://{}", dbpath);
    info!(db_connection_str);
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_connection_str)
        .await
        .expect("can connect to database");

    let app = Router::new()
        .route(
            "/",
            get(home),
        ).route(
            "/by-id/:version/:id",
            get(by_id)
        ).route(
            "/search",
            get(search)
        ).route(
            "/clade-lookup/:id",
            get(clade_lookup)
        ).merge(SpaRouter::new("/static", "static")
        ).layer(Extension(pool));


    let addr: SocketAddr = args.listen_on.parse().expect("Unable to parse listen on address");

    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[instrument]
async fn home(
    Extension(pool): Extension<SqlitePool>,
) -> Result<Html<String>, (StatusCode, String)> {
    info!("home");
    let foo = "{\"foo\": \"go to home\"}".to_string();
    let page = get_template_page(&foo);
    Ok(page) 
}

lazy_static! {
    static ref ASV: Regex = Regex::new(r"[ATGC]{90}").unwrap();
    static ref NOT_SPECIES_WITH_RANK: Regex = Regex::new(r"^[dpcofg]__").unwrap();
    static ref MD5: Regex = Regex::new(r"[0-9a-f]{32}").unwrap();
    static ref WITH_RANK: Regex = Regex::new(r"^[dpcofgs]__").unwrap();
}

fn resolve_id(id: String) -> String {
    let id_as_str = id.as_str();

    if ASV.is_match(id_as_str) {
        let asv_md5 = md5::compute(id.as_bytes());
        return format!("{:x}", asv_md5);
    }

    if MD5.is_match(id_as_str) {
        return id;
    }
    
    if WITH_RANK.is_match(id_as_str) {
        return id;
    } else {
        "s__".to_owned() + id.clone().as_str()
    }
}

async fn query_id(pool: SqlitePool, version: String, id: String) -> Result<SqliteRow, Error> {
    let id_as_str = id.as_str();
    if WITH_RANK.is_match(id_as_str) && NOT_SPECIES_WITH_RANK.is_match(id_as_str) {
        sqlx::query(r#"select data   
                    from clade_lookup 
                    where id = $1 and version = $2"#)
            .bind(id)
            .bind(version.clone())
            .fetch_one(&pool)
            .await    
    } else {
        sqlx::query(r#"select data   
                    from entity 
                    where id = $1 and version = $2"#)
            .bind(id)
            .bind(version.clone())
            .fetch_one(&pool)
            .await 
    }  
}

async fn query_sequence(pool: SqlitePool, version: String, sequence: String) -> Result<SqliteRow, String> {
    let length = sequence.len();
    let allowed = vec![250, 200, 150, 125, 100, 90];

    for trim in allowed.iter() {
        if trim <= &length {
            let subseq = &sequence[..*trim];
            let subseq_id = resolve_id(subseq.to_owned());
            let res = query_id(pool.clone(), 
                               version.clone(), 
                               subseq_id).await;

            match res {
                Ok(result) => return Ok(result),
                Err(_) => continue
            }
            
        }
    }
    
    Err("{\"error\": \"The requested record was not found.\", \"type\": \"error\"}".to_string())
    
}

#[instrument]
async fn by_id(
    Path((version, id)): Path<(String, String)>,
    Extension(pool): Extension<SqlitePool>,
) -> Result<Html<String>, (StatusCode, String)> {
    info!(id);
    let resolved_id = resolve_id(id);
    let res = query_id(pool.clone(), 
                       version.clone(), 
                       resolved_id).await;
    
    let foo = match res {
        Ok(result) => result.get("data"),
        Err(_) => "{\"error\": \"The requested record was not found.\", \"type\": \"error\"}".to_string()
    };
    let page = get_template_page(&foo);
    Ok(page)    
}

#[derive(Deserialize, Debug)]
struct Search {
    id: String,
    version: String
}

#[instrument]
async fn search(
    Form(payload): Form<Search>,
    Extension(pool): Extension<SqlitePool>,
) -> Result<Html<String>, (StatusCode, String)> {
    info!(payload.id);

    let foo: String;
    if ASV.is_match(payload.id.as_str()) {
        let res = query_sequence(pool, payload.version, payload.id).await;
        foo = match res {
            Ok(result) => result.get("data"),
            Err(_) => "{\"error\": \"The requested record was not found.\", \"type\": \"error\"}".to_string()
        };
    } else {
        let resolved_id = resolve_id(payload.id);
        let res = query_id(pool.clone(), payload.version, resolved_id).await;

        foo = match res {
            Ok(result) => result.get("data"),
            Err(_) => "{\"error\": \"The requested record was not found.\", \"type\": \"error\"}".to_string()
        };
    }

    let page = get_template_page(&foo);
    Ok(page)
}

#[instrument]
async fn clade_lookup(
    Path(id): Path<String>,
    Extension(pool): Extension<SqlitePool>) -> Result<String, (StatusCode, String)> {
    info!(id);
    let res = query_clade_lookup(pool, id);
    Ok(res.await)
}

#[instrument]
async fn query_clade_lookup(pool: SqlitePool, id: String) -> String {
    let like = format!("%__{}%", id.to_owned());
    info!(like);
    let ids: Vec<String> = sqlx::query(r#"SELECT id 
                                          FROM clade_lookup 
                                          WHERE id LIKE $1 ORDER BY id LIMIT 100"#)
        .bind(like)  
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get("id"))
        .collect();
    format!(r#"["{}"]"#, ids.join(r#"",""#).to_owned())
}


struct DatabaseConnection(sqlx::pool::PoolConnection<sqlx::Sqlite>);

#[async_trait]
impl<B> FromRequest<B> for DatabaseConnection
where
    B: Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(pool) = Extension::<SqlitePool>::from_request(req)
            .await
            .map_err(internal_error)?;

        let conn = pool.acquire().await.map_err(internal_error)?;

        Ok(Self(conn))
    }
}


fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn get_template_page(payload: &String) -> axum::response::Html<String> {
    let mut page: String = include_str!("page.html").into();
    page = page.replace("{1:?}", payload).into();
    page.replace("{2:?}", &get_server()).into()
}
