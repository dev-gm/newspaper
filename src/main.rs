use std::{ io, sync::Arc };
use actix_cors::Cors;
use actix_web::{ middleware, web, App, Error, HttpResponse, HttpServer };
use juniper::http::GraphQLRequest;

mod schema;

use crate::schema::{ create_schema, Schema };

async fn graphql(st: web::Data<Arc<Schema>>, data: web::Json<GraphQLRequest>) -> Result<HttpResponse, Error> {
    let user = web::block(move || {
        let res = data.execute_sync(&st, &());
        serde_json::to_string(&res)
    }).await?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(user))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let schema = Arc::new(create_schema());
    HttpServer::new(move || {
        App::new()
            .data(schema.clone())
            .wrap(middleware::Logger::default())
            .wrap(
                Cors::default()
                    .allowed_methods(vec!["POST", "GET"])
                    .supports_credentials()
                    .max_age(3600)
            )
            .service(web::resource("/").route(web::post().to(graphql)))
    })
    .bind("localhost:8080")?
    .run()
    .await
}
