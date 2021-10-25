use actix_cors::Cors;
use actix_web::{
    middleware,
    web,
    App,
    Error,
    HttpResponse,
    HttpServer,
};
use juniper::http::{
    graphiql::graphiql_source,
    GraphQLRequest,
};
use std::sync::Arc;
use std::io;

mod schema;

use crate::schema::{ Context, create_schema, Schema };

async fn graphiql() -> HttpResponse {
    let html = graphiql_source("http://127.0.0.1:8080/graphql", None);
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

async fn graphql(schema: web::Data<Arc<Schema>>, data: web::Json<GraphQLRequest>) -> Result<HttpResponse, Error> {
    let context = Context::new().await.unwrap();
    let user = web::block(move || {
        serde_json::to_string(&data.execute_sync(&schema, &context))
    }).await?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(user))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
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
            .service(web::resource("/graphql").route(web::post().to(graphql)))
            .service(web::resource("/graphiql").route(web::get().to(graphiql)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}