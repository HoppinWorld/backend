#![feature(plugin)]
#![plugin(rocket_codegen)]
// TODO: Remove this line once diesel 1.4 is released
#![allow(proc_macro_derive_resolution_fallback)]

#[macro_use]
extern crate diesel;
extern crate dotenv;
extern crate rocket;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate rocket_contrib;
extern crate rocket_cors;
extern crate serde_json;
extern crate uuid;
#[macro_use]
extern crate log;
extern crate chrono;
extern crate backend_utils;


use chrono::offset::Local;
use chrono::Duration;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use dotenv::dotenv;
use rocket::http::{Cookies, Status};
use rocket::request::{self, Form, FromRequest};
use rocket::response::content::Html;
use rocket::response::Redirect;
use rocket::Rocket;
use rocket::{Outcome, Request, State};
use rocket_contrib::Json;
use rocket_cors::{AllowedHeaders, AllowedOrigins, Cors};
use std::env;
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use rocket::http::Method;
use rocket::response::status;
use rocket::response::status::BadRequest;
use rocket::response::Responder;
use rocket::Response;
use uuid::Uuid;


pub use backend_utils::*;

mod schema;
mod model;
mod db;
mod endpoint;
pub use self::model::*;
pub use self::db::*;
pub use self::endpoint::*;






fn main() {
    let options = rocket_trajectory_restriction(None);
    rocket::ignite()
        .manage(create_conn())
        .mount(
            "/",
            routes![
                login,
                register,
                change_password
            ],
        )
        .attach(options)
        .launch();
}
