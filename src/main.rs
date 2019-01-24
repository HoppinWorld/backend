#![feature(proc_macro_hygiene, decl_macro)]
// TODO: Remove this line once diesel 1.4 is released
#![allow(proc_macro_derive_resolution_fallback)]

#[macro_use]
extern crate diesel;
extern crate dotenv;
#[macro_use]
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
extern crate lettre;
extern crate lettre_email;
extern crate validator;
#[macro_use]
extern crate validator_derive;
extern crate mailgun_v3;

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
                change_password,
                submit_score,
                map_scores,
                user_score_for_map,
                list_maps,
                map_info,
                request_password_reset,
            ],
        )
        .attach(options)
        .launch();
}
