// TODO: Remove this line once diesel 1.4 is released
#![allow(proc_macro_derive_resolution_fallback)]

use super::schema::*;
use chrono::prelude::*;
use diesel::prelude::*;

use validator::Validate;

//use super::schema::user;

#[derive(Queryable, Debug, Deserialize, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub token: Option<String>,
}

#[derive(Deserialize, Insertable, Validate)]
#[table_name = "user"]
pub struct UserInsert {
    pub username: String,
    #[validate(email)]
    pub email: String,
}


#[derive(Queryable, Debug)]
pub struct PasswordReset {
    pub id: i32,
    pub user: i32,
    pub token: String,
    pub valid_until: NaiveDateTime,
}

#[derive(Insertable, Debug)]
#[table_name = "password_reset"]
pub struct PasswordResetInsert {
    pub token: String,
    pub userid: i32,
    pub valid_until: NaiveDateTime,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    /// Reset token generated by the reset_password route.
    pub token: String,
    /// The new password.
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest{
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginResult {
    pub token: String,
}

#[derive(Queryable, Serialize)]
pub struct Score {
    pub id: i32,
    pub userid: i32,
    pub mapid: i32,
    pub segment_times: String, // 0.22344,2233.34,..
    pub strafes: i32,
    pub jumps: i32,
    /// Seconds
    pub total_time: f32,
    pub max_speed: f32,
    pub average_speed: f32,
    pub seasonid: i32,
}

/// Score sent for the score listing of a map
#[derive(Serialize, Debug)]
pub struct ScoreDisplay {
    pub userid: i32,
    pub username: String,
    pub segment_times: String, // 0.22344,2233.34,..
    pub strafes: i32,
    pub jumps: i32,
    /// Seconds
    pub total_time: f32,
}

#[derive(Deserialize)]
pub struct ScoreInsertRequest {
    pub mapid: i32,
    /// Abs time when at segment end
    pub segment_times: Vec<f32>,
    pub strafes: i32,
    pub jumps: i32,
    /// Seconds
    pub total_time: f32,
    pub max_speed: f32,
    pub average_speed: f32,
}

#[derive(Insertable)]
#[table_name = "score"]
pub struct ScoreInsert {
    pub userid: i32,
    pub mapid: i32,
    pub segment_times: String,
    pub strafes: i32,
    pub jumps: i32,
    /// Seconds
    pub total_time: f32,
    pub max_speed: f32,
    pub average_speed: f32,
    pub season: i32,
}

#[derive(Queryable, Debug, Deserialize, Serialize)]
pub struct Map {
    pub id: i32,
    pub status: String,
    pub name: String,
    pub segment_count: i32,
    /// If the map gets removed, the path will be null.
    /// Maps that get outdated following updates will be deleted from the servers and the path will be null?
    /// not sure if this should be the case.
    pub path: Option<String>,
    pub mapper: i32,
    pub difficulty: String,
    pub categories: String,
    pub tags: String,
}

#[derive(Debug, Serialize)]
pub struct MapDisplay {
    pub id: i32,
    pub status: String,
    pub name: String,
    pub segment_count: i32,
    pub path: Option<String>,
    pub mapper: i32,
    pub mapper_name: String,
    pub difficulty: String,
    pub categories: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Queryable)]
pub struct Season {
    pub id: i32,
    pub display_name: String,
    pub friendly_name: String,
    pub ends_at: Option<NaiveDateTime>,
}
