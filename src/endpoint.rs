use mailgun_v3::email::*;
use mailgun_v3::*;
use rocket::request::FromRequest;
use backend_utils::*;
use super::model::*;
use super::db::*;
use std::env;
use uuid::Uuid;
use rocket::http::Status;
use rocket_contrib::json::Json;
use rocket::{Outcome, Request};
//use lettre_email::EmailBuilder;
//use lettre::{ClientSecurity, EmailAddress, Envelope, SendableEmail, SmtpClient, Transport, SmtpTransport, SendmailTransport};
use validator::Validate;

pub struct UserLogged {
    pub user: User,
}

//impl<'a, 'r, R: Sized, UT: FilterDsl<SelectStatement<UT, DefaultSelectClause, NoDistinctClause, WhereClause<diesel::expression::operators::Eq<T, Bound<Text, &String>>>>>+Sized, T: ExpressionMethods+Sized> FromRequest<'a, 'r> for UserLogged<R, UT, T> {
impl<'a, 'r> FromRequest<'a, 'r> for UserLogged {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> rocket::request::Outcome<UserLogged, Self::Error> {
        let db = DbConn::from_request(request);
        if let Outcome::Failure(e) = db {
            return Outcome::Failure(e);
        }

        // token from request header
        let token = request.headers().get_one("X-Authorization");
        if let Some(token) = token {
            let token = token.trim();
            if !token.starts_with("Bearer ") {
                info!("User failed token login with token: {}", token);
                return Outcome::Failure((Status::BadRequest, ()));
            }
            let token = &token[7..]; // Possible DOS, mitigated by trim()
                                     // user from token db
            let user = user_from_token(db.as_ref().unwrap(), &token.to_string());
            if let Ok(u) = user {
                Outcome::Success(UserLogged { user: u})
            } else {
                info!("User attempted to login with invalid bearer token: {}", token);
                Outcome::Failure((Status::Unauthorized, ()))
            }
        } else {
            info!("User attempted to use secure route without Bearer header.");
            Outcome::Failure((Status::Unauthorized, ()))
        }
    }
}

/// Attempt to login user `LoginData` as json. Returns `LoginResult` a.k.a the auth token if the credentials are valid.
/// #Test
/// curl -X POST -H "Content-Type: application/json" http://raidable.ddns.net:27015/login -d '{"email":"value1", "password":"value2"}'
#[post("/login", format = "application/json", data = "<login>")]
pub fn login(login: Json<LoginRequest>, db: DbConn) -> Result<Json<LoginResult>, ReturnStatus> {
    // Pass from email
    let user = user_from_email(&db, &login.email);

    match user.as_ref() {
        Ok(user) => {
            match user.password {
                Some(ref pass) => {
                    match do_login(&pass.to_string(), &login.password) {
                        Some(token) => {
                            match set_user_token(&db, user.id, &token.to_string())
                            {
                                Ok(_) => {
                                    return Ok(Json(LoginResult {
                                        token: token.to_string(),
                                    }));
                                }
                                Err(e) => {
                                    error!("Failed to update user table to set new token of user id {:?}",e);
                                    return Err(ReturnStatus::new(Status::InternalServerError));
                                }
                            }
                        }
                        None => {
                            // Either bcrypt can't check the password, or its the wrong password.
                            // Either way its bad.

                            //error!("Internal password check error.");
                            //return Err(ReturnStatus::new(Status::InternalServerError));
                        }
                    }
                }
                None => info!(
                    "Login attempt for account without a password: {}",
                    &login.email
                ),
            }
        }
        Err(diesel::result::Error::NotFound) => {
            info!("Connection attempt with unknown email: {}", &login.email);
            return Err(ReturnStatus::new(Status::BadRequest));
        }
        Err(e) => {
            error!("Failed to get user from email: {:?}", e);
            return Err(ReturnStatus::new(Status::InternalServerError));
        }
    }
    return Err(ReturnStatus::new(Status::Unauthorized).with_message("Login Failed".to_string()));
}


/// Registers a new user using `RegisterData` as json.
/// #Test
/// curl -X POST -H "Content-Type: application/json" https://hoppinworld.net:27015/register -d '{"username":"test", "email":"test@test.com"}'
#[post("/register", format = "application/json", data = "<register>")]
pub fn register(db: DbConn, register: Json<RegisterRequest>, req: UserIp) -> Result<(), ReturnStatus> {
    if let Err(_) = register.validate() {
        return Err(ReturnStatus::new(Status::BadRequest).with_message("Failed to validate input data.".to_string()));
    }
    let key = env::var("RECAPTCHA_KEY").expect("RECAPTCHA_KEY must be set!");
    match recaptcha::verify(&key, &register.recaptcha, req.0.as_ref()) {
        Ok(_) => {
            match user_add(&db, &UserInsert::from(register.clone())) {
                Ok(1) => {
                    let token = Uuid::new_v4();
                    let limit = instant_in_days(1);
                    // Unwrap should be safe, as we inserted into the db just a split second ago.
                    let user = user_from_email(&db, &register.email).unwrap();
                    let password_reset = PasswordResetInsert {
                        token: token.to_string().clone(),
                        userid: user.id,
                        valid_until: limit.naive_local(),
                    };
                    info!(
                        "[TEMPORARY] Generated reset password token: {:?}",
                        password_reset
                    );
                    match password_reset_insert_or_replace(&db, password_reset) {
                        Ok(_) => {
                            let key = env::var("MAILGUN_KEY").expect("MAILGUN_KEY must be set!");
                            let creds = Credentials::new(&key, "mail.hoppinworld.net");
                            let from = EmailAddress::name_address("HoppinWorld", "noreply@mail.hoppinworld.net");
                            let msg = Message {
                                to: vec![EmailAddress::address(&register.email)],
                                cc: vec![],
                                bcc: vec![],
                                subject: String::from("HoppinWorld Register"),
                                body: MessageBody::Text(format!("Here's the password reset link: https://hoppinworld.net/setpassword/{}",token.to_string())),
                                options: vec![],
                            };
                            match send_email(&creds, &from, msg) {
                                Ok(_send_res) => {
                                    Ok(())
                                }
                                Err(e) => {
                                    error!("Failed to send register email: {:?}", e);
                                    Err(ReturnStatus::new(Status::InternalServerError))
                                }
                            }
                        },
                        Err(e) => {
                            error!("Failed to create password reset entry: {:?}", e);
                            Err(ReturnStatus::new(Status::InternalServerError))
                        }
                    }
                },
                Ok(_) => {
                    // TODO: Duplicate email != 500
                    error!("1)Failed to register new user");
                    Err(ReturnStatus::new(Status::InternalServerError))
                },
                Err(e) => {
                    // TODO: Duplicate email != 500
                    error!("2)Failed to register new user: {:?}", e);
                    Err(ReturnStatus::new(Status::InternalServerError))
                }
            }
        }
        Err(_) => {
            Err(ReturnStatus::new(Status::Unauthorized).with_message("Recaptcha check failed. Please try again.".to_string()))
        }
    }
}


#[post("/passreset", format = "application/json", data = "<passreset>")]
pub fn request_password_reset(db: DbConn, passreset: Json<PasswordResetRequest>, req: UserIp) -> Result<(), ReturnStatus> {
    if let Err(_) = passreset.validate() {
        return Err(ReturnStatus::new(Status::BadRequest).with_message("Failed to validate input data.".to_string()));
    }

    let key = env::var("RECAPTCHA_KEY").expect("RECAPTCHA_KEY must be set!");

    match recaptcha::verify(&key, &passreset.recaptcha, req.0.as_ref()) {
        Ok(_) => {
            match user_from_email(&db, &passreset.email) {
                Ok(user) => {
                    let token = Uuid::new_v4();
                    let limit = instant_in_days(1);
                    let password_reset = PasswordResetInsert {
                        token: token.to_string().clone(),
                        userid: user.id,
                        valid_until: limit.naive_local(),
                    };
                    // Unwrap should be safe, as we inserted into the db just a split second ago.
                    match password_reset_insert_or_replace(&db, password_reset) {
                        Ok(_) => {
                            let key = env::var("MAILGUN_KEY").expect("MAILGUN_KEY must be set!");
                            let creds = Credentials::new(&key, "mail.hoppinworld.net");
                            let from = EmailAddress::name_address("HoppinWorld", "noreply@mail.hoppinworld.net");
                            let msg = Message {
                                to: vec![EmailAddress::address(&passreset.email)],
                                cc: vec![],
                                bcc: vec![],
                                subject: String::from("HoppinWorld Password Reset"),
                                body: MessageBody::Text(format!("Here's the password reset link: https://hoppinworld.net/setpassword/{}",token.to_string())),
                                options: vec![],
                            };
                            match send_email(&creds, &from, msg) {
                                Ok(_send_res) => {
                                    Ok(())
                                }
                                Err(e) => {
                                    error!("Failed to send password reset email: {:?}", e);
                                    Err(ReturnStatus::new(Status::InternalServerError))
                                }
                            }
                        },
                        Err(e) => {
                            error!("Failed to create password reset entry: {:?}", e);
                            Err(ReturnStatus::new(Status::InternalServerError))
                        }
                    }
                },
                Err(e) => {
                    // TODO: Duplicate email != 500
                    error!("Failed to find user for email {} err: {:?}", passreset.email, e);
                    Err(ReturnStatus::new(Status::InternalServerError))
                }
            }
        }
        Err(_) => {
            Err(ReturnStatus::new(Status::Unauthorized).with_message("Recaptcha check failed. Please try again.".to_string()))
        }
    }
}


/// Changes the password of a user using the reset token and the new password (`ChangePassword` as json).
/// #Test
/// curl -X POST -H "Content-Type: application/json" https://raidable.ddns.net:27015/changepassword -d '{"token":"uuid", "password":"pass"}'
#[post("/changepassword", format = "application/json", data = "<data>")]
pub fn change_password(db: DbConn, data: Json<ChangePasswordRequest>) -> Result<(), ReturnStatus> {
    if data.password.len() < 8 || data.password.len() > 64 {
        return Err(ReturnStatus::new(Status::BadRequest).with_message("Password must be between 8 and 64 characters.".to_string()));
    }

    // Delete expired password reset entries
    if let Err(e) = remove_expired_password_reset(&db) {
        error!("Failed to delete expired password reset entries: {:?}", e);
    }

    match user_from_password_reset_token(&db, &data.token)
    {
        Ok(user) => {

            match set_user_password(&db, user.id, &data.password) {
                Ok(_) => {
                    if let Err(e) = remove_password_reset_for_user(&db, user.id) {
                        error!("Failed to delete old password reset records for user {:?} with err: {:?}", user, e);
                    }
                    Ok(())
                },
                Err(e) => {
                    error!("An error occured while changing the user password: {:?}", e);
                    Err(ReturnStatus::new(Status::InternalServerError))
                }
            }
        },
        Err(diesel::result::Error::NotFound) => {
            info!("Failed attempt to reset password: Token is invalid.");
            Err(ReturnStatus::new(Status::BadRequest).with_message("The password reset token is invalid, did it expire?".to_string()))
        }
        Err(e) => {
            error!(
                "Failed to get password_reset entry from reset token: {:?}",
                e
            );
            Err(ReturnStatus::new(Status::InternalServerError))
        }
    }
}

#[get("/logout")]
pub fn logout(user: UserLogged, db: DbConn) -> Result<(), ReturnStatus> {
    match set_user_token(&db, user.user.id, &"".to_string())
    {
        Ok(_) => Ok(()),
        Err(e) => {
            error!(
                "Failed to update user table to set disconnect user id {:?}",
                e
            );
            Err(ReturnStatus::new(Status::InternalServerError))
        }
    }
}


#[post("/submitscore", format = "application/json", data = "<data>")]
pub fn submit_score(user: UserLogged, db: DbConn, data: Json<ScoreInsertRequest>) -> Result<Json<bool>, ReturnStatus> {
    let userid = user.user.id;
    let season = 1;

    // Map exists?
    let map = map_from_id(&db, data.mapid);
    match map{
        Ok(_) => {
            // Is it the best score of the user on this map. Minimal time.
            let best_previous = score_from_user_map(&db, userid, data.mapid, season);
            match best_previous {
                Ok(bp) => {
                    if data.total_time < bp.total_time {
                        // New personnal best score
                    } else {
                        // Not a new personnal best.
                        return Ok(Json(false));
                    }
                }
                Err(diesel::result::Error::NotFound) => {
                    // No previous personnal best
                }
                Err(e) => {
                    error!("Failed to query database score_from_user_map: {}", e);
                    return Err(ReturnStatus::new(Status::InternalServerError));
                }
            }
            // TODO: Validate score https://github.com/HoppinWorld/scorevalidator
            let valid = true;

            if valid {
                let segment_times = segment_scores_to_string(&data.segment_times);

                let score_insert = ScoreInsert {
                    userid,
                    mapid: data.mapid,
                    segment_times,
                    strafes: data.strafes,
                    jumps: data.jumps,
                    total_time: data.total_time,
                    max_speed: data.max_speed,
                    average_speed: data.average_speed,
                    season,
                };
                match score_insert_or_replace(&db, score_insert) {
                    Ok(_) => {
                        Ok(Json(true))
                    }
                    Err(e) => {
                        error!("Failed to insert score: {}", e);
                        return Err(ReturnStatus::new(Status::InternalServerError));
                    }
                }
            } else {
                // TODO: Cheater likeliness update, or check validator works properly

                Ok(Json(false))
            }
        },
        Err(diesel::result::Error::NotFound) => {
            info!("User submitted score for invalid map id: {}", data.mapid);
            Err(ReturnStatus::new(Status::BadRequest).with_message("Invalid map id".to_string()))
        }
        Err(e) => {
            error!("Failed to query database map: {}", e);
            return Err(ReturnStatus::new(Status::InternalServerError));
        }
    }
}

/// Returns top 25 scores on a map
#[get("/map/<mapid>/scores")]
pub fn map_scores(db: DbConn, mapid: i32) -> Result<Json<Vec<ScoreDisplay>>, ReturnStatus> {
    let season = 1;
    match score_top_from_map(&db, mapid, season) {
        Ok(scores) => {
            let score_displays = scores.iter().flat_map(|score| {
                if let Ok(username) = user_from_id(&db, score.userid).map(|u| u.username){
                    Some(ScoreDisplay {
                        userid: score.userid,
                        username: username,
                        segment_times: score.segment_times.clone(),
                        strafes: score.strafes,
                        jumps: score.jumps,
                        total_time: score.total_time,
                    })
                } else {
                    None
                }
            }).collect::<Vec<_>>();
            Ok(Json(score_displays))
        }
        Err(e) => {
            error!("Failed to query database: {}", e);
            Err(ReturnStatus::new(Status::InternalServerError))
        }
    }
}

/// Returns the map info for a specific map
#[get("/map/<mapid>")]
pub fn map_info(db: DbConn, mapid: i32) -> Result<Json<MapDisplay>, ReturnStatus> {
    match map_from_id(&db, mapid) {
        Ok(map) => {
            // Convert Map to MapDisplay
            let mapper_name = user_from_id(&db, map.mapper).map(|u| u.username).unwrap_or_else(|_| {
                error!("Failed to find user from map creator for map id: {}", map.id);
                String::from("???") // Unknown mapper
            });

            let map_display = MapDisplay {
                id: map.id,
                status: map.status,
                name: map.name,
                segment_count: map.segment_count,
                path: map.path,
                mapper: map.mapper,
                mapper_name,
                difficulty: map.difficulty,
                categories: map.categories.split(",").map(|e| e.to_string()).collect(),
                tags: map.tags.split(",").map(|e| e.to_string()).collect(),
            };
            Ok(Json(map_display))
        }
        Err(diesel::result::Error::NotFound) => {
            Err(ReturnStatus::new(Status::BadRequest).with_message("Map not found for specified id".to_string()))
        }
        Err(e) => {
            error!("Failed to query database: {}", e);
            Err(ReturnStatus::new(Status::InternalServerError))
        }
    }
}

/// Returns the top score of a user on the specified map.
#[get("/user/<userid>/scores/<mapid>")]
pub fn user_score_for_map(db: DbConn, userid: i32, mapid: i32) -> Result<Json<Score>, ReturnStatus> {
    let season = 1;
    match score_from_user_map(&db, userid, mapid, season) {
        Ok(score) => {
            Ok(Json(score))
        }
        Err(diesel::result::Error::NotFound) => {
            Err(ReturnStatus::new(Status::BadRequest).with_message("User has no score on this map".to_string()))
        }
        Err(e) => {
            error!("Failed to query database: {}", e);
            Err(ReturnStatus::new(Status::InternalServerError))
        }
    }
}

/// Returns the list of maps
#[get("/map")]
pub fn list_maps(db: DbConn) -> Result<Json<Vec<Map>>, ReturnStatus> {
    match map_list(&db) {
        Ok(maps) => {
            Ok(Json(maps))
        }
        Err(e) => {
            error!("Failed to query database: {}", e);
            Err(ReturnStatus::new(Status::InternalServerError))
        }
    }
}

/// Checks if a given user token is valid
#[post("/validatetoken", format = "application/json", data = "<token>")]
pub fn validate_token(token: Json<String>, db: DbConn) -> Result<Json<bool>, ReturnStatus> {
    // Pass from email
    let user = user_from_token(&db, &token);

    match user.as_ref() {
        Ok(_) => {
            Ok(Json(true))
        }
        Err(diesel::result::Error::NotFound) => {
            Ok(Json(false))
        }
        Err(e) => {
            error!("Failed to get user from email: {:?}", e);
            return Err(ReturnStatus::new(Status::InternalServerError));
        }
    }
}
