use rocket::request::FromRequest;
use backend_utils::*;
use super::model::*;
use super::db::*;
use uuid::Uuid;
use rocket::http::Status;
use rocket_contrib::Json;
use rocket::{Outcome, Request};
use lettre_email::EmailBuilder;
use lettre::{ClientSecurity, EmailAddress, Envelope, SendableEmail, SmtpClient, Transport, SmtpTransport, SendmailTransport};

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
                return Outcome::Failure((Status::BadRequest, ()));
            }
            let token = &token[7..]; // Possible DOS, mitigated by trim()
                                     // user from token db
            let user = user_from_token(db.as_ref().unwrap(), &token.to_string());
            if let Ok(u) = user {
                Outcome::Success(UserLogged { user: u})
            } else {
                Outcome::Failure((Status::Unauthorized, ()))
            }
        } else {
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
/// curl -X POST -H "Content-Type: application/json" http://127.0.0.1:27015/register -d '{"name":"test", "email":"test@test.com"}'
#[post("/register", format = "application/json", data = "<register>")]
pub fn register(db: DbConn, register: Json<UserInsert>) -> Result<(), ReturnStatus> {
    match user_add(&db, &*register) {
        Ok(1) => {
            let token = Uuid::new_v4();
            let limit = instant_in_days(1);
            // Unwrap should be safe, as we inserted into the db just a split second ago.
            let user = user_from_email(&db, &register.email).unwrap();
            let password_reset = PasswordResetInsert {
                token: token.to_string(),
                userid: user.id,
                valid_until: limit.naive_local(),
            };
            info!(
                "[TEMPORARY] Generated reset password token: {:?}",
                password_reset
            );
            match password_reset_insert_or_replace(&db, password_reset) {
                Ok(_) => {
                    // Send email
                    let email = EmailBuilder::new()
                        // Addresses can be specified by the tuple (email, alias)
                        .to("jojolepromain@gmail.com")
                        // ... or by an address only
                        .from("noreply@hoppinworld.net")
                        .subject("Hi, Hello world")
                        .text("Hello world.")
                        //.html()
                        .build()
                        .unwrap();

                    /*let mut mailer = SmtpClient::simple_builder("server.tld").unwrap()
                        // Set the name sent during EHLO/HELO, default is `localhost`
                        .hello_name(ClientId::Domain("my.hostname.tld".to_string()))
                        // Add credentials for authentication
                        .credentials(Credentials::new("username".to_string(), "password".to_string()))
                        // Enable SMTPUTF8 if the server supports it
                        .smtp_utf8(true)
                        // Configure expected authentication mechanism
                        .authentication_mechanism(Mechanism::Plain)
                        // Enable connection reuse
                        .connection_reuse(ConnectionReuseParameters::ReuseUnlimited).build();*/
                    //let mut mailer = SmtpClient::new_unencrypted_localhost().unwrap().transport();
                    //let mailer = SmtpTransport::simple_builder("hoppinworld.net");
                    //let mut mailer = SendmailTransport::new();
                    //let mailer = SmtpClient::new_simple("127.0.0.1")
                    let mailer = SmtpClient::new("127.0.0.1:25", ClientSecurity::None)
                        .unwrap()
                        .transport()
                        .send(email.into())
                        .unwrap();
                    //mailer.send(email.into()).expect("failed to send mail");
                    //mailer.close();
                    Ok(())
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


/// Changes the password of a user using the reset token and the new password (`ChangePassword` as json).
/// #Test
/// curl -X POST -H "Content-Type: application/json" http://raidable.ddns.net:27015/changepassword -d '{"token":"uuid", "password":"pass"}'
#[post("/changepassword", format = "application/json", data = "<data>")]
pub fn change_password(db: DbConn, data: Json<ChangePasswordRequest>) -> Result<(), ReturnStatus> {
    match user_from_password_reset_token(&db, &data.token)
    {
        Ok(user) => match set_user_password(&db, user.id, &data.password) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("An error occured while changing the user password: {:?}", e);
                Err(ReturnStatus::new(Status::InternalServerError))
            }
        },
        Err(diesel::result::Error::NotFound) => {
            info!("Failed attempt to reset password: Token is invalid.");
            Err(ReturnStatus::new(Status::BadRequest))
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
fn logout(user: UserLogged, db: DbConn) -> Result<(), ReturnStatus> {
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
fn submit_score(user: UserLogged, db: DbConn, data: Json<ScoreInsertRequest>) -> Result<Json<bool>, ReturnStatus> {
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
            Err(ReturnStatus::new(Status::BadRequest).with_message("Invalid map id".to_string()))
        }
        Err(e) => {
            error!("Failed to query database map: {}", e);
            return Err(ReturnStatus::new(Status::InternalServerError));
        }
    }
}


