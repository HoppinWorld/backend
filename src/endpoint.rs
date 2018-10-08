use rocket::request::FromRequest;
use backend_utils::*;
use super::model::*;
use super::db::*;
use uuid::Uuid;
use rocket::http::Status;
use rocket_contrib::Json;
use rocket::{Outcome, Request};


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
                Ok(_) => Ok(()),
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

