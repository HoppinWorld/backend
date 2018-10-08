use backend_utils::*;
use super::model::*;
use super::schema::*;

use diesel::*;

type DieselResult<T> = Result<T, diesel::result::Error>;

/// Returns the user associated with the corresponding token.
pub fn user_from_token(db: &DbConn, token: &String) -> DieselResult<User> {
    user::table
        .filter(user::token.eq(token))
        .first::<User>(&**db)
}

/// Returns the user associated with the corresponding email.
pub fn user_from_email(db: &DbConn, email: &String) -> DieselResult<User> {
    user::table
        .filter(user::email.eq(email))
        .first::<User>(&**db)
}

pub fn set_user_token(db: &DbConn, user_id: i32, token: &String) -> DieselResult<usize> {
	diesel::update(
        user::table.filter(user::columns::id.eq(user_id)),
    ).set(user::columns::token.eq(token.clone()))
        .execute(&**db)
}

/// Sets the database password of a user to the bcrypt'ed version of the input string.
pub fn set_user_password(
    db: &DbConn,
    user_id: i32,
    password: &String,
) -> Result<usize, Box<std::error::Error>> {
    let encrypted = hash_password(password)?;
    Ok(
        diesel::update(user::table.filter(user::id.eq(user_id)))
            .set(user::columns::password.eq(encrypted))
            .execute(&**db)?,
    )
}

pub fn user_add(db: &DbConn, user: &UserInsert) -> DieselResult<usize> {
	diesel::insert_into(user::table)
        .values(user)
        .execute(&**db)
}

pub fn password_reset_insert_or_replace(db: &DbConn, password_reset: PasswordResetInsert) -> DieselResult<usize> {
	diesel::replace_into(password_reset::table)
        .values(password_reset)
        .execute(&**db)
}

pub fn user_from_password_reset_token(db: &DbConn, token: &String) -> DieselResult<User> {
	password_reset::table
        .filter(password_reset::token.eq(token))
        .inner_join(user::table.on(password_reset::userid.eq(user::id)))
        .first::<(PasswordReset, User)>(&**db)
        .map(|t| t.1)
}

