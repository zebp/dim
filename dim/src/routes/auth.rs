use crate::core::DbConnection;
use crate::errors;
use auth::jwt_generate;

use database::user::verify;
use database::user::InsertableUser;
use database::user::Login;
use database::user::User;

use serde_json::json;

use warp::reply;

/// # POST `/api/v1/auth/login`
/// Method will log a user in and return a authentication token that can be used to authenticate other
/// requests.
///
/// # Request
/// This method accepts a JSON body that deserializes into [`Login`].
///
/// ## Example
/// ```text
/// curl -X POST http://127.0.0.1:8000/api/v1/auth/login -H "Content-type: application/json" -d
/// '{"username": "testuser", "password": "testpassword", "invite_token":
/// "72390330-b8af-4413-8305-5f8cae1c8f88"}'
/// ```
///
/// # Response
/// If a user is successfully created, this method will return status `200 0K` as well as a
/// authentication token.
/// ```
/// {
///   "token": "...."
/// }
/// ```
///
/// # Errors
/// * [`InvalidCredentials`] - The provided username or password is incorrect.
///
/// [`InvalidCredentials`]: crate::errors::DimError::InvalidCredentials
/// [`Login`]: database::user::login
pub async fn login(
    new_login: Login,
    conn: DbConnection,
) -> Result<impl warp::Reply, errors::DimError> {
    let mut tx = conn.read().begin().await?;
    let user = User::get(&mut tx, &new_login.username)
        .await
        .map_err(|_| errors::DimError::InvalidCredentials)?;

    if verify(
        user.username.clone(),
        user.password.clone(),
        new_login.password.clone(),
    ) {
        let token = jwt_generate(user.username, user.roles.clone());

        return Ok(reply::json(&json!({
            "token": token,
        })));
    }

    Err(errors::DimError::InvalidCredentials)
}


pub async fn register(
    new_user: Login,
    conn: DbConnection,
) -> Result<impl warp::Reply, errors::DimError> {
    // FIXME: Return INTERNAL SERVER ERROR maybe with a traceback?
    let mut lock = conn.writer().lock_owned().await;
    let mut tx = database::write_tx(&mut lock).await?;
    // NOTE: I doubt this method can faily all the time, we should map server error here too.
    let users_empty = User::get_all(&mut tx).await?.is_empty();

    if !users_empty
        && (new_user.invite_token.is_none()
            || !new_user.invite_token_valid(&mut tx).await.unwrap_or(false))
    {
        return Err(errors::DimError::NoToken);
    }

    let roles = if !users_empty {
        vec!["user".to_string()]
    } else {
        vec!["owner".to_string()]
    };

    let claimed_invite = if users_empty {
        // NOTE: Double check what we are returning here.
        Login::new_invite(&mut tx).await?
    } else {
        new_user
            .invite_token
            .ok_or(errors::DimError::NoToken)?
    };

    let res = InsertableUser {
        username: new_user.username.clone(),
        password: new_user.password.clone(),
        roles,
        claimed_invite,
        prefs: Default::default(),
    }
    .insert(&mut tx)
    .await?;

    // FIXME: Return internal server error.
    tx.commit().await?;

    Ok(reply::json(&json!({ "username": res })))
}

#[doc(hidden)]
pub(crate) mod filters {
    use crate::core::DbConnection;
    use database::user::Login;

    use warp::reject;
    use warp::Filter;

    use super::super::global_filters::with_state;

    pub fn login(
        conn: DbConnection,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("api" / "v1" / "auth" / "login")
            .and(warp::post())
            .and(warp::body::json::<Login>())
            .and(with_state(conn))
            .and_then(|new_login: Login, conn: DbConnection| async move {
                super::login(new_login, conn)
                    .await
                    .map_err(|e| reject::custom(e))
            })
    }

    pub fn register(
        conn: DbConnection,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("api" / "v1" / "auth" / "register")
            .and(warp::post())
            .and(warp::body::json::<Login>())
            .and(with_state(conn))
            .and_then(|new_login: Login, conn: DbConnection| async move {
                super::register(new_login, conn)
                    .await
                    .map_err(|e| reject::custom(e))
            })
    }
}
