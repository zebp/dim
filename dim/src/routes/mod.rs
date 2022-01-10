//! This module contains all the routes supported by the API.
//!
//! # Errors
//! All routes can error out. If some unexpected behavior has occured, the server will return a non
//! 2XX HTTP code, alongside the error and error description encoded with the following format:
//! ```
//! {
//!   "error": "<error type>",
//!   "message": "<error message>"
//! }
//! ```
//!
//! ## Common errors
//! * [`DatabaseError`] - All routes can spurriously fail
//! when making a database transaction, or trying to acquire a database connection. When this
//! happens [`DatabaseError`] will be returned.
//!
//! [`DatabaseError`]: crate::errors::DimError::DatabaseError
pub mod auth;
pub mod dashboard;
pub mod general;
pub mod library;
pub mod media;
pub mod mediafile;
pub mod rematch_media;
pub mod settings;
pub mod statik;
pub mod stream;
pub mod tv;
pub mod user;
pub mod host;
pub mod invites;

#[doc(hidden)]
pub mod global_filters {
    use crate::errors;
    use database::DbConnection;

    use std::convert::Infallible;
    use std::error::Error;
    use warp::Filter;
    use warp::Reply;

    pub fn with_db(
        conn: DbConnection,
    ) -> impl Filter<Extract = (DbConnection,), Error = Infallible> + Clone {
        warp::any().map(move || conn.clone())
    }

    pub fn with_state<T: Send + Clone>(
        state: T,
    ) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
        warp::any().map(move || state.clone())
    }

    pub async fn handle_rejection(
        err: warp::reject::Rejection,
    ) -> Result<impl warp::Reply, warp::reject::Rejection> {
        if let Some(e) = err.find::<errors::DimError>() {
            return Ok(e.clone().into_response());
        } else if err.find::<auth::JWTError>().is_some() {
            return Ok(errors::DimError::Unauthenticated.into_response());
        } else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
            return Ok(errors::DimError::MissingFieldInBody {
                description: e.source().unwrap().to_string(),
            }
            .into_response());
        }

        Err(err)
    }

    pub fn api_not_found(
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("api" / ..)
            .and(warp::any())
            .map(|| crate::errors::DimError::NotFoundError)
    }
}
