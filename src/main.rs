use auth::{with_auth, Role};
use error::Error::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use warp::{reject, reply, Filter, Rejection, Reply};
use uuid::Uuid;
use blake2::{Blake2b, Digest};
use openssl::sign::{Signer};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;

extern crate chrono;
extern crate base64;

mod auth;
mod error;


type Result<T> = std::result::Result<T, error::Error>;
type WebResult<T> = std::result::Result<T, Rejection>;
type Users = Arc<HashMap<String, User>>;

#[derive(Clone)]
pub struct User {
    pub uid: String,
    pub identity: String,
    pub service_id: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub identity: String,
    pub service_id: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub responder: String,
}


#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());
    let login_route = warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler);
    let user_route = warp::path!("user")
        .and(with_auth(Role::User))
        .and_then(user_handler);
    let admin_route = warp::path!("admin")
        .and(with_auth(Role::Admin))
        .and_then(admin_handler);
    let routes = login_route
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection);

    println!("============================");
    println!("| royal_blobs_jwt_service  |");
    println!("============================");
    println!("-> Symmetric HS512 JWT");
    println!("-> base64 encoded BLAKE2");
    println!("-> UUID version 4 tracking");
    println!("ADDED~RSA~signed~blob~format");
    println!("Starting Warp listener on the loopback device, port 5599...");

    warp::serve(routes).run(([127, 0, 0, 1], 5599)).await;

}

fn with_users(users: Users) -> impl Filter<Extract = (Users,), Error = Infallible> + Clone {
    warp::any().map(move || users.clone())
}

pub async fn login_handler(users: Users, body: LoginRequest) -> WebResult<impl Reply> {
    use chrono::DateTime;
    use chrono::Utc;
    let login_date: DateTime<Utc> = Utc::now();
    let transaction_id = Uuid::new_v4();
    println!("{} - royal_blobs_jwt_service INFO - START JWT usage UID {}", login_date, &transaction_id);

    match users
        .iter()
        .find(|(_uid, user)| user.identity == body.identity && user.service_id == body.service_id)
    {
        Some((uid, user)) => {
            let jwt_token = auth::create_jwt(&uid, &Role::from_str(&user.role))
                .map_err(|e| reject::custom(e))?;
            let mut hasher = Blake2b::new();
            hasher.update(&jwt_token);
            let blake2_hash = hasher.finalize();
            let encoded_hash = base64::encode(blake2_hash);
            let hash_date: DateTime<Utc> = Utc::now();
            eprintln!("{} - royal_blobs_jwt_service INFO - {} - base64 BLAKE2: {:?}", hash_date, &transaction_id, &encoded_hash);
            let key_pair = Rsa::generate(2048).unwrap();
            let blob_sign_key = PKey::from_rsa(key_pair).unwrap();
            let mut signer = Signer::new(MessageDigest::sha256(), &blob_sign_key).unwrap();
            let jwt_token_bytes = &jwt_token.as_bytes();
            signer.update(jwt_token_bytes).unwrap();
            let signature = signer.sign_to_vec().unwrap();
            let blob_64 = base64::encode(signature);
            let responder: String = [blob_64,jwt_token,encoded_hash].join("|");

            Ok(reply::json(&LoginResponse { responder }))
        }
        None => Err(reject::custom(WrongCredentialsError)),
    }

}

pub async fn user_handler(uid: String) -> WebResult<impl Reply> {
    use chrono::DateTime;
    use chrono::Utc;
    let handler_date: DateTime<Utc> = Utc::now();
    println!("{} - royal_blobs_jwt_service INFO - user resource provided", handler_date);

    Ok(format!("royal_blobs_jwt_service {}", uid))
}

pub async fn admin_handler(uid: String) -> WebResult<impl Reply> {
    use chrono::DateTime;
    use chrono::Utc;
    let admin_handler_date: DateTime<Utc> = Utc::now();
    println!("{} - royal_blobs_jwt_service INFO - admin resource provided", admin_handler_date);

    Ok(format!("royal_blobs_jwt_service ADMIN {}", uid))
}

fn init_users() -> HashMap<String, User> {
    let mut map = HashMap::new();
    map.insert(
        String::from("1"),
        User {
            uid: String::from("Hashmap for services mapping"),
            identity: String::from("nobody@localhost"),
            service_id: String::from("5aae5619a4b33765800bc5f9bdd1be507fb"),
            role: String::from("User"),
        },
    );
    map.insert(
        String::from("2"),
        User {
            uid: String::from("Hashmap for services mapping"),
            identity: String::from("root@localhost"),
            service_id: String::from("3ec85f59dce67fc936d7f1e63466aea3b6c"),
            role: String::from("Admin"),
        },
    );

    map
}
