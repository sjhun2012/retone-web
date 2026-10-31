use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use rand_core::OsRng;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, SqlitePool};
use tower_http::{services::{ServeDir, ServeFile}, trace::TraceLayer};
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
struct AppState { db: SqlitePool, jwt_secret: Arc<String>, openai_key: Option<Arc<String>>, openai_model: Arc<String>, secure_cookie: bool }

#[derive(Debug, Serialize)]
struct ApiError { error: String }
impl ApiError { fn bad(message: &str) -> (StatusCode, Json<ApiError>) { (StatusCode::BAD_REQUEST, Json(ApiError { error: message.into() })) } fn unauthorized() -> (StatusCode, Json<ApiError>) { (StatusCode::UNAUTHORIZED, Json(ApiError { error: "로그인이 필요합니다.".into() })) } }

#[derive(Debug, Serialize, Deserialize)]
struct Claims { sub: String, exp: usize }
#[derive(Debug, Deserialize)]
struct Credentials { name: String, phone: String, password: String }
#[derive(Debug, Serialize)]
struct UserView { id: String, name: String }
#[derive(Debug, FromRow)]
struct User { id: String, name: String, phone: String, password_hash: String }

#[derive(Debug, Deserialize)] struct NewRoom { name: String, friend_ids: Option<Vec<String>> }
#[derive(Debug, Deserialize)] struct AddFriend { phone: String }
#[derive(Debug, Serialize, FromRow)] struct FriendView { id: String, name: String, phone: String }
#[derive(Debug, Serialize, FromRow)] struct FriendRequestView { id: String, sender_id: String, sender_name: String, sender_phone: String }
#[derive(Debug, Deserialize)] struct FriendDecision { accepted: bool }
#[derive(Debug, Serialize, FromRow)] struct RoomView { id: String, name: String, members: i64, unread: i64, last: String, updated: i64 }
#[derive(Debug, Serialize, FromRow)] struct MessageView { id: String, sender: String, mine: bool, body: String, created: i64 }
#[derive(Debug, Deserialize)] struct NewMessage { body: String }
#[derive(Debug, Deserialize)] struct AnalyzeRequest { text: String, relationship: Option<String> }
#[derive(Debug, Serialize, Deserialize)] struct Suggestion { label: String, text: String }
#[derive(Debug, Serialize, Deserialize)] struct Analysis { message_type: String, emotion: String, intent: String, risk: String, suggestions: Vec<Suggestion>, rehearsal: String, missing_details: Vec<String>, check_questions: Vec<String> }
#[derive(Debug, Deserialize)] struct NewAgreement { room_id: String, task: String, my_understanding: String, their_understanding: String, deadline: Option<String> }
#[derive(Debug, Serialize, FromRow)] struct AgreementView { id: String, room_id: String, task: String, my_understanding: String, their_understanding: String, deadline: Option<String>, agreed: bool }
#[derive(Debug, Deserialize)] struct NewAppointment { title: String, starts_at: String, place: Option<String> }
#[derive(Debug, Serialize, FromRow)] struct AppointmentView { id: String, title: String, starts_at: String, place: Option<String> }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();
    std::fs::create_dir_all("data").ok();
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://data/retone.db?mode=rwc".into());
    let db = SqlitePoolOptions::new().max_connections(5).connect(&database_url).await.context("database connection failed")?;
    migrate(&db).await?;
    let state = AppState { db, jwt_secret: Arc::new(env::var("JWT_SECRET").unwrap_or_else(|_| "development-secret-change-me".into())), openai_key: env::var("OPENAI_API_KEY").ok().filter(|s| !s.is_empty()).map(Arc::new), openai_model: Arc::new(env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-6-luna".into())), secure_cookie: env::var("RENDER").is_ok() };
    let api = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/auth/register", post(register)).route("/api/auth/login", post(login)).route("/api/auth/logout", post(logout)).route("/api/auth/me", get(me))
        .route("/api/bootstrap", get(bootstrap)).route("/api/friends", get(friends).post(add_friend)).route("/api/friends/requests", get(friend_requests)).route("/api/friends/requests/:id", post(decide_friend_request)).route("/api/rooms", post(create_room)).route("/api/rooms/:id/messages", get(messages).post(send_message))
        .route("/api/analyze", post(analyze)).route("/api/agreements", post(create_agreement)).route("/api/appointments", post(create_appointment))
        .with_state(state)
        .layer(TraceLayer::new_for_http());
    let app = api.fallback_service(ServeDir::new("static").not_found_service(ServeFile::new("static/index.html")));
    let addr = SocketAddr::from(([0, 0, 0, 0], env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3000)));
    info!(%addr, "Re:Tone started");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn migrate(db: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query("PRAGMA foreign_keys = ON; CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS friendships (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, PRIMARY KEY(user_id,friend_id), CHECK(user_id <> friend_id)); CREATE TABLE IF NOT EXISTS friend_requests (id TEXT PRIMARY KEY, sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, receiver_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT NOT NULL CHECK(status IN ('pending','accepted','rejected')), created_at INTEGER NOT NULL, UNIQUE(sender_id,receiver_id)); CREATE TABLE IF NOT EXISTS rooms (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS room_members (room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(room_id,user_id)); CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS agreements (id TEXT PRIMARY KEY, room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE, created_by TEXT NOT NULL REFERENCES users(id), task TEXT NOT NULL, my_understanding TEXT NOT NULL, their_understanding TEXT NOT NULL, deadline TEXT, agreed INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS appointments (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, starts_at TEXT NOT NULL, place TEXT);").execute(db).await?;
    Ok(())
}

fn now() -> i64 { Utc::now().timestamp_millis() }
fn password_hash(password: &str) -> Result<String, (StatusCode, Json<ApiError>)> { Argon2::default().hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng)).map(|p| p.to_string()).map_err(|_| ApiError::bad("비밀번호를 처리하지 못했습니다.")) }
fn token(user_id: &str, secret: &str) -> Result<String, (StatusCode, Json<ApiError>)> { encode(&Header::default(), &Claims { sub: user_id.into(), exp: (Utc::now() + ChronoDuration::days(7)).timestamp() as usize }, &EncodingKey::from_secret(secret.as_bytes())).map_err(|_| ApiError::bad("로그인 토큰을 생성하지 못했습니다.")) }
fn cookie(token: &str, secure: bool) -> HeaderValue { HeaderValue::from_str(&format!("retone_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{}", if secure { "; Secure" } else { "" })).unwrap() }
fn auth(headers: &HeaderMap, state: &AppState) -> Result<String, (StatusCode, Json<ApiError>)> { let raw = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).and_then(|v| v.split(';').map(str::trim).find_map(|part| part.strip_prefix("retone_session="))).ok_or_else(ApiError::unauthorized)?; decode::<Claims>(raw, &DecodingKey::from_secret(state.jwt_secret.as_bytes()), &Validation::default()).map(|d| d.claims.sub).map_err(|_| ApiError::unauthorized()) }
async fn user_for(headers: &HeaderMap, state: &AppState) -> Result<User, (StatusCode, Json<ApiError>)> { let id = auth(headers, state)?; sqlx::query_as::<_, User>("SELECT id,name,phone,password_hash FROM users WHERE id=?").bind(id).fetch_optional(&state.db).await.map_err(|_| ApiError::bad("사용자 정보를 읽지 못했습니다."))?.ok_or_else(ApiError::unauthorized) }

async fn register(State(state): State<AppState>, Json(input): Json<Credentials>) -> Result<Response, (StatusCode, Json<ApiError>)> {
    if input.name.trim().is_empty() || input.phone.chars().filter(|c| c.is_ascii_digit()).count() < 9 || input.password.len() < 6 { return Err(ApiError::bad("이름, 올바른 전화번호, 6자 이상 비밀번호를 입력해 주세요.")); }
    let id = Uuid::new_v4().to_string(); let phone: String = input.phone.chars().filter(|c| c.is_ascii_digit()).collect();
    let result = sqlx::query("INSERT INTO users(id,name,phone,password_hash,created_at) VALUES(?,?,?,?,?)").bind(&id).bind(input.name.trim()).bind(phone).bind(password_hash(&input.password)?).bind(now()).execute(&state.db).await;
    if result.is_err() { return Err(ApiError::bad("이미 가입된 전화번호입니다. 로그인해 주세요.")); }
    let mut response = Json(UserView { id: id.clone(), name: input.name.trim().into() }).into_response(); response.headers_mut().insert(header::SET_COOKIE, cookie(&token(&id, &state.jwt_secret)?, state.secure_cookie)); Ok(response)
}
async fn login(State(state): State<AppState>, Json(input): Json<Credentials>) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let phone: String = input.phone.chars().filter(|c| c.is_ascii_digit()).collect(); let user = sqlx::query_as::<_, User>("SELECT id,name,phone,password_hash FROM users WHERE phone=?").bind(phone).fetch_optional(&state.db).await.map_err(|_| ApiError::bad("로그인에 실패했습니다."))?.ok_or_else(|| ApiError::bad("전화번호 또는 비밀번호가 올바르지 않습니다."))?;
    let parsed = PasswordHash::new(&user.password_hash).map_err(|_| ApiError::bad("로그인에 실패했습니다."))?; if Argon2::default().verify_password(input.password.as_bytes(), &parsed).is_err() { return Err(ApiError::bad("전화번호 또는 비밀번호가 올바르지 않습니다.")); }
    let mut response = Json(UserView { id: user.id.clone(), name: user.name }).into_response(); response.headers_mut().insert(header::SET_COOKIE, cookie(&token(&user.id, &state.jwt_secret)?, state.secure_cookie)); Ok(response)
}
async fn logout(State(state): State<AppState>) -> Response { let mut r = StatusCode::NO_CONTENT.into_response(); r.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static("retone_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")); r }
async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<UserView>, (StatusCode, Json<ApiError>)> { let u = user_for(&headers, &state).await?; Ok(Json(UserView { id: u.id, name: u.name })) }

async fn friend_list(db: &SqlitePool, user_id: &str) -> Result<Vec<FriendView>, (StatusCode, Json<ApiError>)> { sqlx::query_as::<_, FriendView>("SELECT u.id,u.name,u.phone FROM friendships f JOIN users u ON u.id=f.friend_id WHERE f.user_id=? ORDER BY u.name COLLATE NOCASE").bind(user_id).fetch_all(db).await.map_err(|_| ApiError::bad("친구 목록을 읽지 못했습니다.")) }
async fn friends(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<FriendView>>, (StatusCode, Json<ApiError>)> { let user=user_for(&headers,&state).await?; Ok(Json(friend_list(&state.db,&user.id).await?)) }
async fn incoming_requests(db: &SqlitePool, user_id: &str) -> Result<Vec<FriendRequestView>, (StatusCode, Json<ApiError>)> { sqlx::query_as::<_,FriendRequestView>("SELECT r.id,r.sender_id,u.name sender_name,u.phone sender_phone FROM friend_requests r JOIN users u ON u.id=r.sender_id WHERE r.receiver_id=? AND r.status='pending' ORDER BY r.created_at DESC").bind(user_id).fetch_all(db).await.map_err(|_|ApiError::bad("친구 요청을 읽지 못했습니다.")) }
async fn add_friend(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<AddFriend>) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> { let user=user_for(&headers,&state).await?; let phone:String=input.phone.chars().filter(|c|c.is_ascii_digit()).collect(); let friend=sqlx::query_as::<_,User>("SELECT id,name,phone,password_hash FROM users WHERE phone=?").bind(phone).fetch_optional(&state.db).await.map_err(|_|ApiError::bad("전화번호를 확인하지 못했습니다."))?.ok_or_else(||ApiError::bad("이 전화번호로 가입한 사용자가 없습니다."))?; if friend.id==user.id{return Err(ApiError::bad("자기 자신은 친구로 추가할 수 없습니다."));} let already=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM friendships WHERE user_id=? AND friend_id=?").bind(&user.id).bind(&friend.id).fetch_one(&state.db).await.unwrap_or(0)>0; if already{return Err(ApiError::bad("이미 친구입니다."));} let reverse_pending=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM friend_requests WHERE sender_id=? AND receiver_id=? AND status='pending'").bind(&friend.id).bind(&user.id).fetch_one(&state.db).await.unwrap_or(0)>0; if reverse_pending{return Err(ApiError::bad("상대가 이미 친구 요청을 보냈어요. 친구 탭에서 승인해 주세요."));} let request_id=Uuid::new_v4().to_string(); let result=sqlx::query("INSERT INTO friend_requests(id,sender_id,receiver_id,status,created_at) VALUES(?,?,?,'pending',?) ON CONFLICT(sender_id,receiver_id) DO UPDATE SET status='pending',created_at=excluded.created_at").bind(&request_id).bind(&user.id).bind(&friend.id).bind(now()).execute(&state.db).await; if result.is_err(){return Err(ApiError::bad("친구 요청을 보내지 못했습니다."));} Ok(Json(json!({"message":"친구 요청을 보냈습니다.","receiver_name":friend.name}))) }
async fn friend_requests(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Vec<FriendRequestView>>, (StatusCode, Json<ApiError>)> { let user=user_for(&headers,&state).await?; Ok(Json(incoming_requests(&state.db,&user.id).await?)) }
async fn decide_friend_request(State(state): State<AppState>, headers: HeaderMap, Path(request_id): Path<String>, Json(input): Json<FriendDecision>) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> { let user=user_for(&headers,&state).await?; let request=sqlx::query_as::<_,(String,String)>("SELECT sender_id,receiver_id FROM friend_requests WHERE id=? AND receiver_id=? AND status='pending'").bind(&request_id).bind(&user.id).fetch_optional(&state.db).await.map_err(|_|ApiError::bad("친구 요청을 처리하지 못했습니다."))?.ok_or_else(||ApiError::bad("처리할 친구 요청이 없습니다."))?; let mut tx=state.db.begin().await.map_err(|_|ApiError::bad("친구 요청을 처리하지 못했습니다."))?; let status=if input.accepted{"accepted"}else{"rejected"}; sqlx::query("UPDATE friend_requests SET status=? WHERE id=?").bind(status).bind(&request_id).execute(&mut *tx).await.map_err(|_|ApiError::bad("친구 요청을 처리하지 못했습니다."))?; if input.accepted { for (a,b) in [(&request.0,&request.1),(&request.1,&request.0)] { sqlx::query("INSERT OR IGNORE INTO friendships(user_id,friend_id,created_at) VALUES(?,?,?)").bind(a).bind(b).bind(now()).execute(&mut *tx).await.map_err(|_|ApiError::bad("친구를 추가하지 못했습니다."))?; } } tx.commit().await.map_err(|_|ApiError::bad("친구 요청을 처리하지 못했습니다."))?; Ok(Json(json!({"accepted":input.accepted}))) }
async fn bootstrap(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> { let user = user_for(&headers, &state).await?; let rooms = sqlx::query_as::<_, RoomView>("SELECT r.id,r.name,COUNT(DISTINCT rm.user_id) members,0 unread,COALESCE((SELECT body FROM messages WHERE room_id=r.id ORDER BY created_at DESC LIMIT 1),'아직 메시지가 없어요') last,COALESCE((SELECT created_at FROM messages WHERE room_id=r.id ORDER BY created_at DESC LIMIT 1),r.created_at) updated FROM rooms r JOIN room_members rm ON rm.room_id=r.id WHERE EXISTS(SELECT 1 FROM room_members mine WHERE mine.room_id=r.id AND mine.user_id=?) GROUP BY r.id ORDER BY updated DESC").bind(&user.id).fetch_all(&state.db).await.map_err(|_| ApiError::bad("대화 목록을 읽지 못했습니다."))?; let agreements = sqlx::query_as::<_, AgreementView>("SELECT id,room_id,task,my_understanding,their_understanding,deadline,agreed FROM agreements WHERE created_by=? ORDER BY rowid DESC").bind(&user.id).fetch_all(&state.db).await.unwrap_or_default(); let appointments = sqlx::query_as::<_, AppointmentView>("SELECT id,title,starts_at,place FROM appointments WHERE user_id=? ORDER BY starts_at ASC").bind(&user.id).fetch_all(&state.db).await.unwrap_or_default(); let friend_views=friend_list(&state.db,&user.id).await?; let requests=incoming_requests(&state.db,&user.id).await?; Ok(Json(json!({"user":{"id":user.id,"name":user.name},"rooms":rooms,"friends":friend_views,"incoming_requests":requests,"agreements":agreements,"appointments":appointments}))) }
async fn create_room(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<NewRoom>) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> { let user = user_for(&headers, &state).await?; if input.name.trim().is_empty() { return Err(ApiError::bad("채팅방 이름을 입력해 주세요.")); } let id = Uuid::new_v4().to_string(); let mut tx = state.db.begin().await.map_err(|_| ApiError::bad("채팅방을 만들지 못했습니다."))?; sqlx::query("INSERT INTO rooms(id,name,created_at) VALUES(?,?,?)").bind(&id).bind(input.name.trim()).bind(now()).execute(&mut *tx).await.map_err(|_| ApiError::bad("채팅방을 만들지 못했습니다."))?; sqlx::query("INSERT INTO room_members(room_id,user_id) VALUES(?,?)").bind(&id).bind(&user.id).execute(&mut *tx).await.map_err(|_| ApiError::bad("참여자를 추가하지 못했습니다."))?; for friend_id in input.friend_ids.unwrap_or_default() { let is_friend=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM friendships WHERE user_id=? AND friend_id=?").bind(&user.id).bind(&friend_id).fetch_one(&state.db).await.unwrap_or(0)>0; if is_friend { let _=sqlx::query("INSERT OR IGNORE INTO room_members(room_id,user_id) VALUES(?,?)").bind(&id).bind(friend_id).execute(&mut *tx).await; } } tx.commit().await.map_err(|_| ApiError::bad("채팅방을 만들지 못했습니다."))?; Ok(Json(json!({"id":id}))) }
async fn room_access(db: &SqlitePool, room_id: &str, user_id: &str) -> bool { sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM room_members WHERE room_id=? AND user_id=?").bind(room_id).bind(user_id).fetch_one(db).await.unwrap_or(0) > 0 }
async fn messages(State(state): State<AppState>, headers: HeaderMap, Path(room_id): Path<String>) -> Result<Json<Vec<MessageView>>, (StatusCode, Json<ApiError>)> { let user = user_for(&headers, &state).await?; if !room_access(&state.db, &room_id, &user.id).await { return Err(ApiError::unauthorized()); } let rows = sqlx::query_as::<_, MessageView>("SELECT m.id,u.name sender,(m.sender_id=?) mine,m.body,m.created_at created FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.room_id=? ORDER BY m.created_at ASC").bind(&user.id).bind(room_id).fetch_all(&state.db).await.map_err(|_| ApiError::bad("메시지를 읽지 못했습니다."))?; Ok(Json(rows)) }
async fn send_message(State(state): State<AppState>, headers: HeaderMap, Path(room_id): Path<String>, Json(input): Json<NewMessage>) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> { let user = user_for(&headers, &state).await?; let body = input.body.trim(); if body.is_empty() || body.chars().count() > 1000 { return Err(ApiError::bad("메시지는 1~1000자로 입력해 주세요.")); } if !room_access(&state.db, &room_id, &user.id).await { return Err(ApiError::unauthorized()); } let id=Uuid::new_v4().to_string(); sqlx::query("INSERT INTO messages(id,room_id,sender_id,body,created_at) VALUES(?,?,?,?,?)").bind(&id).bind(room_id).bind(user.id).bind(body).bind(now()).execute(&state.db).await.map_err(|_| ApiError::bad("메시지를 보내지 못했습니다."))?; Ok(Json(json!({"id":id}))) }
async fn create_agreement(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<NewAgreement>) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> { let user = user_for(&headers, &state).await?; if input.task.trim().is_empty() || input.my_understanding.trim().is_empty() || input.their_understanding.trim().is_empty() { return Err(ApiError::bad("할 일과 양측의 이해 내용을 입력해 주세요.")); } if !room_access(&state.db, &input.room_id, &user.id).await { return Err(ApiError::unauthorized()); } let id=Uuid::new_v4().to_string(); sqlx::query("INSERT INTO agreements(id,room_id,created_by,task,my_understanding,their_understanding,deadline) VALUES(?,?,?,?,?,?,?)").bind(&id).bind(input.room_id).bind(user.id).bind(input.task.trim()).bind(input.my_understanding.trim()).bind(input.their_understanding.trim()).bind(input.deadline).execute(&state.db).await.map_err(|_| ApiError::bad("공동 확인을 만들지 못했습니다."))?; Ok(Json(json!({"id":id}))) }
async fn create_appointment(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<NewAppointment>) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> { let user = user_for(&headers, &state).await?; if input.title.trim().is_empty() || input.starts_at.trim().is_empty() { return Err(ApiError::bad("약속 제목과 시간을 입력해 주세요.")); } let id=Uuid::new_v4().to_string(); sqlx::query("INSERT INTO appointments(id,user_id,title,starts_at,place) VALUES(?,?,?,?,?)").bind(&id).bind(user.id).bind(input.title.trim()).bind(input.starts_at).bind(input.place).execute(&state.db).await.map_err(|_| ApiError::bad("약속을 저장하지 못했습니다."))?; Ok(Json(json!({"id":id}))) }
async fn analyze(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<AnalyzeRequest>) -> Result<Json<Analysis>, (StatusCode, Json<ApiError>)> { let _ = user_for(&headers, &state).await?; let text=input.text.trim(); if text.is_empty() || text.chars().count()>800 { return Err(ApiError::bad("분석할 메시지를 1~800자로 입력해 주세요.")); } let analysis = if let Some(key)=&state.openai_key { openai_analyze(text, input.relationship.as_deref(), key, &state.openai_model).await.unwrap_or_else(|_| local_analysis(text)) } else { local_analysis(text) }; Ok(Json(analysis)) }
async fn openai_analyze(text: &str, relationship: Option<&str>, key: &str, model: &str) -> anyhow::Result<Analysis> {
    let instructions = format!("You are Re:Tone, a Korean teen communication coach. Analyze a message before it is sent. Preserve the user's intended meaning. Do not shame, diagnose, or choose for the user. Write every value in Korean. Message relationship: {}. Produce exactly three suggestions: 부드럽게, 분명하게, 친근하게.", relationship.unwrap_or("not specified"));
    let schema = json!({"type":"object","additionalProperties":false,"properties":{"message_type":{"type":"string"},"emotion":{"type":"string"},"intent":{"type":"string"},"risk":{"type":"string"},"suggestions":{"type":"array","minItems":3,"maxItems":3,"items":{"type":"object","additionalProperties":false,"properties":{"label":{"type":"string"},"text":{"type":"string"}},"required":["label","text"]}},"rehearsal":{"type":"string"},"missing_details":{"type":"array","items":{"type":"string"}},"check_questions":{"type":"array","items":{"type":"string"}}},"required":["message_type","emotion","intent","risk","suggestions","rehearsal","missing_details","check_questions"]});
    let value: Value = reqwest::Client::new().post("https://api.openai.com/v1/responses")
        .bearer_auth(key).json(&json!({"model":model,"instructions":instructions,"input":text,"text":{"format":{"type":"json_schema","name":"retone_analysis","strict":true,"schema":schema}},"store":false}))
        .send().await?.error_for_status()?.json().await?;
    let raw = value["output"][0]["content"][0]["text"].as_str().context("missing OpenAI response text")?;
    Ok(serde_json::from_str(raw)?)
}
fn local_analysis(text: &str) -> Analysis { let urgent=text.contains('왜')||text.contains('빨리')||text.contains('지금'); let hostile=["바보","싫어","짜증","미쳤","꺼져","버러지"].iter().any(|w| text.contains(w)); let request=text.contains('해줘')||text.contains('부탁')||text.contains('?'); let missing=if request { vec!["대상·기한·방법이 충분히 구체적인지 확인해 보세요.".into()] } else { vec![] }; let base=text.trim_end_matches(['!','?','.']); Analysis { message_type: if request {"부탁·질문".into()} else {"의견·감정 전달".into()}, emotion: if hostile {"답답함 또는 화남이 느껴질 수 있어요".into()} else if urgent {"급한 마음이 전달될 수 있어요".into()} else {"차분한 표현이에요".into()}, intent: "내 생각을 전달하고 상대의 반응을 확인하려는 의도로 보여요.".into(), risk: if hostile||urgent {"상대가 압박이나 비난으로 받아들일 가능성이 있어요.".into()} else {"큰 오해 위험은 낮지만 맥락을 덧붙이면 더 분명해져요.".into()}, suggestions: vec![Suggestion{label:"부드럽게".into(),text:format!("시간 괜찮을 때 {base}에 대해 이야기해 줄 수 있을까?")},Suggestion{label:"분명하게".into(),text:format!("{base}에 대해 오늘 안에 확인이 필요해. 가능할지 알려줘.")},Suggestion{label:"친근하게".into(),text:format!("{base} 관련해서 잠깐만 도와줄래? 고마워!")}], rehearsal:"상대는 갑작스러운 요구보다 이유와 선택할 시간을 함께 들으면 더 편하게 답할 수 있어요.".into(), missing_details: missing, check_questions: if request {vec!["언제까지 답이 필요한가요?".into(),"무엇을, 어떤 방법으로 해주면 될까요?".into()]} else {vec!["상대가 알아야 할 배경이 있나요?".into()]}, } }

