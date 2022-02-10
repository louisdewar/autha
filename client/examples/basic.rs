use autha_client::{flow::FlowResponse, jwt::Scope, Client};

#[tokio::main]
async fn main() {
    let client = Client::new(
        "http://localhost:8080".parse().unwrap(),
        "AUTHA_DEV_SHARED_SECRET".into(),
    )
    .await
    .unwrap();

    let response = client
        .provider_flow(
            "password",
            "register",
            serde_json::json!({
                "email": "test@email.com",
                "username": "testuser",
                "password": "testpassword"
            }),
            None,
        )
        .await
        .unwrap();
    dbg!(&response);

    let response = client.make_admin_by_id(1).await.unwrap();
    dbg!(&response);

    let response = client
        .provider_flow(
            "password",
            "login",
            serde_json::json!({
                "username_or_email": "testuser",
                "password": "testpassword"
            }),
            None,
        )
        .await
        .unwrap();
    dbg!(&response);

    let refresh_token = if let Ok(FlowResponse::Authenticated {
        user,
        refresh_token,
    }) = response
    {
        let token = client.verify_jwt(&refresh_token).unwrap();
        dbg!(user);
        dbg!(&token);
        assert!(token.has_scope(&Scope::Refresh));
        refresh_token
    } else {
        panic!("failed to authentiate user")
    };

    let response = client.authorize(refresh_token).await.unwrap();
    dbg!(&response);
}
