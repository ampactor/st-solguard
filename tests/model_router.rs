use st_solguard::llm::{LlmClient, ModelRouter, Provider, TaskKind};

#[test]
fn default_client_returned_when_no_override() {
    let client = LlmClient::new(
        Provider::OpenRouter,
        "key".into(),
        "default-model".into(),
        100,
        Some("http://localhost:1".into()),
    )
    .unwrap();
    let router = ModelRouter::new(client);
    assert_eq!(
        router.client_for(TaskKind::Validation).model(),
        "default-model"
    );
    assert_eq!(
        router.client_for(TaskKind::CrossReference).model(),
        "default-model"
    );
}

#[test]
fn override_returns_custom_client() {
    let default = LlmClient::new(
        Provider::OpenRouter,
        "key".into(),
        "default-model".into(),
        100,
        Some("http://localhost:1".into()),
    )
    .unwrap();
    let custom = LlmClient::new(
        Provider::Anthropic,
        "key".into(),
        "custom-model".into(),
        100,
        Some("http://localhost:1".into()),
    )
    .unwrap();
    let router = ModelRouter::new(default).with_client(TaskKind::Validation, custom);

    assert_eq!(
        router.client_for(TaskKind::Validation).model(),
        "custom-model"
    );
    assert_eq!(
        router.client_for(TaskKind::CrossReference).model(),
        "default-model"
    );
}
