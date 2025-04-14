use crate::db::datastore_wrapper::DatastoreWrapper;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libtoken::Token;

#[derive(Debug)]
pub(crate) struct AuthHandler {
    app_id: String,
    app_secret: String,
    datastore: DatastoreWrapper,
    token: Option<Token>,
}

impl AuthHandler {
    pub fn new(app_id: String, app_secret: String, datastore: DatastoreWrapper) -> Self {
        Self {
            app_id,
            app_secret,
            datastore,
            token: None,
        }
    }

    pub async fn obtain_token_safe(&mut self) -> Result<String, Error> {
        if self.token.as_ref().is_none_or(Token::is_expired) {
            let jwt: String = self
                .datastore
                .login(self.app_id.clone(), self.app_secret.clone())
                .await?;

            let new_token = Token::from_jwt(jwt.as_str()).handle_err(location!())?;

            self.token = Some(new_token);
        }

        Ok(self.token.as_ref().unwrap().jwt.clone())
    }
}
