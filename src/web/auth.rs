use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ===== Credenciais Enterprise (padrão; alterável via variáveis de ambiente) =====
// ADMIN_USER / ADMIN_PASS sobrepõem os padrões abaixo
pub fn admin_user() -> String {
    std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string())
}

pub fn admin_pass() -> String {
    std::env::var("ADMIN_PASS").unwrap_or_else(|_| "enterprise2026".to_string())
}

fn jwt_secret() -> Vec<u8> {
    std::env::var("JWT_SECRET").map(|s| s.into_bytes()).unwrap_or_else(|_| {
        let mut h = Sha256::new();
        h.update(b"vuln-scanner-enterprise-jwt-secret-key-2026");
        h.finalize().to_vec()
    })
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

/// Verifica usuário/senha (password comparada via SHA-256 para não trafegar o texto puro em memória)
pub fn verify_credentials(user: &str, pass: &str) -> bool {
    let expected_user = admin_user();
    let expected_hash = hex_hash(&admin_pass());
    let given_hash = hex_hash(pass);
    user == expected_user && given_hash == expected_hash
}

pub fn hex_hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Emite um token JWT com validade de 8 horas
pub fn create_token(user: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user.to_string(),
        role: "admin".to_string(),
        exp: chrono::Utc::now().timestamp() as usize + 8 * 3600,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(&jwt_secret()))
}

/// Valida um token JWT e retorna as claims
pub fn verify_token(token: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .ok()
}

/// Extrai o token do header "Authorization: Bearer <token>"
pub fn bearer_token(auth_header: &str) -> Option<&str> {
    auth_header.strip_prefix("Bearer ").or_else(|| auth_header.strip_prefix("bearer "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let token = create_token("admin").unwrap();
        let claims = verify_token(&token).unwrap();
        assert_eq!(claims.sub, "admin");
    }
}
