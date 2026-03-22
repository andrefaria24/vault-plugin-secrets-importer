path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "secret/data/*" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/*" {
  capabilities = ["read"]
}
