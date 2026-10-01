CREATE TABLE IF NOT EXISTS registros (
    id integer PRIMARY KEY,
    titulo text NOT NULL,
    detalhe text NOT NULL
);

INSERT INTO registros (id, titulo, detalhe) VALUES
    (1, 'A1 profile', 'ICP-Brasil certificate stored in KV.'),
    (2, 'Service TLS', 'Short-lived certificate from the PKI secrets engine.'),
    (3, 'Dynamic credential', 'Read with a PostgreSQL role that Vault created for this lease.')
ON CONFLICT (id) DO NOTHING;
