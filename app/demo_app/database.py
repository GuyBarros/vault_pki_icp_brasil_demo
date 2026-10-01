"""Read the demo table with the PostgreSQL role Vault just issued."""

from __future__ import annotations


def fetch_rows(connect, username: str, password: str, host: str, port: int, database: str, sslmode: str) -> dict:
    with connect(
        host=host,
        port=port,
        dbname=database,
        user=username,
        password=password,
        connect_timeout=3,
        sslmode=sslmode,
    ) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_user")
            current_user = cursor.fetchone()[0]
            cursor.execute("SELECT id, titulo, detalhe FROM registros ORDER BY id")
            rows = [
                {"id": row[0], "titulo": row[1], "detalhe": row[2]}
                for row in cursor.fetchall()
            ]
    return {"current_user": current_user, "rows": rows}


def connect_psycopg(**kwargs):
    import psycopg

    return psycopg.connect(**kwargs)
