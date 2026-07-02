import os
import sys
import logging
from contextlib import closing

import psycopg2
from psycopg2 import sql

# Ensure project root is on path (harmless if not used)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

logger = logging.getLogger("sync_all_tables")

# --- Expected schema (production) ---
# Notes:
# - We must not drop/rename columns; only create missing tables/columns.
# - For emergency_response_plan, certain column names are quoted PascalCase.
EXPECTED_TABLES = [
    # 1) public.tenant
    {
        "schema": "public",
        "table": "tenant",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("company_name", "TEXT", None),
            ("track_audits", "BOOLEAN", None),
            ("track_risk_management", "BOOLEAN", None),
        ],
        "fks": [],
    },

    # 2) public.user (id SERIAL PRIMARY KEY)
    {
        "schema": "public",
        "table": "user",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("tenant_id", "INTEGER", None),
        ],
        "fks": [
            ("tenant_id", "public", "tenant", "id"),
        ],
    },

    # 3) public.risk_assessment (standard columns as currently used by app)
    {
        "schema": "public",
        "table": "risk_assessment",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("hazard_description", "TEXT", None),
            ("probability", "INTEGER", None),
            ("severity", "INTEGER", None),
            ("risk_level", "TEXT", None),
            ("mitigation_plan", "TEXT", None),
        ],
        "fks": [],
    },

    # 3) public.safety_policy
    {
        "schema": "public",
        "table": "safety_policy",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("safety_objectives", "TEXT", None),
            ("description", "TEXT", None),
            ("implementation_status", "TEXT", None),
            ("manual_filename", "TEXT", None),
            ("implementation_date", "DATE", None),
            ("user_id", "INTEGER", None),
        ],
        "fks": [
            ("user_id", "public", "user", "id"),
        ],
    },

    # 4) public.safety_assurance
    {
        "schema": "public",
        "table": "safety_assurance",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("audit_date", "DATE", None),
            ("finding_details", "TEXT", None),
            ("status", "TEXT", None),
            ("next_audit_date", "DATE", None),
            ("user_id", "INTEGER", None),

            # Notification / email dispatch targets (used by app.py + templates)
            ("auditee_email", "VARCHAR(255)", None),
            ("notification_body", "TEXT", None),
            ("checklist_name", "VARCHAR(255)", None),
            ("checklist_data", "BYTEA", None),
            ("audit_scope", "VARCHAR(255)", None),
            ("target_month", "VARCHAR(255)", None),
            ("department_notified", "BOOLEAN", None),

            # Public auditee response security (used by token routes)
            ("public_respond_token", "VARCHAR(255)", None),
            ("public_respond_token_expires_at", "TIMESTAMP", None),

            # Auditee response / closure fields (used by public response + admin)
            ("auditee_responder_name", "VARCHAR(255)", None),
            ("auditee_remarks", "TEXT", None),
            ("proposed_alternative_date", "DATE", None),
            ("description_of_conformance", "TEXT", None),
            ("root_causes", "TEXT", None),
            ("immediate_corrective_action", "TEXT", None),
            ("system_alteration", "TEXT", None),
            ("auditee_signature_name", "VARCHAR(255)", None),
            ("auditee_signed_date", "DATE", None),

            # Audit plan/checklist persistence attachments (used by downloads + email)
            ("audit_plan_filename", "VARCHAR(255)", None),
            ("audit_plan_data", "BYTEA", None),

        ],
        "fks": [
            ("user_id", "public", "user", "id"),
        ],
    },

    # 5) public.safety_promotion
    {
        "schema": "public",
        "table": "safety_promotion",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("bulletin_title", "TEXT", None),
            ("content", "TEXT", None),
            ("training_records", "TEXT", None),
            ("date_published", "DATE", None),
            ("user_id", "INTEGER", None),
        ],
        "fks": [
            ("user_id", "public", "user", "id"),
        ],
    },

    # 6) public.emergency_response_plan
    {
        "schema": "public",
        "table": "emergency_response_plan",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            # PascalCase quoted names
            ('"PlanName"', "TEXT", None),
            ('"LastDrillDate"', "DATE", None),
            ('"NextDrillDate"', "DATE", None),
            ('"Status"', "TEXT", None),
            ('"Observations"', "TEXT", None),
        ],
        "fks": [],
    },

    # 7) public.hazard_report
    {
        "schema": "public",
        "table": "hazard_report",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("report_no", "TEXT", None),
            ("date_reported", "TIMESTAMP", None),
            ("taxonomy_specific", "TEXT", None),
            ("unsafe_event", "TEXT", None),
            ("inherent_risk_score", "INTEGER", None),
            ("safety_actions", "TEXT", None),
            ("status", "TEXT", None),
            ("reporter_email", "TEXT", None),
        ],
        "fks": [],
    },

    # 8) public.occurrence_report
    {
        "schema": "public",
        "table": "occurrence_report",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("report_no", "TEXT", None),
            ("date_reported", "TIMESTAMP", None),
            ("reporter_name", "TEXT", None),
            ("location", "TEXT", None),
            ("description", "TEXT", None),
            ("personnel_injured", "INTEGER", None),
            ("equipment_damaged", "INTEGER", None),
            ("immediate_action", "TEXT", None),
            ("severity", "INTEGER", None),
            ("probability", "INTEGER", None),
            ("risk_score", "INTEGER", None),
            ("corrective_action", "TEXT", None),
            ("residual_risk", "INTEGER", None),
            ("actual_close_date", "DATE", None),
            ("status", "TEXT", None),
            ("feedback_given", "BOOLEAN", None),
            ("closure_comment", "TEXT", None),
            ("root_cause", "TEXT", None),
            ("system_alteration", "TEXT", None),
            ("resp_manager", "TEXT", None),
            ("reporter_feedback", "TEXT", None),
            ("feedback_date", "DATE", None),
        ],
        "fks": [],
    },

    # 9) public.safety_objective
    {
        "schema": "public",
        "table": "safety_objective",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("customer_no", "TEXT", None),
            ("operator_id", "TEXT", None),
            ("text", "TEXT", None),
        ],
        "fks": [],
    },

    # 10) public.safety_drill
    {
        "schema": "public",
        "table": "safety_drill",
        "columns": [
            ("id", "SERIAL", "PRIMARY KEY"),
            ("drill_type", "TEXT", None),
            ("custom_name", "TEXT", None),
            ("observations", "TEXT", None),
            ("date_conducted", "DATE", None),
        ],
        "fks": [],
    },
]


def _get_database_url() -> str:
    db_url = os.environ.get("DATABASE_URL") or os.environ.get("SQLALCHEMY_DATABASE_URI")
    if not db_url:
        raise RuntimeError(
            "Database URL missing. Provide DATABASE_URL (preferred) or SQLALCHEMY_DATABASE_URI in the environment."
        )

    # Trim any accidental whitespace (this fixes cases like /postgres<space>)
    db_url = db_url.strip()

    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    return db_url


def _configure_logging():
    # Vercel/stdout friendly
    level = os.environ.get("SYNC_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [sync_all_tables] %(message)s",
    )


def _table_exists(conn, schema: str, table: str) -> bool:
    q = """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = %s AND table_name = %s
        LIMIT 1
    """
    with conn.cursor() as cur:
        cur.execute(q, (schema, table))
        return cur.fetchone() is not None


def _column_exists(conn, schema: str, table: str, column_name: str) -> bool:
    """
    column_name should be the exact stored identifier name (case-sensitive for quoted identifiers).
    """
    q = """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s AND column_name = %s
        LIMIT 1
    """
    with conn.cursor() as cur:
        cur.execute(q, (schema, table, column_name))
        return cur.fetchone() is not None


def _parse_ident_for_column(column_def):
    """
    Column definitions include a "raw name" string. For emergency_response_plan we used
    entries like '"PlanName"' to indicate quoted identifier intent.
    Returns:
      (identifier_for_sql, column_name_for_information_schema_lookup)
    """
    name, col_type, pk = column_def
    if name.startswith('"') and name.endswith('"'):
        # information_schema stores the unquoted identifier in column_name,
        # preserving case (e.g. PlanName)
        column_name = name[1:-1]
        return sql.Identifier(column_name), column_name
    # normal lower_snake column names
    return sql.Identifier(name), name


def _add_column_if_missing(conn, schema: str, table: str, column_def):
    col_ident, column_name = _parse_ident_for_column(column_def)
    _, col_type, pk = column_def

    if _column_exists(conn, schema, table, column_name):
        return

    # Postgres allows IF NOT EXISTS on ADD COLUMN.
    # We keep it simple and idempotent.
    stmt = sql.SQL("ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS {} {}").format(
        sql.Identifier(schema),
        sql.Identifier(table),
        col_ident,
        sql.SQL(col_type),
    )

    # Primary keys/constraints handled at CREATE TABLE time only.
    if pk:
        logger.info("Skipping PK flag for ADD COLUMN (%s.%s.%s) because existing PK cannot be safely re-applied.", schema, table, column_name)

    with conn.cursor() as cur:
        cur.execute(stmt)
    conn.commit()
    logger.info("Added column %s.%s.%s (%s)", schema, table, column_name, col_type)


def _ensure_foreign_keys(conn, schema: str, table: str, fks: list):
    """
    fks items: (local_col, ref_schema, ref_table, ref_col)
    Creates FK constraint only if it doesn't already exist.
    """
    if not fks:
        return

    # Constraint name: deterministic and unlikely to collide.
    # If you already have a different constraint name, we avoid duplicating via existence check.
    for local_col, ref_schema, ref_table, ref_col in fks:
        local_col_ident = local_col
        # Find existing FK matching these columns.
        q = """
            SELECT 1
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
             AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_schema = %s
              AND tc.table_name = %s
              AND kcu.column_name = %s
            LIMIT 1
        """
        with conn.cursor() as cur:
            cur.execute(q, (schema, table, local_col_ident))
            if cur.fetchone() is not None:
                continue

        constraint_name = f"fk_{table}_{local_col}_to_{ref_table}_{ref_col}"

        stmt = sql.SQL("""
            ALTER TABLE {}.{}
            ADD CONSTRAINT {}
            FOREIGN KEY ({})
            REFERENCES {}.{} ({})
        """).format(
            sql.Identifier(schema),
            sql.Identifier(table),
            sql.Identifier(constraint_name),
            sql.Identifier(local_col_ident),
            sql.Identifier(ref_schema),
            sql.Identifier(ref_table),
            sql.Identifier(ref_col),
        )

        with conn.cursor() as cur:
            cur.execute(stmt)
        conn.commit()
        logger.info("Created FK constraint %s on %s.%s(%s)", constraint_name, schema, table, local_col_ident)


def _create_table_if_missing(conn, schema: str, table: str, columns: list, fks: list):
    if _table_exists(conn, schema, table):
        return

    # Build CREATE TABLE
    col_sql_parts = []
    for col_def in columns:
        col_ident, _column_name = _parse_ident_for_column(col_def)
        _name, col_type, pk = col_def

        # For quoted columns we used Identifier(column_name)
        part = sql.SQL("{} {}").format(col_ident, sql.SQL(col_type))
        if pk:
            part = sql.SQL("{} PRIMARY KEY").format(col_ident)
        col_sql_parts.append(part)

    create_stmt = sql.SQL("CREATE TABLE IF NOT EXISTS {}.{} ({} )").format(
        sql.Identifier(schema),
        sql.Identifier(table),
        sql.SQL(", ").join(col_sql_parts),
    )

    with conn.cursor() as cur:
        cur.execute(create_stmt)
    conn.commit()
    logger.info("Created missing table %s.%s", schema, table)

    # Add FKs after create
    _ensure_foreign_keys(conn, schema, table, fks)


def _sync_table(conn, table_def: dict):
    schema = table_def["schema"]
    table = table_def["table"]
    columns = table_def["columns"]
    fks = table_def.get("fks", [])

    # Create missing table (includes PKs, but not FKs)
    _create_table_if_missing(conn, schema, table, columns, fks)

    # Ensure columns exist (idempotent)
    for col_def in columns:
        _add_column_if_missing(conn, schema, table, col_def)

    # Ensure FK constraints exist (only if table existed/was created)
    _ensure_foreign_keys(conn, schema, table, fks)


def main():
    _configure_logging()
    logger.info("Starting production schema sync (tables/columns verification)")

    db_url = _get_database_url()
    conn = None
    try:
        conn = psycopg2.connect(db_url, connect_timeout=10)
        conn.autocommit = False

        with conn:
            with closing(conn.cursor()) as cur:
                pass

            for table_def in EXPECTED_TABLES:
                _sync_table(conn, table_def)

        logger.info("Schema sync complete.")
    except Exception as e:
        logger.exception("Schema sync FAILED: %s", e)
        raise
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    main()
