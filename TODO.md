# TODO

## Login works but dashboard fails (Vercel 500)
### Root cause
`GET /dashboard` throws 500 due to missing DB table:
- `psycopg2.errors.UndefinedTable: relation "risk_assessment" does not exist`
- Triggered by: `risks = RiskAssessment.query.all()` in `/dashboard`

### Required fix
1. Ensure migrations have created all required tables in the **same PostgreSQL database** used by Vercel (`DATABASE_URL`).
2. Apply migrations against that DB so tables like `risk_assessment` exist.
3. Confirm that the `risk_assessment` table exists.

> Current proof: `/dashboard` crashes with `UndefinedTable: relation "risk_assessment" does not exist` at:
> `risks = RiskAssessment.query.all()`.

### Optional robustness improvement (recommended)
After DB is fixed, prevent the whole dashboard from crashing if any single table is missing:
- Wrap `/dashboard` queries in try/except (SQLAlchemyError / ProgrammingError),
- Default dashboard values (0 / empty lists),
- Optionally flash/log which table is missing.

### Diagnostic commands (local)
- `alembic current`
- `alembic upgrade head`
- Verify table existence via psql using `DATABASE_URL`.
