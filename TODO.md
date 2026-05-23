# Aviation SMS ERP - Run & Fix Routes (End-to-End)

## Step 1: Initial verification
- [ ] Run `python app.py` and capture traceback/errors
- [ ] Fix any startup/import/config issues

## Step 2: Model ↔ Route ↔ Template alignment
- [ ] Align `EmergencyResponsePlan` SQLAlchemy model fields with what routes/templates expect (`plan_name`, `description`, `coordinator`, `phone`, optional `erp_image`)
- [ ] Verify other model field names used by routes/templates (HazardReport, OccurrenceReport, SafetyObjective, SafetyDrill, EmergencyDrill, RiskAssessment, etc.)

## Step 3: Database/schema consistency
- [ ] Ensure tables exist / schema matches models
- [ ] If needed for dev: delete or recreate `aviation_sms_erp.db` or use migrations

## Step 4: End-to-end route smoke tests
- [ ] `/login` (GET/POST)
- [ ] `/dashboard`
- [ ] `/erp/new` (create)
- [ ] `/erp/update` (update)
- [ ] `/erp/list`
- [ ] `/export/excel`, `/export/pdf`, `/export/erp/pdf`, `/export/risk/excel`
- [ ] `/risk/new`, `/risk/assessment`, `/risk/assessment/new`
- [ ] `/hazard/report`, `/hazard/assess/<id>`, `/hazard/close/<id>`, `/hazard/report/list`
- [ ] `/occurrence/report`, `/occurrence/form`
- [ ] `/inventory`
- [ ] `/drills`, `/drills/add`, `/drills/edit/<id>`
- [ ] `/manage_objectives`, `/delete_objective/<id>`

## Step 5: Uploads/static paths
- [ ] Ensure upload directories exist for ERP images and drill photos
- [ ] Ensure any “static/uploads/...” paths match template usage

## Step 6: Final verification
- [ ] Re-run `python app.py`
- [ ] Confirm all smoke tests render without template errors and persist data correctly
