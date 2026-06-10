# TODO - Safety Assurance 500 Fix

- [x] Update `models.py` to use the definitive `SafetyAssurance` model class (matching requested fields and nullability).
- [x] Update `app.py` route `POST /safety/assurance`:
  - [ ] Add bulletproof `parse_date(date_str)` that safely converts flatpickr string formats (and also supports datetime-local ISO).
  - [ ] Save uploaded `audit_plan` safely with directory creation and `request.files.get('audit_plan')`.
  - [ ] Map checkbox explicitly: `dept_notified = True if request.form.get('department_notified') else False`.
  - [ ] Wrap `db.session.add()` and `db.session.commit()` in `try/except` and print `DATABASE ERROR: ...`.
- [x] Update `templates/safety_assurance.html` to ensure form fields submit consistent data (especially checkbox and date input expectations).
- [ ] Smoke test: submit Safety Assurance form and verify no 500; verify audit_date/next_audit_date parsing, checkbox mapping, and file save.
