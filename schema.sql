-- =====================================================================
-- DL Tracker — PostgreSQL schema
-- Driver's licence tracking: import, approval, payment, appointment,
-- attendance, delivery.
--
-- Currency is USD. Dates are stored as DATE; the day/month/year format
-- is a display concern, not a storage one.
--
-- The rules that must never be bypassed (payment before appointment,
-- approval before appointment, completion before delivery) are enforced
-- by triggers here, not only in the application. A bug in the browser,
-- a stray SQL statement or a future second client cannot get around them.
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------------
-- Reference data
-- ---------------------------------------------------------------------

CREATE TABLE company (
    id          integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code        text NOT NULL UNIQUE,          -- BMMC, CMC, MAPA, GLM, ...
    name        text,
    active      boolean NOT NULL DEFAULT true
);
COMMENT ON TABLE company IS 'Subsidiaries of the group. Rows are created automatically on import when a new code appears.';

INSERT INTO company (code, name) VALUES
    ('BMMC',     'Bea Mountain Mining Corporation'),
    ('CMC',      'CMC'),
    ('MAPA',     'MAPA'),
    ('GLM',      'GLM'),
    ('EVERETTE', 'Everette'),
    ('MNG GOLD', 'MNG Gold');

-- The fee matrix lives in the database so it can be changed without a
-- code release. effective_from lets an old batch keep the old prices.
CREATE TABLE fee_reference (
    license_type     text NOT NULL,            -- Chaffuer, Heavy Duty
    application_type text NOT NULL CHECK (application_type IN ('New', 'Renewal')),
    effective_from   date NOT NULL DEFAULT DATE '2020-01-01',
    license_fee      numeric(10,2) NOT NULL,
    process_fee      numeric(10,2) NOT NULL,
    eye_test_fee     numeric(10,2) NOT NULL,
    PRIMARY KEY (license_type, application_type, effective_from)
);
COMMENT ON TABLE fee_reference IS 'Expected fees. Used to flag mismatches on import; it never overwrites what the workbook says.';

INSERT INTO fee_reference (license_type, application_type, license_fee, process_fee, eye_test_fee) VALUES
    ('Chaffuer',   'Renewal',  45, 15, 3),
    ('Chaffuer',   'New',      45, 25, 3),
    ('Heavy Duty', 'Renewal', 100, 15, 3),
    ('Heavy Duty', 'New',     100, 25, 3);
-- The driving test fee is charged case by case and is deliberately not
-- part of the reference matrix.

-- ---------------------------------------------------------------------
-- People who use the system
-- ---------------------------------------------------------------------

CREATE TABLE app_user (
    id            integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email         text NOT NULL UNIQUE,
    full_name     text NOT NULL,
    role          text NOT NULL CHECK (role IN ('Admin', 'Approver', 'Officer', 'Viewer')),
    password_hash text NOT NULL,
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX ux_app_user_email_lower ON app_user (lower(email));
COMMENT ON COLUMN app_user.role IS 'Admin imports, approves, records payments, books and delivers. Approver only signs off batches. Officer only ticks at the licence office. Viewer is read only.';

-- Browser sessions. Opaque tokens, stored hashed, revocable by deleting
-- the row. No third-party token library needed.
CREATE TABLE app_session (
    token_hash text PRIMARY KEY,
    user_id    integer NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL DEFAULT now(),
    user_agent text
);
CREATE INDEX ix_session_user ON app_session (user_id);
CREATE INDEX ix_session_exp  ON app_session (expires_at);

-- ---------------------------------------------------------------------
-- Employees — one row per person, updated on every import
-- ---------------------------------------------------------------------

CREATE TABLE employee (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reg_no        text NOT NULL UNIQUE,
    company_id    integer NOT NULL REFERENCES company(id),
    name          text NOT NULL,
    surname       text NOT NULL,
    department    text,
    job_title     text,
    location      text,
    national_id   text,        -- text on purpose: passports (PP0057287) and leading zeros
    date_of_birth date,
    phone         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_employee_company  ON employee (company_id);
CREATE INDEX ix_employee_location ON employee (location);
CREATE INDEX ix_employee_national ON employee (national_id) WHERE national_id IS NOT NULL;
COMMENT ON COLUMN employee.national_id IS 'Never store as a number. Passport numbers and leading zeros must survive.';

-- ---------------------------------------------------------------------
-- Batches — one monthly workbook, signed off by the General Manager
-- ---------------------------------------------------------------------

CREATE TABLE batch (
    id                   integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                 text NOT NULL UNIQUE,          -- 'September 2026'
    source_file          text,
    imported_by          integer REFERENCES app_user(id),
    imported_at          timestamptz NOT NULL DEFAULT now(),
    approval_status      text NOT NULL DEFAULT 'Pending'
                         CHECK (approval_status IN ('Pending', 'Approved', 'Rejected')),
    gm_signed_on         date,                          -- the day the GM actually signed
    approval_recorded_by integer REFERENCES app_user(id),
    approval_recorded_at timestamptz,
    note                 text
);
COMMENT ON COLUMN batch.gm_signed_on IS 'Date on the General Manager''s approval. Separate from approval_recorded_at, which is when it was keyed in.';

-- An approved batch must carry the date it was signed.
ALTER TABLE batch ADD CONSTRAINT ck_batch_approved_needs_date
    CHECK (approval_status <> 'Approved' OR gm_signed_on IS NOT NULL);

-- ---------------------------------------------------------------------
-- Applications — one licence job for one person in one batch
-- ---------------------------------------------------------------------

CREATE TABLE application (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    batch_id              integer NOT NULL REFERENCES batch(id) ON DELETE CASCADE,
    employee_id           bigint  NOT NULL REFERENCES employee(id),

    license_type          text,                          -- Chaffuer / Heavy Duty
    application_type      text NOT NULL CHECK (application_type IN ('New', 'Renewal')),
    dl_no                 text,
    dl_class              text,                          -- filled at the licence office
    dl_expire_date        date,

    amount                numeric(10,2),
    process_fee           numeric(10,2),
    driving_test_fee      numeric(10,2),
    eye_test_fee          numeric(10,2),
    total                 numeric(10,2) GENERATED ALWAYS AS (
                              COALESCE(amount,0) + COALESCE(process_fee,0)
                            + COALESCE(driving_test_fee,0) + COALESCE(eye_test_fee,0)
                          ) STORED,

    payment_paid          boolean NOT NULL DEFAULT false,
    bill_number           text,
    payment_date          date,
    payment_recorded_by   integer REFERENCES app_user(id),

    appointment_date      date,
    appointment_set_by    integer REFERENCES app_user(id),

    delivered_on          date,
    delivered_by          integer REFERENCES app_user(id),

    -- Some people renew their own licence while the batch is in progress.
    -- The company pays nothing, so this closes the application without
    -- going through payment, appointment or the licence office.
    self_renewed_on       date,
    self_renewed_by       integer REFERENCES app_user(id),
    self_renewed_note     text,

    cancelled_at          timestamptz,
    cancel_reason         text,

    source_row            integer,      -- position in the workbook, for tracing
    note                  text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN application.application_type IS 'Derived on import: no DL NO means New, otherwise Renewal. Never taken from the TYPE column, which is the licence category.';
COMMENT ON COLUMN application.total IS 'Always amount + process + driving test + eye test. AMOUNT is not the total in the source workbook.';

-- A person may hold only one live application at a time. Delivered and
-- cancelled ones drop out, so next year's renewal is allowed.
CREATE UNIQUE INDEX ux_application_one_open_per_employee
    ON application (employee_id)
    WHERE delivered_on IS NULL AND cancelled_at IS NULL AND self_renewed_on IS NULL;

CREATE INDEX ix_application_batch       ON application (batch_id);
CREATE INDEX ix_application_appointment ON application (appointment_date) WHERE appointment_date IS NOT NULL;
CREATE INDEX ix_application_unpaid      ON application (batch_id) WHERE payment_paid = false;
CREATE INDEX ix_application_expiry      ON application (dl_expire_date);
CREATE INDEX ix_application_bill        ON application (bill_number) WHERE bill_number IS NOT NULL;

-- Payment details only make sense once payment is recorded.
ALTER TABLE application ADD CONSTRAINT ck_application_payment_date
    CHECK (payment_paid = false OR payment_date IS NOT NULL);

-- ---------------------------------------------------------------------
-- Events — append only. This is what makes offline ticking safe.
-- ---------------------------------------------------------------------

CREATE TABLE application_event (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_id  bigint NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    event_type      text NOT NULL CHECK (event_type IN
                        ('ATTENDED', 'COMPLETED', 'NO_SHOW', 'DELIVERED',
                         'PHOTO_FRONT', 'PHOTO_BACK')),
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    recorded_by     integer REFERENCES app_user(id),
    walk_in         boolean NOT NULL DEFAULT false,
    device          text,
    note            text,
    -- The phone generates this before it has a connection. Replaying the
    -- same queued event after a reconnect can never create a duplicate.
    client_event_id uuid UNIQUE
);
CREATE INDEX ix_event_application ON application_event (application_id, occurred_at);
COMMENT ON COLUMN application_event.occurred_at IS 'When it happened at the office. recorded_at is when it reached the server — they differ when the phone was offline.';
COMMENT ON COLUMN application_event.walk_in IS 'True when the person was served on a day other than their appointment.';

-- ---------------------------------------------------------------------
-- Licence photographs — front and back
-- ---------------------------------------------------------------------

CREATE TABLE application_photo (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_id bigint NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    side           text NOT NULL CHECK (side IN ('front', 'back')),
    mime_type      text NOT NULL DEFAULT 'image/jpeg',
    bytes          bytea NOT NULL,
    size_bytes     integer NOT NULL,
    width          integer,
    height         integer,
    uploaded_by    integer REFERENCES app_user(id),
    uploaded_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, side)      -- retaking replaces
);
COMMENT ON TABLE application_photo IS 'Images are downscaled to 1280px and JPEG-compressed by the phone before upload, roughly 150 KB each.';

-- ---------------------------------------------------------------------
-- Import and audit history
-- ---------------------------------------------------------------------

CREATE TABLE import_log (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    batch_id      integer REFERENCES batch(id) ON DELETE SET NULL,
    file_name     text,
    sheet_name    text,
    rows_read     integer,
    rows_imported integer,
    rows_blocked  integer,
    findings      jsonb,                 -- the full validation report
    imported_by   integer REFERENCES app_user(id),
    imported_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    user_id     integer REFERENCES app_user(id),
    action      text NOT NULL,          -- PAYMENT_RECORDED, APPOINTMENT_SET, ...
    entity      text NOT NULL,
    entity_id   bigint,
    detail      jsonb
);
CREATE INDEX ix_audit_at ON audit_log (at DESC);

-- ---------------------------------------------------------------------
-- Gates. These are the rules that cannot be bypassed.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_application_gates() RETURNS trigger AS $$
DECLARE
    v_status text;
    v_done   boolean;
BEGIN
    -- Booking an appointment needs an approved batch and a recorded payment.
    IF NEW.appointment_date IS NOT NULL
       AND (TG_OP = 'INSERT' OR NEW.appointment_date IS DISTINCT FROM OLD.appointment_date) THEN

        -- most specific reason first, so the message is the useful one
        IF NEW.self_renewed_on IS NOT NULL THEN
            RAISE EXCEPTION 'Appointment refused: this person renewed their own licence'
                USING ERRCODE = 'check_violation';
        END IF;

        SELECT approval_status INTO v_status FROM batch WHERE id = NEW.batch_id;
        IF v_status <> 'Approved' THEN
            RAISE EXCEPTION 'Appointment refused: batch is % , not Approved', v_status
                USING ERRCODE = 'check_violation';
        END IF;

        IF NOT NEW.payment_paid THEN
            RAISE EXCEPTION 'Appointment refused: payment not recorded'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    -- Handing the licence over needs the office to have completed it.
    IF NEW.delivered_on IS NOT NULL
       AND (TG_OP = 'INSERT' OR NEW.delivered_on IS DISTINCT FROM OLD.delivered_on) THEN

        SELECT EXISTS (SELECT 1 FROM application_event
                       WHERE application_id = NEW.id AND event_type = 'COMPLETED')
          INTO v_done;
        IF NOT v_done THEN
            RAISE EXCEPTION 'Delivery refused: not marked completed at the licence office'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    -- Unpaying someone who is already booked would leave a booking behind.
    IF TG_OP = 'UPDATE' AND OLD.payment_paid AND NOT NEW.payment_paid
       AND NEW.appointment_date IS NOT NULL THEN
        RAISE EXCEPTION 'Cannot remove payment while an appointment is booked'
            USING ERRCODE = 'check_violation';
    END IF;

    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_application_gates
    BEFORE INSERT OR UPDATE ON application
    FOR EACH ROW EXECUTE FUNCTION fn_application_gates();

-- Nothing may be ticked at the licence office for an unpaid person.
CREATE OR REPLACE FUNCTION fn_event_gate() RETURNS trigger AS $$
DECLARE
    v_paid boolean;
BEGIN
    SELECT payment_paid INTO v_paid FROM application WHERE id = NEW.application_id;
    IF NOT v_paid THEN
        RAISE EXCEPTION 'Refused: payment not recorded for this person'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_event_gate
    BEFORE INSERT ON application_event
    FOR EACH ROW EXECUTE FUNCTION fn_event_gate();

CREATE OR REPLACE FUNCTION fn_photo_gate() RETURNS trigger AS $$
DECLARE
    v_paid boolean;
BEGIN
    SELECT payment_paid INTO v_paid FROM application WHERE id = NEW.application_id;
    IF NOT v_paid THEN
        RAISE EXCEPTION 'Refused: payment not recorded for this person'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_photo_gate
    BEFORE INSERT OR UPDATE ON application_photo
    FOR EACH ROW EXECUTE FUNCTION fn_photo_gate();

CREATE OR REPLACE FUNCTION fn_touch_employee() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_touch_employee
    BEFORE UPDATE ON employee
    FOR EACH ROW EXECUTE FUNCTION fn_touch_employee();

-- ---------------------------------------------------------------------
-- Views the application reads from
-- ---------------------------------------------------------------------

-- One flat row per application, with the status worked out. Status is
-- never stored, so it cannot drift out of step with the events.
CREATE VIEW v_application AS
SELECT
    a.id,
    a.batch_id,
    b.name              AS batch_name,
    b.approval_status,
    b.gm_signed_on,
    e.id                AS employee_id,
    e.reg_no,
    e.name,
    e.surname,
    e.name || ' ' || e.surname AS full_name,
    c.code              AS company,
    e.department,
    e.job_title,
    e.location,
    e.national_id,
    e.date_of_birth,
    e.phone,
    a.license_type,
    a.application_type,
    a.dl_no,
    a.dl_class,
    a.dl_expire_date,
    a.amount,
    a.process_fee,
    a.driving_test_fee,
    a.eye_test_fee,
    a.total,
    a.payment_paid,
    a.bill_number,
    a.payment_date,
    a.appointment_date,
    a.delivered_on,
    a.self_renewed_on,
    a.self_renewed_note,
    a.note,
    COALESCE(ev.attended,  false) AS attended,
    COALESCE(ev.completed, false) AS completed,
    COALESCE(ph.photo_count, 0)   AS photo_count,
    CASE
        WHEN a.cancelled_at IS NOT NULL              THEN 'Cancelled'
        WHEN a.self_renewed_on IS NOT NULL           THEN 'Self-renewed'
        WHEN a.delivered_on IS NOT NULL              THEN 'Delivered'
        WHEN COALESCE(ev.completed, false)           THEN 'Completed'
        WHEN ev.last_event = 'NO_SHOW'               THEN 'No show'
        WHEN COALESCE(ev.attended, false)            THEN 'Attended'
        WHEN a.appointment_date IS NOT NULL          THEN 'Scheduled'
        WHEN a.payment_paid                          THEN 'Paid'
        WHEN b.approval_status = 'Approved'          THEN 'Approved'
        ELSE 'Imported'
    END AS status
FROM application a
JOIN batch    b ON b.id = a.batch_id
JOIN employee e ON e.id = a.employee_id
JOIN company  c ON c.id = e.company_id
LEFT JOIN LATERAL (
    SELECT bool_or(event_type = 'ATTENDED')  AS attended,
           bool_or(event_type = 'COMPLETED') AS completed,
           (array_agg(event_type ORDER BY occurred_at DESC, id DESC))[1] AS last_event
    FROM application_event
    WHERE application_id = a.id
      AND event_type IN ('ATTENDED', 'COMPLETED', 'NO_SHOW')
) ev ON true
LEFT JOIN LATERAL (
    SELECT count(*) AS photo_count FROM application_photo WHERE application_id = a.id
) ph ON true;

-- Cumulative funnel: every stage counts everyone who has reached it, so
-- nobody drops off a stage by moving to the next one.
CREATE VIEW v_funnel AS
SELECT
    batch_id,
    batch_name,
    count(*)                                                      AS imported,
    count(*) FILTER (WHERE approval_status = 'Approved')           AS approved,
    count(*) FILTER (WHERE payment_paid)                           AS paid,
    count(*) FILTER (WHERE appointment_date IS NOT NULL)           AS booked,
    count(*) FILTER (WHERE attended OR completed)                  AS arrived,
    count(*) FILTER (WHERE completed)                              AS completed,
    count(*) FILTER (WHERE delivered_on IS NOT NULL)               AS delivered,
    count(*) FILTER (WHERE self_renewed_on IS NOT NULL)            AS self_renewed,
    count(*) FILTER (WHERE status = 'No show')                     AS no_show,
    count(*) FILTER (WHERE NOT payment_paid
                       AND self_renewed_on IS NULL)                AS unpaid,
    count(*) FILTER (WHERE self_renewed_on IS NULL
                       AND delivered_on IS NULL)                   AS still_open,
    sum(total) FILTER (WHERE payment_paid)                         AS collected,
    sum(total) FILTER (WHERE NOT payment_paid)                     AS outstanding,
    sum(total)                                                     AS programme_cost
FROM v_application
WHERE status <> 'Cancelled'
GROUP BY batch_id, batch_name;

-- Licences coming due, newest application per person only.
CREATE VIEW v_expiry_radar AS
SELECT DISTINCT ON (employee_id)
    employee_id, reg_no, full_name, company, department, location,
    license_type, dl_no, dl_expire_date, status,
    CASE
        WHEN dl_expire_date IS NULL                             THEN 'No date'
        WHEN dl_expire_date <  current_date                     THEN 'Overdue'
        WHEN dl_expire_date <= current_date + 30                THEN 'Within 30 days'
        WHEN dl_expire_date <= current_date + 90                THEN 'Within 90 days'
        ELSE 'Later'
    END AS bucket
FROM v_application
WHERE status <> 'Cancelled'
ORDER BY employee_id, dl_expire_date DESC NULLS LAST, id DESC;

-- What the licence office sees for a given day.
CREATE VIEW v_office_day AS
SELECT appointment_date, id, reg_no, full_name, company, department, location,
       license_type, application_type, payment_paid, status, photo_count
FROM v_application
WHERE appointment_date IS NOT NULL AND status <> 'Cancelled';

COMMIT;
