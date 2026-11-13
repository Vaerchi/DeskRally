-- 0063: scheduled access windows (docs/57).
--
-- A membership may carry a weekly window: it grants only during [window_start, window_end) local
-- wall-clock minutes on window_days, in window_tz. All four NULL = any time, which every existing row
-- keeps (no backfill). GrantFor (pgstore.go) ANDs membership_window_open(...) at statement_timestamp()
-- into its docs/56 expiry filter, so the window is enforced on every authenticated request and every
-- session-lease renewal. ListUsers and the access summary evaluate it with the same function.
--
-- window_days is a bitmask, bit d = weekday d with 0 = Sunday (extract(dow), Go time.Weekday).
-- window_end <= window_start crosses midnight: open from window_start on a listed day until window_end on
-- the FOLLOWING day. window_end 1440 = end of day. The zone's validity depends on the tz database, so it
-- is not a CHECK: the write path requires an exact pg_timezone_names match, and the function below fails
-- CLOSED (false) on a zone it cannot evaluate rather than raising.

ALTER TABLE membership
    ADD COLUMN window_days  smallint,
    ADD COLUMN window_start smallint,
    ADD COLUMN window_end   smallint,
    ADD COLUMN window_tz    text,
    ADD CONSTRAINT membership_window_complete CHECK (
        (window_days IS NULL AND window_start IS NULL AND window_end IS NULL AND window_tz IS NULL)
     OR (window_days IS NOT NULL AND window_start IS NOT NULL AND window_end IS NOT NULL AND window_tz IS NOT NULL)),
    ADD CONSTRAINT membership_window_range CHECK (
        window_days IS NULL OR (window_days BETWEEN 1 AND 127
            AND window_start BETWEEN 0 AND 1439 AND window_end BETWEEN 1 AND 1440
            AND window_start <> window_end));

-- NOT STRICT: a NULL window is open. plpgsql so a bad zone denies this one membership instead of failing
-- the whole query (GrantFor keeps the user's other memberships; ListUsers keeps listing the row).
CREATE OR REPLACE FUNCTION membership_window_open(days smallint, s smallint, e smallint, tz text, at timestamptz)
RETURNS boolean
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog
AS $$
DECLARE
    lt timestamp;
    d  int;
    m  int;
BEGIN
    IF days IS NULL THEN
        RETURN true;
    END IF;
    BEGIN
        lt := at AT TIME ZONE tz;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    d := extract(dow FROM lt)::int;
    m := extract(hour FROM lt)::int * 60 + extract(minute FROM lt)::int;
    IF s < e THEN
        RETURN (days & (1 << d)) <> 0 AND m >= s AND m < e;
    END IF;
    RETURN ((days & (1 << d)) <> 0 AND m >= s) OR ((days & (1 << ((d + 6) % 7))) <> 0 AND m < e);
END;
$$;

COMMENT ON COLUMN membership.window_days IS
    'docs/57: weekly access window (bit d = weekday d, 0 = Sunday); NULL with window_start/end/tz = any '
    'time. Enforced by GrantFor via membership_window_open; never on Owner memberships.';
