ALTER TABLE dynamic_group
    ADD COLUMN match text NOT NULL DEFAULT 'all' CHECK (match IN ('all', 'any')),
    ADD COLUMN conditions jsonb NULL CHECK (jsonb_typeof(conditions) = 'array');

COMMENT ON TABLE dynamic_group IS
    'A saved, named machine predicate evaluated live over machines visible to the caller.';
