-- This file should undo anything in `up.sql`
alter table score modify column strafes integer;
alter table score modify column jumps integer;