-- This file should undo anything in `up.sql`

ALTER TABLE map DROP COLUMN mapper;
ALTER TABLE map DROP COLUMN difficulty;
ALTER TABLE map DROP COLUMN categories;
ALTER TABLE map DROP COLUMN tags;

ALTER TABLE `map` DROP CONSTRAINT `map_fk0`;