-- Your SQL goes here
ALTER TABLE map ADD COLUMN mapper int NOT NULL;
ALTER TABLE map ADD COLUMN difficulty varchar(32) NOT NULL;
ALTER TABLE map ADD COLUMN categories varchar(64) NOT NULL;
ALTER TABLE map ADD COLUMN tags varchar(64) NOT NULL;

ALTER TABLE `map` ADD CONSTRAINT `map_fk0` FOREIGN KEY (`mapper`) REFERENCES `user`(`id`);