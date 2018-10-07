-- Your SQL goes here
CREATE TABLE `User` (
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar NOT NULL,
	`email` varchar NOT NULL,
	`password` varchar NOT NULL,
	`token` varchar,
	PRIMARY KEY (`id`)
);

CREATE TABLE `Role` (
	`id` int NOT NULL AUTO_INCREMENT,
	`friendly_name` varchar NOT NULL,
	`display_name` varchar NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `Map` (
	`id` int NOT NULL AUTO_INCREMENT,
	`status` int NOT NULL,
	`name` varchar NOT NULL,
	`segment_count` bit NOT NULL,
	`path` varchar,
	PRIMARY KEY (`id`)
);

CREATE TABLE `Replay` (
	`id` int NOT NULL AUTO_INCREMENT,
	`scoreid` int NOT NULL,
	`path` varchar NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `Score` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`mapid` int NOT NULL,
	`segment_times` varchar NOT NULL,
	`strafes` int,
	`jumps` int,
	`total_time` FLOAT NOT NULL,
	`max_speed` FLOAT NOT NULL,
	`average_speed` FLOAT NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `MapStatus` (
	`id` int NOT NULL AUTO_INCREMENT,
	`friendly_name` varchar NOT NULL,
	`display_name` varchar NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `UserStat` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`jumps` bigint NOT NULL,
	`strafes` bigint NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `Badge` (
	`id` int NOT NULL AUTO_INCREMENT,
	`friendly_name` varchar NOT NULL,
	`display_name` varchar NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `UserBadge` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`badgeid` int NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `PasswordReset` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`token` varchar NOT NULL,
	`valid_until` DATETIME NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `UserRole` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`roleid` int NOT NULL,
	PRIMARY KEY (`id`)
);

ALTER TABLE `Map` ADD CONSTRAINT `Map_fk0` FOREIGN KEY (`status`) REFERENCES `MapStatus`(`id`);

ALTER TABLE `Replay` ADD CONSTRAINT `Replay_fk0` FOREIGN KEY (`scoreid`) REFERENCES `Score`(`id`);

ALTER TABLE `Score` ADD CONSTRAINT `Score_fk0` FOREIGN KEY (`userid`) REFERENCES `User`(`id`);

ALTER TABLE `Score` ADD CONSTRAINT `Score_fk1` FOREIGN KEY (`mapid`) REFERENCES `Map`(`id`);

ALTER TABLE `UserStat` ADD CONSTRAINT `UserStat_fk0` FOREIGN KEY (`userid`) REFERENCES `User`(`id`);

ALTER TABLE `UserBadge` ADD CONSTRAINT `UserBadge_fk0` FOREIGN KEY (`userid`) REFERENCES `User`(`id`);

ALTER TABLE `UserBadge` ADD CONSTRAINT `UserBadge_fk1` FOREIGN KEY (`badgeid`) REFERENCES `Badge`(`id`);

ALTER TABLE `PasswordReset` ADD CONSTRAINT `PasswordReset_fk0` FOREIGN KEY (`userid`) REFERENCES `User`(`id`);

ALTER TABLE `UserRole` ADD CONSTRAINT `UserRole_fk0` FOREIGN KEY (`userid`) REFERENCES `User`(`id`);

ALTER TABLE `UserRole` ADD CONSTRAINT `UserRole_fk1` FOREIGN KEY (`roleid`) REFERENCES `Role`(`id`);
