CREATE TABLE `user` (
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(64) NOT NULL UNIQUE,
	`email` varchar(64) NOT NULL UNIQUE,
	`password` varchar(64),
	`token` varchar(64),
	PRIMARY KEY (`id`)
);

CREATE TABLE `role` (
	`id` int NOT NULL AUTO_INCREMENT,
	`friendly_name` varchar(64) NOT NULL,
	`display_name` varchar(64) NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `map` (
	`id` int NOT NULL AUTO_INCREMENT,
	`status` varchar(64) NOT NULL,
	`name` varchar(64) NOT NULL,
	`segment_count` bit NOT NULL,
	`path` varchar(64),
	PRIMARY KEY (`id`)
);

CREATE TABLE `replay` (
	`id` int NOT NULL AUTO_INCREMENT,
	`scoreid` int NOT NULL,
	`path` varchar(64) NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `score` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`mapid` int NOT NULL,
	`segment_times` varchar(64) NOT NULL,
	`strafes` int,
	`jumps` int,
	`total_time` FLOAT NOT NULL,
	`max_speed` FLOAT NOT NULL,
	`average_speed` FLOAT NOT NULL,
	`season` int NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `user_stat` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`jumps` bigint NOT NULL DEFAULT '0',
	`strafes` bigint NOT NULL DEFAULT '0',
	PRIMARY KEY (`id`)
);

CREATE TABLE `badge` (
	`id` int NOT NULL AUTO_INCREMENT,
	`friendly_name` varchar(64) NOT NULL,
	`display_name` varchar(64) NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `user_badge` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`badgeid` int NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `password_reset` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`token` varchar(64) NOT NULL,
	`valid_until` DATETIME NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `user_role` (
	`id` int NOT NULL AUTO_INCREMENT,
	`userid` int NOT NULL,
	`roleid` int NOT NULL,
	PRIMARY KEY (`id`)
);

CREATE TABLE `season` (
	`id` int NOT NULL AUTO_INCREMENT,
	`display_name` varchar(64) NOT NULL UNIQUE,
	`friendly_name` varchar(64) NOT NULL UNIQUE,
	`ends_at` DATETIME,
	PRIMARY KEY (`id`)
);

ALTER TABLE `replay` ADD CONSTRAINT `replay_fk0` FOREIGN KEY (`scoreid`) REFERENCES `score`(`id`);

ALTER TABLE `score` ADD CONSTRAINT `score_fk0` FOREIGN KEY (`userid`) REFERENCES `user`(`id`);

ALTER TABLE `score` ADD CONSTRAINT `score_fk1` FOREIGN KEY (`mapid`) REFERENCES `map`(`id`);

ALTER TABLE `score` ADD CONSTRAINT `score_fk2` FOREIGN KEY (`season`) REFERENCES `season`(`id`);

ALTER TABLE `user_stat` ADD CONSTRAINT `user_stat_fk0` FOREIGN KEY (`userid`) REFERENCES `user`(`id`);

ALTER TABLE `user_badge` ADD CONSTRAINT `user_badge_fk0` FOREIGN KEY (`userid`) REFERENCES `user`(`id`);

ALTER TABLE `user_badge` ADD CONSTRAINT `user_badge_fk1` FOREIGN KEY (`badgeid`) REFERENCES `badge`(`id`);

ALTER TABLE `password_reset` ADD CONSTRAINT `password_reset_fk0` FOREIGN KEY (`userid`) REFERENCES `user`(`id`);

ALTER TABLE `user_role` ADD CONSTRAINT `user_role_fk0` FOREIGN KEY (`userid`) REFERENCES `user`(`id`);

ALTER TABLE `user_role` ADD CONSTRAINT `user_role_fk1` FOREIGN KEY (`roleid`) REFERENCES `role`(`id`);
