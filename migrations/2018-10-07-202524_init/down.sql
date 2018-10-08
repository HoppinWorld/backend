ALTER TABLE `replay` DROP FOREIGN KEY `replay_fk0`;

ALTER TABLE `score` DROP FOREIGN KEY `score_fk0`;

ALTER TABLE `score` DROP FOREIGN KEY `score_fk1`;

ALTER TABLE `score` DROP FOREIGN KEY `score_fk2`;

ALTER TABLE `user_stat` DROP FOREIGN KEY `user_stat_fk0`;

ALTER TABLE `user_badge` DROP FOREIGN KEY `user_badge_fk0`;

ALTER TABLE `user_badge` DROP FOREIGN KEY `user_badge_fk1`;

ALTER TABLE `password_reset` DROP FOREIGN KEY `password_reset_fk0`;

ALTER TABLE `user_role` DROP FOREIGN KEY `user_role_fk0`;

ALTER TABLE `user_role` DROP FOREIGN KEY `user_role_fk1`;

DROP TABLE IF EXISTS `user`;

DROP TABLE IF EXISTS `role`;

DROP TABLE IF EXISTS `map`;

DROP TABLE IF EXISTS `replay`;

DROP TABLE IF EXISTS `score`;

DROP TABLE IF EXISTS `user_stat`;

DROP TABLE IF EXISTS `badge`;

DROP TABLE IF EXISTS `user_badge`;

DROP TABLE IF EXISTS `password_reset`;

DROP TABLE IF EXISTS `user_role`;

DROP TABLE IF EXISTS `season`;
