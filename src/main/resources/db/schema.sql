CREATE TABLE `sys_account`
(
    `id`                         bigint(20) NOT NULL COMMENT '账号ID',
    `username`                   varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin  DEFAULT NULL COMMENT '用户名',
    `password`                   varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT '密码',
    `avatar`                     varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT '头像',
    `phone_number`               varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin  DEFAULT NULL COMMENT '手机号',
    `email`                      varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin  DEFAULT NULL COMMENT '邮箱',
    `type`                       varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin  DEFAULT NULL COMMENT '账号类型 MEMBER：会员 STAFF：员工',
    `is_deleted`                 tinyint(1) DEFAULT '0' COMMENT '是否删除',
    `is_enabled`                 tinyint(1) DEFAULT '0' COMMENT '是否启用',
    `created`                    timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `is_account_non_expired`     tinyint(1) DEFAULT '0' COMMENT '是否账号过期',
    `is_account_non_locked`      tinyint(1) DEFAULT '0' COMMENT '是否账号锁定',
    `is_credentials_non_expired` tinyint(1) DEFAULT '0' COMMENT '是否凭据过期',
    `is_email_confirmed`         tinyint(1) DEFAULT '0' COMMENT '是否邮箱已确认',
    `github_uid`                 varchar(45) COLLATE utf8mb4_bin                        DEFAULT NULL COMMENT 'Github 用户ID',
    `google_uid`                 varchar(45) COLLATE utf8mb4_bin                        DEFAULT NULL COMMENT '谷歌用户ID',
    `facebook_uid`               varchar(45) COLLATE utf8mb4_bin                        DEFAULT NULL COMMENT 'Facebook 用户ID',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC COMMENT='账号'

