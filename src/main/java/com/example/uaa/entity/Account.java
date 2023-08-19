package com.example.uaa.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@TableName("sys_account")
public class Account {
    private String id;
    private String username;
    private String password;
    private String avatar;
    private String email;
    private String type;
    @TableField("is_account_non_expired")
    private boolean accountNonExpired;
    @TableField("is_account_non_locked")
    private boolean accountNonLocked;
    @TableField("is_credentials_non_expired")
    private boolean credentialsNonExpired;
    @TableField("is_enabled")
    private boolean enabled;
    @TableField("is_deleted")
    private boolean deleted;
    private LocalDateTime created;
    // 社交登录相关的字段
    private String githubUid;
    private String googleUid;
    private String facebookUid;

    public static Account newAccount() {
        var account = new Account();
        account.setAccountNonExpired(true);
        account.setAccountNonLocked(true);
        account.setCredentialsNonExpired(true);
        account.setCreated(LocalDateTime.now());
        account.setDeleted(false);
        account.setEnabled(true);
        return account;
    }
}
