package com.example.uaa.dao;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.uaa.entity.Account;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountDao extends BaseMapper<Account> {
}
