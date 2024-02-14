<?php

function squirrelmail_plugin_init_spamassassin_sql() {
  global $squirrelmail_plugin_hooks;
  global $mailbox, $imap_stream, $imapConnection;

  $squirrelmail_plugin_hooks['options_save']['spamassassin_sql'] = 'spamassassin_sql_save_pref';
  $squirrelmail_plugin_hooks['optpage_register_block']['spamassassin_sql'] = 'spamassassin_sql_opt';
}


function spamassassin_sql_opt() {
    global $optpage_blocks;

    $optpage_blocks[] = array(
        'name' => 'Настройка Анти-Спамового фильтра',
        'url' => '../plugins/spamassassin_sql/options.php',
        'desc' => 'Здесь вы можете настроить списки пользователей, которых вы будете игнорировать, различные тесты на спам, или отключить фильтр совсем.',
        'js' => FALSE
    );

}

function spamassassin_sql_save_pref() {
   global $plugin_spamassassin_sql;

   if (!isset($plugin_spamassassin_sql))
       return;

   echo "<p align=center><b>Password changed successfully!</b></p>\n";
}

?>
