<?php

/**
 * Configure App specific behavior for 
 * Maestrano SSO
 */
class MnoSsoUser extends MnoSsoBaseUser
{
  /**
   * Database connection
   * @var PDO
   */
  public $connection = null;
  
  
  /**
   * Extend constructor to inialize app specific objects
   *
   * @param OneLogin_Saml_Response $saml_response
   *   A SamlResponse object from Maestrano containing details
   *   about the user being authenticated
   */
  public function __construct(OneLogin_Saml_Response $saml_response, &$session = array(), $opts = array())
  {
    // Call Parent
    parent::__construct($saml_response,$session);
    
    // Assign new attributes
    //$this->connection = $opts['db_connection'];
  }
  
  
  /**
   * Sign the user in the application. 
   * Parent method deals with putting the mno_uid, 
   * mno_session and mno_session_recheck in session.
   *
   * @return boolean whether the user was successfully set in session or not
   */
  protected function setInSession()
  {
    if ($this->local_id) {
      // Get globals
      global $user_cookie_site, $prefs, $userlib;
      
      $userId = $this->local_id;
      $username = $userlib->get_user_login($userId);
      $secret = $userlib->create_user_cookie($userId);
			setcookie($user_cookie_site, $secret . '.' . $userId, $tikilib->now + $prefs['remembertime'], $prefs['cookie_path'], $prefs['cookie_domain']);
      $this->session[$user_cookie_site] = $username;
      
      return true;
    } else {
      return false;
    }
  }
  
  
  /**
   * Used by createLocalUserOrDenyAccess to create a local user 
   * based on the sso user.
   * If the method returns null then access is denied
   *
   * @return the ID of the user created, null otherwise
   */
  protected function createLocalUser()
  {
    $lid = null;
    
    if ($this->accessScope() == 'private') {
      // First build the local user attributes hash $conn variable (used internally by collabtive methods)
      $user = $this->buildLocalUser();
      
      // Create the user
      global $userlib;
      $lid = $userlib->add_user($user['login'],$user['password'],$user['email']);
      
      // Assign user to group (only if admin - not required otherwise)
      $role = $this->getRoleToAssign();
      if ($role == 'Admins') {
        $userlib->assign_user_to_group($user['login'], $role);
      }
      
      // Get the id
      $result = TikiLib::table('users_users')->fetchOne('userId', array('login' => $user['login']));
      if ($result) {
        $lid = intval($result);
      }
      
    }
    
    return $lid;
  }
  
  /**
   * Return a user for creation
   *
   * @return a hash of attributes
   */
  protected function buildLocalUser()
  {
    $user = Array(
      'login'    => $this->formatUniqueUsername(),
      'password' => $this->generatePassword(),
      'email'    => $this->email,
    );
    
    return $user;
  }
  
  /**
   * Return the role to give to the user based on context
   * If the user is the owner of the app or at least Admin
   * for each organization, then it is given the role of 'Admin'.
   * Return 'User' role otherwise
   *
   * @return the ID of the user created, null otherwise
   */
  public function getRoleToAssign() {
    $default_role_user = 'Registered';
    $default_role_admin = 'Admins';
    
    $role = $default_role_user; // User
    
    if ($this->app_owner) {
      $role = $default_role_admin; // Admin
    } else {
      foreach ($this->organizations as $organization) {
        if ($organization['role'] == 'Admin' || $organization['role'] == 'Super Admin') {
          $role = $default_role_admin;
        } else {
          $role = $default_role_user;
        }
      }
    }
    
    return $role;
  }
  
  /**
   * Return a unique username which is more user friendly
   * that just using the maestrano uid
   */
  public function formatUniqueUsername() {
    $s_name = preg_replace("/[^a-zA-Z0-9]+/", "", $this->name);
    $s_surname = preg_replace("/[^a-zA-Z0-9]+/", "", $this->surname);
    $formatted = $s_name . '_' . $s_surname . '_' . $this->uid;
    return $formatted;
  }
  
  /**
   * Get the ID of a local user via Maestrano UID lookup
   *
   * @return a user ID if found, null otherwise
   */
  protected function getLocalIdByUid()
  {    
    $result = TikiLib::table('users_users')->fetchOne('userId', array('mno_uid' => $this->uid));
    
    if ($result) {
      return intval($result);
    }
    
    return null;
  }
  
  /**
   * Get the ID of a local user via email lookup
   *
   * @return a user ID if found, null otherwise
   */
  protected function getLocalIdByEmail()
  {
    $result = TikiLib::table('users_users')->fetchOne('userId', array('email' => $this->email));
    
    if ($result) {
      return intval($result);
    }
    
    return null;
  }
  
  /**
   * Set all 'soft' details on the user (like name, surname, email)
   * Implementing this method is optional.
   *
   * @return boolean whether the user was synced or not
   */
   protected function syncLocalDetails()
   {
     if($this->local_id) {
       
       $upd = TikiLib::table('users_users')->update(array(
           'login' => $this->formatUniqueUsername(),
           'email' => $this->email,
         ), 
         array('userId' => $this->local_id));
       
       return $upd;
     }
     
     return false;
   }
  
  /**
   * Set the Maestrano UID on a local user via id lookup
   *
   * @return a user ID if found, null otherwise
   */
  protected function setLocalUid()
  {
    if($this->local_id) {
      
      $upd = TikiLib::table('users_users')->update(array(
          'mno_uid' => $this->uid,
        ), 
        array('userId' => $this->local_id));
      
      return $upd;
    }
    
    return false;
  }
}