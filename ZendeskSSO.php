<?php

/**
 * Author: Peter Ncube
 * Description: Single sign on (SSO) class for Zendesk
 * Consists of 2 methods, construtor and redirect
 * the jwt token is created by the constructor and appended
 * to the redirect url therein. 
 * 
 */

 class ZendeskSSO
 {
     /**
      * Properties
      */
    private $payload;
    private $key = "";
    private $subdomain = "";
    private $now;
    private $data;
    private $jwt;
    private $header;
    public $location;
    private $signature;



    /**
     * Initialise this class by passing the logged in user object
     */
    public function __construct($user)
    {

        $user = json_decode($user);
        $this->now = time();
        $this->header = array("typ" => "JWT", "alg" => "HS256");
        $this->data = array(
                                "jti"   => md5($this->now . rand()),
                                "iat"   => $this->now,
                                "name"  => $user->name,
                                "email" => $user->email
                                 );

        $data = json_encode($this->data);
        $data = str_replace(array('[', ']'), '', $data);
        $this->header = str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode(json_encode($this->header)));
        $this->payload = str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode($data));
        $this->signature = hash_hmac('sha256', $this->header.'.'.$this->payload, $this->key, true);
        $this->signature = str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode($this->signature));
        $this->jwt = $this->header.'.'.$this->payload.'.'.$this->signature;
        $this->location = "https://" . $this->subdomain . ".zendesk.com/access/jwt?jwt=" . $this->jwt;
        if(isset($_GET["return_to"])) {
            $this->location .= "&return_to=" . urlencode($_GET["return_to"]);
        }                 
    }

    /**
     * Redirect function that sends locally authenticated user
     * to zendesk.
     */
    public function redirect()
    {
        header("Location: " . $this->location);
    }



 }
 
